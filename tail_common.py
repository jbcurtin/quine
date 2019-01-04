import asyncio
import boto3
import concurrent
import copy
import enum
import ipaddress
import math
import logging
import jinja2
import hashlib
import os
import random
import typing
import uvloop

from botocore import errorfactory
from botocore import exceptions as boto_exceptions

from pprint import pprint

from datetime import datetime, timedelta

from quine import tail_constants as constants_quine

APPSERVER_INTERNAL_SECURITY_KEY = f'{constants_quine.CLUSTER_PREFIX}-appserver'
BASTION_KEY = f'{constants_quine.CLUSTER_PREFIX}-bastion'
BASTION_SECURITY_KEY = f'{constants_quine.CLUSTER_PREFIX}-bastion'
RDS_KEY = f'{constants_quine.CLUSTER_PREFIX}-{constants_quine.RESOURCE_NAME}'
RDS_SECURITY_KEY = f'{RDS_KEY}-rds-security'
RDS_SUBNET_KEY = f'{RDS_SECURITY_KEY}-subnets'
CACHE_KEY = '-'.join([abbrev for abbrev in map(lambda x: x[:4],
  [constants_quine.DEPLOYMENT, constants_quine.STAGE, constants_quine.RESOURCE_NAME])])
FORWARD_ALB_SECURITY_GROUP_KEY = f'{constants_quine.CLUSTER_PREFIX}-edge-public'
TURTLE_ALB_SECURITY_GROUP_KEY = f'{constants_quine.CLUSTER_PREFIX}-edge-private'

if len(CACHE_KEY) > 20:
  # Elasticache restricts identifiers to < 20 chars
  raise NotImplementedError

CACHE_SUBNET_KEY = f'{CACHE_KEY}-subnest'
CACHE_SECURITY_KEY = f'{CACHE_KEY}-ec-security'
CACHE_SECURITY_GROUP_KEY = f'{CACHE_KEY}-sg-key'


logger = logging.getLogger(__name__)
class SubnetType(enum.Enum):
  PRIVATE = 'private'
  PUBLIC = 'public'

def _next_cidrblock(vpc_cidrblocks: typing.List[str]) -> str:
  cidrblock, mask = sorted([
      (int.from_bytes(ipaddress.ip_address(cidr).packed, 'big'), mask)
      for cidr, mask in [cidr.split('/') for cidr in vpc_cidrblocks]], key=lambda x: x[0])[-1]
  return '/'.join([ipaddress.ip_address(cidrblock + constants_quine.NET_MASKS[mask]).compressed, mask])

def _sync_subnet_expectations(ec2: typing.Any, vpc: str, vpc_details: typing.Dict[str, str], allocated_cidrblocks: typing.List[str], subnet_type: SubnetType) -> typing.List[str]:
  selected_subnets = [sub for sub_id, sub in vpc_details['subnets'].items() if sub['subnet-type'] is subnet_type]
  zones = [zone for zone in sorted({z['availability-zone'] for z in selected_subnets})]
  additional_cidrblocks = copy.deepcopy(allocated_cidrblocks)
  for zone in constants_quine.REQUIRED_VPC_SUBNET_ZONES:
    if not zone in zones:
      next_cidrblock = _next_cidrblock(additional_cidrblocks)
      logger.info(f'Creating Subnet[{next_cidrblock}] for VPC[{vpc}]')
      new_subnet = ec2.create_subnet(AvailabilityZone=zone, CidrBlock=next_cidrblock, VpcId=vpc)
      new_subnet.create_tags(Tags=[{'Key': 'Name', 'Value': '-'.join([constants_quine.DEPLOYMENT, constants_quine.STAGE, zone, subnet_type.value])}])
      additional_cidrblocks.append(next_cidrblock)

  return additional_cidrblocks
                
def obtain_executor() -> concurrent.futures.ThreadPoolExecutor:
  def _active_test():
    return None

  try:
    future = constants_quine.DEFAULT_EXECUTOR.submit(_active_test)
    future.result()
  except (AttributeError, TypeError, RuntimeError) as err:
    logger.info('Building new Executor')
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    setattr(constants_quine, 'DEFAULT_EXECUTOR', executor)

  return constants_quine.DEFAULT_EXECUTOR

def obtain_event_loop() -> typing.Any:
  if constants_quine.EVENT_LOOP is None:
    logger.info('Setting up uvloop')
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    setattr(constants_quine, 'EVENT_LOOP', asyncio.get_event_loop())

  return constants_quine.EVENT_LOOP

def obtain_jinja2_env() -> typing.Any:
  if constants_quine.JINJA2_ENV is None:
    logger.info('Setting up jinja2')
    env = jinja2.Environment(
        trim_blocks=True,
        autoescape=False,
        loader=jinja2.FileSystemLoader(os.path.abspath(os.getcwd())))
    setattr(constants_quine, 'JINJA2_ENV', env)

  return constants_quine.JINJA2_ENV

def create_dir_of_path(output_path: str) -> None:
  dir_path = os.path.dirname(output_path)
  if not os.path.exists(dir_path):
    os.makedirs(dir_path)

def map_deployment_ips(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> typing.Dict[str, typing.Any]:
  payload['deployment-ips'] = {
      'public': ['209.34.140.73/32', '114.161.65.20/32'],
      'private': [] # subnet?
  }
  return payload

def map_aws_ips(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  ec2_client = boto3.client('ec2')
  addresses = ec2_client.describe_addresses(Filters=[{
    'Name': 'tag:Name',
    'Values': [f'{constants_quine.CLUSTER_PREFIX}-bastion']
  }])
  for vpc, vpc_details in payload['vpcs'].items():
    vpc_details['elastic-addresses'] = addresses['Addresses']

def map_aws_route53(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  route53 = boto3.client('route53')
  dns_name = constants_quine.DNS_NAME.strip('.')
  logger.info(f'Looking for DNSPath[{dns_name}]')
  payload['hosted-zones'] = {}
  for page in route53.get_paginator('list_hosted_zones').paginate():
    for zone in page['HostedZones']:
      hosted_zone = payload['hosted-zones'].get(constants_quine.DNS_NAME, {})
      if zone['Name'].strip('.') == constants_quine.DNS_NAME.strip('.'):
        for record_page in route53.get_paginator('list_resource_record_sets').paginate(HostedZoneId=zone['Id']):
          for resource in record_page['ResourceRecordSets']:
            hosted_resources = hosted_zone.get(resource['Name'], [])
            if resource.get('AliasTarget', None):
              hosted_resources.append({
                'aws-type': 'alias',
                'type': resource['Type'],
                'ttl': 0,
                'records': [],
                'alias-target': resource['AliasTarget']
              })

            else:
              hosted_resources.append({
                'aws-type': 'native',
                'type': resource['Type'],
                'ttl': resource['TTL'],
                'records': [v['Value'] for v in resource['ResourceRecords']],
                'alias-target': None
              })
              hosted_zone[resource['Name']] = hosted_resources

        payload['hosted-zones'][constants_quine.DNS_NAME] = {
            'records': hosted_zone,
            'zone-id': zone['Id']
        }
        return None

  raise NotImplementedError(constants_quine.DNS_NAME)

def map_aws_images(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  ec2 = boto3.client('ec2')
  images = ec2.describe_images(**{
    'Filters': [
      {'Name': 'architecture', 'Values': ['x86_64']},
      {'Name': 'virtualization-type', 'Values': ['hvm']},
      {'Name': 'is-public', 'Values': ['true']},
      {'Name': 'state', 'Values': ['available']},
      {'Name': 'owner-id', 'Values': ['099720109477']}, # Canonical
      {'Name': 'name', 'Values': ['ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server*']}
    ]
  })['Images']
  for image in images:
    image['CreationDate'] = datetime.strptime(image['CreationDate'], '%Y-%m-%dT%H:%M:%S.000Z')

  payload['ami-image-id'] = [img for img in sorted(images, key=lambda x: x['CreationDate'], reverse=True)][0]['ImageId']

def map_aws_vpcs(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  ec2 = boto3.client('ec2')
  payload['vpcs'] = {}
  for vpc in ec2.describe_vpcs(**{'Filters': [{'Name': 'tag:Name', 'Values': [constants_quine.CLUSTER_PREFIX]}]})['Vpcs']:
    payload['vpcs'][vpc['VpcId']] = {
        'ip-ranges': [item['CidrBlockState'] for item in vpc['CidrBlockAssociationSet']],
        'vpc-name': constants_quine.CLUSTER_PREFIX,
        'instances': {},
        'subnets': {},
        'security-groups': {},
        'rds-instances': {},
        'elasticache-clusters': {}
    }

def map_aws_rds(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  rds_client = boto3.client('rds')
  for page in rds_client.get_paginator('describe_db_instances').paginate():
    for instance in page['DBInstances']:
      logger.info("I don't like the way this works. It should be more precise.")
      if not instance['DBSubnetGroup']['VpcId'] in payload['vpcs'].keys():
        continue

      rds_instances = payload['vpcs'][instance['DBSubnetGroup']['VpcId']].get('rds-instances', {})
      try:
        uri = ''.join([
            f'postgres://{constants_quine.ENV_VARS["PSQL__USERNAME"]}:{constants_quine.ENV_VARS["PSQL__PASSWORD"]}@',
            f'{instance["Endpoint"]["Address"]}:{instance["Endpoint"]["Port"]}/{instance["DBName"]}'])
      except KeyError:
        uri = None

      rds_instances[instance['DBInstanceIdentifier']] = {'uri': uri}
      payload['vpcs'][instance['DBSubnetGroup']['VpcId']]['rds-instances'] = rds_instances

def map_aws_elasticache(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  ec_client = boto3.client('elasticache')
  vpc = [vpc for vpc, details in payload['vpcs'].items() if details['vpc-name'] == constants_quine.CLUSTER_PREFIX][0]
  try:
    cluster = ec_client.describe_cache_clusters(CacheClusterId=CACHE_KEY, ShowCacheNodeInfo=True)
    # 'deleteing', 'creating'
  except boto_exceptions.ClientError:
    payload['vpcs'][vpc]['elasticache-clusters'][CACHE_KEY] = {}

  else:
    try:
      endpoint = ':'.join([
        str(cluster['CacheClusters'][0]['CacheNodes'][0]['Endpoint']['Address']),
        str(cluster['CacheClusters'][0]['CacheNodes'][0]['Endpoint']['Port']),
      ])
    except (KeyError, IndexError) as err:
      payload['vpcs'][vpc]['elasticache-clusters'][CACHE_KEY] = {
          'endpoint': None,
          'status': 'quine-pending',
      }
    else:
      payload['vpcs'][vpc]['elasticache-clusters'][CACHE_KEY] = {
          'endpoint': f'redis://{endpoint}/0',
          'status': cluster['CacheClusters'][0]['CacheClusterStatus']
      }

def map_aws_subnets(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  """
  Based off EC2-VPCs Instances, identify the Subnets that are available.
  """
  ec2 = boto3.client('ec2')
  for subnet in ec2.describe_subnets(**{
    'Filters': [{'Name': 'tag:Name', 'Values': ['-'.join([constants_quine.CLUSTER_PREFIX, '*'])]}]
    })['Subnets']:
    vpc_subnets = payload['vpcs'][subnet['VpcId']].get('subnets', {})
    vpc_subnet_name = [item['Value'] for item in subnet['Tags'] if item['Key'] == 'Name'][0]
    vpc_subnets[subnet['SubnetId']] = {
      'name': vpc_subnet_name,
      'availability-zone': subnet['AvailabilityZone'],
      'subnet-type': SubnetType.PRIVATE if 'private' in vpc_subnet_name else SubnetType.PUBLIC,
      'cidrblock': subnet['CidrBlock']
    }
    payload['vpcs'][subnet['VpcId']]['subnets'] = vpc_subnets

def map_aws_security_groups(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  ec2 = boto3.client('ec2')
  for page in ec2.get_paginator('describe_security_groups').paginate(**{
    'Filters': [
      {'Name': 'tag:Name', 'Values': [
        '-'.join([constants_quine.CLUSTER_PREFIX, '*']),
        CACHE_SECURITY_GROUP_KEY,
      ]}
    ]
  }):
    for security_group in page['SecurityGroups']:
      vpc_groups = payload['vpcs'][security_group['VpcId']].get('security-groups', {})
      try:
        vpc_groups[security_group['GroupId']] = {
            'group-name': security_group['GroupName'],
            'ingress': {
              'port': security_group['IpPermissions'][0]['FromPort'],
              'ip-ranges': security_group['IpPermissions'][0]['IpRanges'][0]['CidrIp']
            },
            'egress': {}
        }
      except (KeyError, IndexError) as err:
        logging.warn(f"SecurityGroup[{security_group['GroupId']}] doesn't have any gress")
        vpc_groups[security_group['GroupId']] = {
          'group-name': security_group['GroupName'],
          'ingress': {},
          'egress': {}
        }

      payload['vpcs'][security_group['VpcId']]['security-groups'] = vpc_groups

async def sync_aws_alb_dns(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  elb = boto3.client('elbv2')
  route53 = boto3.client('route53')
  alb_instance_key = _compute_alb_instance_key(payload)
  await sync_aws_acm_for_dnsnames([constants_quine.TURTLE_ARRAY_DNS], payload)
  await sync_aws_acm_for_dnsnames([constants_quine.FORWARD_ARRAY_DNS], payload)

def sync_aws_alb_target_groups(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  elb = boto3.client('elbv2')
  alb_target_group_key = _compute_alb_target_group_key(payload)
  for vpc, vpc_details in payload['vpcs'].items():
    if not alb_target_group_key in payload['target-groups']:
      target_group = {
          'Name': alb_target_group_key,
          'Protocol': 'HTTP',
          'Port': constants_quine.INTERNAL_HTTP_PORT,
          'VpcId': vpc,
          'HealthCheckProtocol': 'HTTP',
          'HealthCheckPath': '/okay.txt',
          'HealthCheckIntervalSeconds': 5,
          'HealthCheckTimeoutSeconds': 2,
          'HealthyThresholdCount': 10,
          'UnhealthyThresholdCount': 3,
          'Matcher': {
            'HttpCode': '200'
          },
          'TargetType': 'instance'
      }
      group = elb.create_target_group(**target_group)
      [payload['target-groups'].update({tg['TargetGroupName']: tg}) for tg in group['TargetGroups']]

def _sync_alb_security_groups(vpc: str, vpc_details: typing.Dict[str, typing.Any]) -> None:
  ec2 = boto3.client('ec2')
  if len([sg for sg in vpc_details['security-groups'].values() if sg['group-name'] == FORWARD_ALB_SECURITY_GROUP_KEY]) is 0:
    security_group = ec2.create_security_group(Description=FORWARD_ALB_SECURITY_GROUP_KEY, GroupName=FORWARD_ALB_SECURITY_GROUP_KEY, VpcId=vpc)['GroupId']
    ec2.create_tags(Resources=[security_group], Tags=[{'Key': 'Name', 'Value': FORWARD_ALB_SECURITY_GROUP_KEY}])
    ip_perms = [{
      'ToPort': port,
      'FromPort': port,
      'IpProtocol': 'tcp',
      'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': ''}]
    } for port in constants_quine.FORWARD_ARRAY_PORTS]
    ec2.authorize_security_group_ingress(GroupId=security_group, IpPermissions=ip_perms)
    # Something to do later. Write a LAMBDA that'll forward port 80 to 443.

  if len([sg for sg in vpc_details['security-groups'].values() if sg['group-name'] == TURTLE_ALB_SECURITY_GROUP_KEY]) is 0:
    security_group = ec2.create_security_group(Description=TURTLE_ALB_SECURITY_GROUP_KEY, GroupName=TURTLE_ALB_SECURITY_GROUP_KEY, VpcId=vpc)['GroupId']
    ec2.create_tags(Resources=[security_group], Tags=[{'Key': 'Name', 'Value': TURTLE_ALB_SECURITY_GROUP_KEY}])
    ip_perms = [{
      'ToPort': port,
      'FromPort': port,
      'IpProtocol': 'tcp',
      'IpRanges': [{'CidrIp': cidr, 'Description': ''} 
        for cidr in [subnet['cidrblock'] for subnet in vpc_details['subnets'].values() if subnet['subnet-type'] in [SubnetType.PRIVATE, SubnetType.PUBLIC]]]
      } for port in constants_quine.TURTLE_ARRAY_PORTS]
    ip_perms.extend([{
      'ToPort': 80,
      'FromPort': 80,
      'IpProtocol': 'tcp',
      'IpRanges': [{'CidrIp': cidr, 'Description': ''} 
        for cidr in [subnet['cidrblock'] for subnet in vpc_details['subnets'].values() if subnet['subnet-type'] in [SubnetType.PRIVATE, SubnetType.PUBLIC]]]
      } for port in constants_quine.TURTLE_ARRAY_PORTS])
    ip_perms.extend([{
      'ToPort': 443,
      'FromPort': 443,
      'IpProtocol': 'tcp',
      'IpRanges': [{'CidrIp': cidr, 'Description': ''} 
        for cidr in [subnet['cidrblock'] for subnet in vpc_details['subnets'].values() if subnet['subnet-type'] in [SubnetType.PRIVATE, SubnetType.PUBLIC]]]
      } for port in constants_quine.TURTLE_ARRAY_PORTS])
    ec2.authorize_security_group_ingress(GroupId=security_group, IpPermissions=ip_perms)

def _compute_alb_target_group_key(payload: typing.Dict[str, typing.Any]) -> str:
  alb_target_group_key = f'{constants_quine.RESOURCE_PREFIX}-{payload["options"].focal_type.name.lower()}'
  return '-'.join([part[:4] for part in alb_target_group_key.split('-')])

def _compute_alb_instance_key(payload: typing.Dict[str, typing.Any]) -> str:
  alb_instance_key = f'{constants_quine.RESOURCE_PREFIX}-{payload["options"].focal_type.name.lower()}'
  alb_instance_key = f'{alb_instance_key}-edge'
  return '-'.join([part[:3] for part in alb_instance_key.split('-')])

def _compute_alb_listener_identity(listener: typing.Dict[str, typing.Any]) -> str:
  for action in listener['DefaultActions']:
    if not action['Type'] in ['redirect', 'forward']:
      raise NotImplementedError(action['Type'])

  token = ''.join([
    listener['Protocol'],
    str(listener['Port']),
    listener['LoadBalancerArn'],
    ''.join([
      ''.join([
        action['RedirectConfig']['Host'],
        action['RedirectConfig']['Path'],
        str(action['RedirectConfig']['Port']),
        action['RedirectConfig']['Protocol'],
        action['RedirectConfig']['Query'],
        action['RedirectConfig']['StatusCode']])
      for action in listener['DefaultActions'] if action['Type'] == 'redirect']),
    # ''.join([cert['CertificateArn'] for cert in listener.get('Certificates', [])]),
    ''.join([
      ''.join([
        action['TargetGroupArn'],
        action['Type']])
      for action in listener['DefaultActions'] if action['Type'] == 'forward']),
    ])
  return hashlib.md5(token.encode(constants_quine.ENCODING)).hexdigest()

def sync_aws_alb_instances(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> typing.Dict[str, typing.Any]:
  elb = boto3.client('elbv2')
  alb_instance_key = _compute_alb_instance_key(payload)
  for vpc, vpc_details in payload['vpcs'].items():
    _sync_alb_security_groups(vpc, vpc_details)
    map_aws_security_groups(executor, payload)
    if payload['options'].focal_type in [constants_quine.FocalType.TURTLE]:
      if not alb_instance_key in payload['alb-instances'].keys():
        alb_config = {
          'Name': alb_instance_key,
          'Subnets': [subnet_id for subnet_id, subnet in vpc_details['subnets'].items() if subnet['subnet-type'] is SubnetType.PRIVATE],
          'SecurityGroups': [sg_id for sg_id, sg in vpc_details['security-groups'].items() if sg['group-name'] == TURTLE_ALB_SECURITY_GROUP_KEY],
          'Scheme': 'internal',
          'Tags': [{'Key': 'Name', 'Value': alb_instance_key}],
          'Type': 'application',
          'IpAddressType': 'ipv4'
        }
        balancer = elb.create_load_balancer(**alb_config)
        try:
          balancer = balancer[0]
        except IndexError:
          import ipdb; ipdb.set_trace()
          import sys; sys.exit(1)

        payload['alb-instances'][balancer['LoadBalancerName']] = {
          'dns-name': balancer['DNSName'],
          'arn': balancer['LoadBalancerArn'],
          'type': balancer['VpcId'],
          'state': balancer['State'],
          'SecurityGroups': balancer
        }


    elif payload['options'].focal_type in [constants_quine.FocalType.FORWARD_ARRAY]:
      if not alb_instance_key in payload['alb-instances'].keys():
        alb_config = {
          'Name': alb_instance_key,
          'Subnets': [subnet_id for subnet_id, subnet in vpc_details['subnets'].items() if subnet['subnet-type'] is SubnetType.PUBLIC],
          'SecurityGroups': [sg_id for sg_id, sg in vpc_details['security-groups'].items() if sg['group-name'] == FORWARD_ALB_SECURITY_GROUP_KEY],
          'Scheme': 'internet-facing',
          'Tags': [{'Key': 'Name', 'Value': alb_instance_key}],
          'Type': 'application',
          'IpAddressType': 'ipv4'
        }
        balancer = elb.create_load_balancer(**alb_config)
        try:
          balancer = balancer[0]
        except (KeyError, IndexError) as err:
          import ipdb; ipdb.set_trace()
          import sys; sys.exit(1)

        payload['alb-instances'][balancer['LoadBalancerName']] = {
          'dns-name': balancer['DNSName'],
          'arn': balancer['LoadBalancerArn'],
          'type': balancer['VpcId'],
          'state': balancer['State'],
          'SecurityGroups': balancer
        }


    else:
      raise NotImplementedError(payload['options'].focal_type)

def sync_aws_alb_listeners(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> typing.Dict[str, typing.Any]:
  elb = boto3.client('elbv2')
  for vpc, vpc_details in payload['vpcs'].items():
    targets = {}
    for instance_id, instance in vpc_details['instances'].items():
      if instance['instance-name']['Value'].startswith(constants_quine.RESOURCE_PREFIX):
        targets.update({instance_id: instance})

    if constants_quine.FocalType.FORWARD_ARRAY == payload['options'].focal_type:
      http_to_https = {
        'LoadBalancerArn': payload['alb-instances'][_compute_alb_instance_key(payload)]['arn'],
        'Protocol': 'HTTP',
        'Port': 80,
        'DefaultActions': [
          {
            'Type': 'redirect',
            'RedirectConfig': {
              'Protocol': 'HTTPS',
              'Port': '443',
              'Host': constants_quine.FOCAL_DNS_NAME,
              'Path': '/#{path}',
              'Query': 'rdi=yep',
              'StatusCode': 'HTTP_301',
            }
          }
        ]
      }
      listener: dict = None
      listener_identity: str = _compute_alb_listener_identity(http_to_https)
      if not listener_identity in payload['alb-listeners'].keys():
        import ipdb; ipdb.set_trace()
        listener = elb.create_listener(**http_to_https)['Listeners'][0]
        payload['alb-listeners'][listener_identity] = listener

      https_config = {
        'LoadBalancerArn': payload['alb-instances'][_compute_alb_instance_key(payload)]['arn'],
        'Protocol': 'HTTPS',
        'Port': 443,
        'Certificates': [
          {
            'CertificateArn': payload['acm-certs'][constants_quine.FOCAL_DNS_NAME]['arn'],
          }
        ],
        'DefaultActions': [
          {
            'Type': 'forward',
            'TargetGroupArn': payload['target-groups'][_compute_alb_target_group_key(payload)]['TargetGroupArn'],
          }
        ]
      }
      listener: dict = None
      listener_identity: str = _compute_alb_listener_identity(https_config)
      if not listener_identity in payload['alb-listeners'].keys():
        listener = elb.create_listener(**https_config)
        payload['alb-listeners'][listener_identity] = listener

    elif constants_quine.FocalType.TURTLE == payload['options'].focal_type:
      pass
      # import ipdb; ipdb.set_trace()
      # import sys; sys.exit(1)
      # https_config = {
      #   'LoadBalancerArn': payload['alb-instances'][_compute_alb_instance_key(payload)]['arn'],
      #   'Protocol': 'HTTPS',
      #   'Port': 443,
      #   'Certificates': [
      #     {
      #       'CertificateArn': payload['acm-certs'][constants_quine.FOCAL_DNS_NAME]['arn'],
      #     }
      #   ],
      #   'DefaultActions': [
      #     {
      #       'Type': 'forward',
      #       'TargetGroupArn': payload['target-groups'][_compute_alb_target_group_key(payload)]['TargetGroupArn'],
      #     }
      #   ]
      # }
      # listener: dict = None
      # listener_identity: str = _compute_alb_listener_identity(http_to_https)
      # if not listener_identity in payload['alb-listeners'].keys():
      #   listener = elb.create_listener(**http_to_https)['Listeners'][0]
      #   payload['alb-listeners'][listener_identity] = listener

    else:
      raise NotImplementedError(f'Turtle Array not supported[{payload["options"].focal_type}]')

async def sync_aws_acm_for_dnsnames(dns_names: typing.List[str], payload: typing.Dict[str, typing.Any]) -> None:
  acm = boto3.client('acm')
  route53 = boto3.client('route53')
  for dns_name in dns_names:
    if not dns_name in payload['acm-certs'].keys():
      logger.info(f'Request ACM for [{dns_name}]')
      token = ''.join(['aoeu', dns_name])
      token = hashlib.md5(token.encode('utf-8')).hexdigest()
      result = acm.request_certificate(DomainName=dns_name, IdempotencyToken=token, ValidationMethod='DNS')
      cert = acm.describe_certificate(CertificateArn=result['CertificateArn'])

    else:
      cert = acm.describe_certificate(CertificateArn=payload['acm-certs'][dns_name]['arn'])

    delta: timedelta = timedelta(minutes=constants_quine.POLL_DELAY)
    poll_start: datemite = datetime.utcnow()
    # When creating the cert, DomainValidationOptions doesn't immediately exist.
    while (poll_start + delta) > datetime.utcnow():
      try:
        logger.info(f'Polling ACM for DNSValidationOptions[{dns_name}]')
        dns_validation = [awe for awe in cert['Certificate']['DomainValidationOptions'] if awe['ValidationMethod'] == 'DNS'][0]['ResourceRecord']
      except (IndexError, KeyError) as err:
        await asyncio.sleep(constants_quine.POLL_DELAY)

      else:
        break

    for zone_name, zone_details in payload['hosted-zones'].items():
      if dns_name.endswith(zone_name):
        if not dns_validation['Name'].strip('.') in [rec.strip('.') for rec in zone_details['records'].keys()]:
          route53.change_resource_record_sets(
              HostedZoneId=zone_details['zone-id'],
              ChangeBatch={
                'Comment': f'Requesting DNSValidation for DNS[{dns_name}]',
                'Changes': [
                  {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                      'TTL': 600,
                      'Name': dns_validation['Name'],
                      'Type': dns_validation['Type'],
                      'ResourceRecords': [{'Value': dns_validation['Value']}],
                    }
                  }
                ]
              })

    delta: timedelta = timedelta(minutes=constants_quine.POLL_DELAY)
    poll_start: datetime = datetime.utcnow()
    while (poll_start + delta) > datetime.utcnow():
      cert = acm.describe_certificate(CertificateArn=payload['acm-certs'][dns_name]['arn'])
      status = [awe for awe in cert['Certificate']['DomainValidationOptions'] if awe['ValidationMethod'] == 'DNS'][0]['ValidationStatus']
      if status == 'SUCCESS':
        break

      else:
        logger.info(f'Waiting on ACM Approval for Domain[{dns_name}]')
        await asyncio.sleep(constants_quine.POLL_DELAY)

async def sync_aws_acm_for_albs(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> typing.Dict[str, typing.Any]:
  acm = boto3.client('acm')
  route53 = boto3.client('route53')
  if not constants_quine.FOCAL_DNS_NAME in payload['acm-certs'].keys():
    token = ''.join(['aoeu', constants_quine.FOCAL_DNS_NAME])
    token = hashlib.md5(token.encode('utf-8')).hexdigest()
    result = acm.request_certificate(DomainName=constants_quine.FOCAL_DNS_NAME, IdempotencyToken=token, ValidationMethod='DNS')
    cert = acm.describe_certificate(CertificateArn=result['CertificateArn'])
    # cert = acm.describe_certificate(CertificateArn=payload['acm-certs'][constants_quine.FOCAL_DNS_NAME]['arn'])
  else:
    cert = acm.describe_certificate(CertificateArn=payload['acm-certs'][constants_quine.FOCAL_DNS_NAME]['arn'])

  dns_validation = [awe for awe in cert['Certificate']['DomainValidationOptions'] if awe['ValidationMethod'] == 'DNS'][0]['ResourceRecord']
  for zone_name, zone_details in payload['hosted-zones'].items():
    if constants_quine.FOCAL_DNS_NAME.endswith(zone_name):
      if not dns_validation['Name'].strip('.') in [rec.strip('.') for rec in zone_details['records'].keys()]:
        route53.change_resource_record_sets(
            HostedZoneId=zone_details['zone-id'],
            ChangeBatch={
              'Comment': f'Requesting DNSValidation for DNS[{constants_quine.FOCAL_DNS_NAME}]',
              'Changes': [
                {
                  'Action': 'UPSERT',
                  'ResourceRecordSet': {
                    'TTL': 600,
                    'Name': dns_validation['Name'],
                    'Type': dns_validation['Type'],
                    'ResourceRecords': [{'Value': dns_validation['Value']}],
                  }
                }
              ]
            })

  delta: timedelta = timedelta(minutes=10)
  poll_start: datetime = datetime.utcnow()
  delay: int = 10
  while (poll_start + delta) > datetime.utcnow():
    cert = acm.describe_certificate(CertificateArn=payload['acm-certs'][constants_quine.FOCAL_DNS_NAME]['arn'])
    status = [awe for awe in cert['Certificate']['DomainValidationOptions'] if awe['ValidationMethod'] == 'DNS'][0]['ValidationStatus']
    if status == 'SUCCESS':
      break

    else:
      logger.info(f'Waiting on ACM Approval for Domain[{constants_quine.FOCAL_DNS_NAME}]')
      await asyncio.sleep(delay)

def map_aws_alb_target_groups(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> typing.Dict[str, typing.Any]:
  elb = boto3.client('elbv2')
  payload['target-groups'] = {}
  for page in elb.get_paginator('describe_target_groups').paginate():
    for group in page['TargetGroups']:
      payload['target-groups'][group['TargetGroupName']] = group

def sync_aws_alb_target_group_members(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  elb = boto3.client('elbv2')
  targets = {}
  for vpc, vpc_details in payload['vpcs'].items():
    for instance_id, instance in vpc_details['instances'].items():
      if instance['instance-name']['Value'].startswith(constants_quine.RESOURCE_PREFIX):
        targets.update({instance_id: instance})

  elb.register_targets(
      TargetGroupArn=payload['target-groups'][_compute_alb_target_group_key(payload)]['TargetGroupArn'],
      Targets=[
        {
          'Id': target_id,
          'Port': constants_quine.INTERNAL_HTTP_PORT,
        } for target_id, target in targets.items()])

def map_aws_alb_target_group_members(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> typing.Dict[str, typing.Any]:
  elb = boto3.client('elbv2')
  payload['target-group-members'] = {}
  for target, group in payload['target-groups'].items():
    payload['target-group-members'][target] = []
    for member in elb.describe_target_health(TargetGroupArn=group['TargetGroupArn'])['TargetHealthDescriptions']:
      payload['target-group-members'][target].append(member)

def sync_aws_alb_target_group_rules(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html#ElasticLoadBalancingv2.Client.describe_rules
  # import ipdb; ipdb.set_trace()
  # import sys; sys.exit(1)
  pass

def map_aws_alb_target_group_rules(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  elb = boto3.client('elbv2')
  payload['target-group-rules'] = {}
  # import ipdb; ipdb.set_trace()
  # import sys; sys.exit(1)

def map_aws_alb_instances(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> typing.Dict[str, typing.Any]:
  elb = boto3.client('elbv2')
  payload['alb-instances'] = {}
  for page in elb.get_paginator('describe_load_balancers').paginate():
    for balancer in page['LoadBalancers']:
      payload['alb-instances'][balancer['LoadBalancerName']] = {
        'dns-name': balancer['DNSName'],
        'arn': balancer['LoadBalancerArn'],
        'type': balancer['VpcId'],
        'state': balancer['State'],
        'SecurityGroups': balancer
      }

def map_aws_alb_listeners(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> typing.Dict[str, typing.Any]:
  elb = boto3.client('elbv2')
  payload['alb-listeners'] = {}
  for name, balancer in payload['alb-instances'].items():
    for page in elb.get_paginator('describe_listeners').paginate(LoadBalancerArn=balancer['arn']):
      for listener in page['Listeners']:
        identity = _compute_alb_listener_identity(listener)
        payload['alb-listeners'][identity] = listener

def map_aws_instances(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> typing.Dict[str, typing.Any]:
  ec2 = boto3.client('ec2')
  for page in ec2.get_paginator('describe_instances').paginate(**{
    'Filters': [{'Name': 'tag:Name', 'Values': [
      '-'.join([constants_quine.CLUSTER_PREFIX, '*'])
    ]}]}):
    for reservation in page['Reservations']:
      for instance in reservation['Instances']:
        if instance['State']['Code'] in [
            48, # terminated
          ]:
          continue

        vpc_instances = payload['vpcs'][instance['VpcId']].get('instances', {})
        vpc_instances[instance['InstanceId']] = {
          'ami-image-id': instance['ImageId'],
          'aws-key-name': instance.get('KeyName', None),
          'instance-type': instance['InstanceType'],
          'instance-name': [tag for tag in instance['Tags'] if tag['Key'] == 'Name'][0],
          'subnet-id': instance['SubnetId'],
          'public-ip-address': instance.get('PublicIpAddress', None),
          'private-ip-address': instance['PrivateIpAddress'],
          'security-groups': [sg['GroupId'] for sg in instance['SecurityGroups']],
          'state': instance['State'],
        }
        payload['vpcs'][instance['VpcId']]['instances'] = vpc_instances

  return payload

def _sync_security_groups(ec2: typing.Any, vpc: str, vpc_details: typing.Dict[str, typing.Any], deployment_ips: typing.Dict[str, str]) -> None:
  if len([sg for sg in vpc_details['security-groups'].values() if sg['group-name'] == CACHE_SECURITY_GROUP_KEY]) is 0:
    security_group = ec2.create_security_group(Description=CACHE_SECURITY_GROUP_KEY,
        GroupName=CACHE_SECURITY_GROUP_KEY,
        VpcId=vpc)['GroupId']
    ec2.create_tags(Resources=[security_group], Tags=[{'Key': 'Name', 'Value': CACHE_SECURITY_GROUP_KEY}])
    ip_perms = [{
      'ToPort': port,
      'FromPort': port,
      'IpProtocol': 'tcp',
      'IpRanges': [{'CidrIp': cidr, 'Description': ''} for cidr in [subnet['cidrblock'] for subnet in vpc_details['subnets'].values() if subnet['subnet-type'] is SubnetType.PRIVATE]]
    } for port in constants_quine.REDIS_PORTS]
    ec2.authorize_security_group_ingress(GroupId=security_group, IpPermissions=ip_perms)

  if len([sg for sg in vpc_details['security-groups'].values() if sg['group-name'] == RDS_SECURITY_KEY]) is 0:
    security_group = ec2.create_security_group(Description=RDS_SECURITY_KEY,
        GroupName=RDS_SECURITY_KEY,
        VpcId=vpc)['GroupId']
    ec2.create_tags(Resources=[security_group], Tags=[{'Key': 'Name', 'Value': RDS_SECURITY_KEY}])
    ec2.authorize_security_group_ingress(
        GroupId=security_group,
        IpPermissions=[{
          'ToPort': port,
          'FromPort': port,
          'IpProtocol': 'tcp',
          'IpRanges': [{'CidrIp': cidr, 'Description': ''} for cidr in [subnet['cidrblock'] for subnet in vpc_details['subnets'].values() if subnet['subnet-type'] is SubnetType.PRIVATE]]
        } for port in constants_quine.RDS_PORTS]
      )

  if len([sg for sg in vpc_details['security-groups'].values() if sg['group-name'] == APPSERVER_INTERNAL_SECURITY_KEY]) is 0:
    security_group = ec2.create_security_group(Description=APPSERVER_INTERNAL_SECURITY_KEY,
        GroupName=APPSERVER_INTERNAL_SECURITY_KEY,
        VpcId=vpc)['GroupId']
    ec2.create_tags(Resources=[security_group], Tags=[{'Key': 'Name', 'Value': APPSERVER_INTERNAL_SECURITY_KEY}])
    ip_permissions = [{
          'ToPort': port,
          'FromPort': port,
          'IpProtocol': 'tcp',
          'IpRanges': [{'CidrIp': cidr, 'Description': ''}
            for cidr in [subnet['cidrblock']
              for subnet in vpc_details['subnets'].values()
              if subnet['subnet-type'] in [SubnetType.PRIVATE, SubnetType.PUBLIC]]]
        } for port in constants_quine.INTERNAL_PORTS]
    ec2.authorize_security_group_ingress(IpPermissions=ip_permissions, GroupId=security_group)

  if len([sg for sg in vpc_details['security-groups'].values() if sg['group-name'] == BASTION_SECURITY_KEY]) is 0:
    # import ipdb; ipdb.set_trace()
    security_group = ec2.create_security_group(Description=BASTION_SECURITY_KEY,
        GroupName=BASTION_SECURITY_KEY,
        VpcId=vpc)['GroupId']
    ec2.create_tags(Resources=[security_group], Tags=[{'Key': 'Name', 'Value': BASTION_SECURITY_KEY}])
    ip_permissions = [{
      'ToPort': int(port),
      'FromPort': int(port),
      'IpProtocol': 'tcp',
      'IpRanges': [{'CidrIp': cidr, 'Description': ''}
        for cidr in [subnet['cidrblock']
          for subnet in vpc_details['subnets'].values()
          if subnet['subnet-type'] in [SubnetType.PRIVATE]]]
    } for port in constants_quine.INTERNAL_PORTS]
    ec2.authorize_security_group_ingress(GroupId=security_group, IpPermissions=ip_permissions)

    ip_permissions = [{
      'ToPort': int(port),
      'FromPort': int(port),
      'IpProtocol': 'tcp',
      'IpRanges': [{'CidrIp': cidr, 'Description': ''} for cidr in deployment_ips['public']],
    } for port in constants_quine.BASTION_PORTS]
    ec2.authorize_security_group_ingress(GroupId=security_group, IpPermissions=ip_permissions)

    ip_permissions = [{
      'ToPort': int(port),
      'FromPort': int(port),
      'IpProtocol': 'tcp',
      'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': ''}]
    } for port in constants_quine.BASTION__LETS_ENCRYPT_PORTS]
    ec2.authorize_security_group_ingress(GroupId=security_group, IpPermissions=ip_permissions)


def _sync_bastion_expectations(ec2: typing.Any,
    vpc: str,
    vpc_details: typing.Dict[str, typing.Any],
    ami_image_id: str,
    deployment_type: constants_quine.DeploymentType) -> None:
  if deployment_type in [
      constants_quine.DeploymentType.TURTLE
    ]:
    try:
      instance_id, bastion = [(key, value) for key, value in vpc_details['instances'].items() if value['instance-name']['Value'] == BASTION_KEY][0]
    except IndexError as err:
      logging.info(f'Creating bastion[{BASTION_KEY}] in VPC[{vpc_details["vpc-name"]}]')
      instance_info = {
          'KeyName': constants_quine.AWS_KEY_NAME,
          'ImageId': ami_image_id,
          'InstanceType': 't2.micro',
          'MaxCount': 1,
          'MinCount': 1,
          'SecurityGroupIds': [key for key, value in vpc_details['security-groups'].items() if BASTION_SECURITY_KEY == value['group-name']],
          'SubnetId': random.choice([subnet_id for subnet_id, subnet in vpc_details['subnets'].items() if subnet['subnet-type'] is SubnetType.PUBLIC]),
          'TagSpecifications': [{
            'ResourceType': 'instance',
            'Tags': [{
              'Key': 'Name',
              'Value': BASTION_KEY,
            }, {
              'Key': 'deployment-type',
              'Value': deployment_type.value,
            }]
          }]
        }
      ec2.create_instances(**instance_info)

    else:
      logging.info(f'Bastion[{BASTION_KEY}] found in VPC[{vpc_details["vpc-name"]}]')

  else:
    logger.info(f'Omiting launch of Bastion Service for [{deployment_type}]')


def _sync_appserver_expectations(ec2: typing.Any,
    vpc: str,
    vpc_details: typing.Dict[str, typing.Any],
    ami_image_id: str,
    deployment_type: constants_quine.DeploymentType,
    instance_request_count: int) -> None:
  if deployment_type in [
      constants_quine.DeploymentType.TURTLE,
      constants_quine.DeploymentType.FORWARD_ARRAY
    ]:
    for app_key in [f'{constants_quine.RESOURCE_PREFIX}-appserver-{idx}' for idx in range(0, instance_request_count)]:
      try:
        instance_id, app_instance = [(key, value) for key, value in vpc_details['instances'].items() if value['instance-name']['Value'] == app_key][0]

      except IndexError as err:
        logging.info(f'Creating App Server[{app_key}] in VPC[{vpc_details["vpc-name"]}]')
        instance_info = {
            'KeyName': constants_quine.AWS_KEY_NAME,
            'ImageId': ami_image_id,
            'InstanceType': 't2.micro',
            'MaxCount': 1,
            'MinCount': 1,
            'SecurityGroupIds': [key for key, value in vpc_details['security-groups'].items() if APPSERVER_INTERNAL_SECURITY_KEY == value['group-name']],
            'SubnetId': random.choice([subnet_id for subnet_id, subnet in vpc_details['subnets'].items() if subnet['subnet-type'] is SubnetType.PRIVATE]),
            'TagSpecifications': [{
              'ResourceType': 'instance',
              'Tags': [{
                'Key': 'Name',
                'Value': app_key
              }, {
                'Key': 'deployment-type',
                'Value': deployment_type.value
              }]
            }],
          }
        ec2.create_instances(**instance_info)

      else:
        logging.info(f'App Server[{app_key}] found in VPC[{vpc_details["vpc-name"]}]')

  elif deployment_type in [constants_quine.DeploymentType.MAP]:
    logger.info(f'Omitting DeploymentType[{deployment_type.value}]')

  else:
    raise NotImplementedError(deployment_type)

def _sync_rds_subnets(rds_client: typing.Any, vpc: str, vpc_details: typing.Dict[str, typing.Any], rds_details: typing.Dict[str, typing.Any]) -> None:
  try:
    rds_subnet_group = rds_client.describe_db_subnet_groups(DBSubnetGroupName=RDS_SUBNET_KEY)
  except (boto_exceptions.ClientError, IndexError) as err:
    rds_subnet_group = rds_client.create_db_subnet_group(
        DBSubnetGroupName=RDS_SUBNET_KEY,
        DBSubnetGroupDescription=RDS_SUBNET_KEY,
        SubnetIds=[key for key, subnet in vpc_details['subnets'].items() if subnet['subnet-type'] is SubnetType.PRIVATE],
        Tags=[{'Key': 'tag:Name', 'Value': RDS_SUBNET_KEY}])

  else:
    vpc_id = [subnet_group for subnet_group in rds_subnet_group['DBSubnetGroups'] if subnet_group['DBSubnetGroupName'] == RDS_SUBNET_KEY][0]['VpcId']
    rds_subnet_group = {
        'DBSubnetGroup': [subnet_group for subnet_group in rds_subnet_group['DBSubnetGroups'] if subnet_group['DBSubnetGroupName'] == RDS_SUBNET_KEY][0]
    }
    rds_subnet_group['DBSubnetGroup']['VpcId'] = vpc_id

  rds_details['subnet-group'] = {
      'name': rds_subnet_group['DBSubnetGroup']['DBSubnetGroupName'],
      'arn': rds_subnet_group['DBSubnetGroup']['DBSubnetGroupArn'],
      'vpc': rds_subnet_group['DBSubnetGroup']['VpcId']
  }

def _sync_rds_expectations(
    rds_client: typing.Any,
    vpc: str,
    vpc_details: typing.Dict[str, typing.Any],
    db_deployment_type: constants_quine.DatabaseDeploymentType) -> None:
  if RDS_KEY in vpc_details['rds-instances'].keys():
    return None

  if db_deployment_type in [constants_quine.DatabaseDeploymentType.RDS]:
    rds_details = {
      'subnet-group': {}
    }
    _sync_rds_subnets(rds_client, vpc, vpc_details, rds_details)
    logger.info(f'Creating RDS Instance[{RDS_KEY}]')

    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds.html#RDS.Client.create_db_cluster
    rds_instance = {
      'DBName': constants_quine.ENV_VARS['PSQL__DBNAME'],
      'DBInstanceIdentifier': RDS_KEY,
      'AllocatedStorage': 20,
      # 'Iops': 20,
      'DBInstanceClass': 'db.t2.micro',
      'Engine': 'postgres',
      'MasterUsername': constants_quine.ENV_VARS['PSQL__USERNAME'],
      'MasterUserPassword': constants_quine.ENV_VARS['PSQL__PASSWORD'],
      'VpcSecurityGroupIds': [key for key, sg in vpc_details['security-groups'].items() if sg['group-name'] == RDS_SECURITY_KEY],
      'DBSubnetGroupName': rds_details['subnet-group']['name'],
      'AvailabilityZone': random.choice(constants_quine.REQUIRED_VPC_SUBNET_ZONES),
      # 'PreferredMaintenanceWindow': 'tue:0224:mi-tue:0624'ddd:hh24:mi-ddd:hh24:mi'
      'BackupRetentionPeriod': 3,
      'Port': constants_quine.RDS_PORTS[0],
      # https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_PostgreSQL.html#PostgreSQL.Concepts.General.DBVersions
      # 'EngineVersion': 'awe',
      'AutoMinorVersionUpgrade': True,
      'LicenseModel': 'postgresql-license',
      'Tags': [{
        'Key': 'Name',
        'Value': RDS_SECURITY_KEY
      }],
      'StorageType': 'gp2',
      'DeletionProtection': False,
      'MonitoringInterval': 0,
    }
    result = rds_client.create_db_instance(**rds_instance)

  else:
    logger.info(f'Omiting RDS for Deployment[{db_deployment_type}].')


def _sync_elasticache_subnet_group(ec_client: typing.Any, vpc: str, vpc_details: typing.Dict[str, typing.Any], ec_details: typing.Dict[str, typing.Any]) -> typing.Dict[str, typing.Any]:
  try:
    subnet_group = ec_client.describe_cache_subnet_groups(CacheSubnetGroupName=CACHE_SUBNET_KEY)
  except boto_exceptions.ClientError as err:
    subnet_group = ec_client.create_cache_subnet_group(
        CacheSubnetGroupName=CACHE_SUBNET_KEY,
        CacheSubnetGroupDescription=CACHE_SUBNET_KEY,
        SubnetIds=[key for key, subnet in vpc_details['subnets'].items() if subnet['subnet-type'] is SubnetType.PRIVATE])['CacheSubnetGroup']

  else:
    subnet_group = [group for group in subnet_group['CacheSubnetGroups'] if group['CacheSubnetGroupName'] == CACHE_SUBNET_KEY][0]

  ec_details['subnet-groups'][subnet_group['CacheSubnetGroupName']] = {
    'vpc': subnet_group['VpcId']
  }
  return subnet_group

def _sync_elasticache_security_group(ec_client: typing.Any, vpc: str, vpc_details: typing.Dict[str, typing.Any], ec_details: typing.Dict[str, typing.Any]) -> typing.Dict[str, typing.Any]:
  try:
    security_group = ec_client.describe_cache_security_groups(CacheSecurityGroupName=CACHE_SECURITY_KEY)
  except boto_exceptions.ClientError as err:
    security_group = ec_client.create_cache_security_group(
        CacheSecurityGroupName=CACHE_SECURITY_KEY,
        Description=CACHE_SECURITY_KEY)
    result = ec_client.authorize_cache_security_group_ingress(
      CacheSecurityGroupName=CACHE_SECURITY_KEY,
      EC2SecurityGroupName=CACHE_SECURITY_GROUP_KEY,
      EC2SecurityGroupOwnerId=security_group['CacheSecurityGroup']['OwnerId'])

  else:
    security_group = {'CacheSecurityGroup': security_group['CacheSecurityGroups'][0]}

  ec_details['security-groups'][security_group['CacheSecurityGroup']['CacheSecurityGroupName']] = {
      'owner-id': security_group['CacheSecurityGroup']['OwnerId'],
  }
  return security_group


def _sync_elastic_cache_expectations(
    ec_client: typing.Any,
    vpc: str,
    vpc_details: typing.Dict[str, typing.Any],
    cache_deployment_type: constants_quine.CacheDeploymentType) -> None:

  ec_details = {
    'latest-redis-version': [ev for ev in sorted([item for item in
      ec_client.describe_cache_engine_versions()['CacheEngineVersions']
      if item['Engine'] == 'redis'], key=lambda x: x['EngineVersion'])][-1]['EngineVersion'],
    'subnet-groups': {},
    'security-groups': {},
  }

  subnet_group = _sync_elasticache_subnet_group(ec_client, vpc, vpc_details, ec_details)
  security_group = _sync_elasticache_security_group(ec_client, vpc, vpc_details, ec_details)
  if CACHE_KEY in vpc_details['elasticache-clusters'].keys() and len(vpc_details['elasticache-clusters'][CACHE_KEY].values()) > 0:
    return None

  if cache_deployment_type in [
      constants_quine.CacheDeploymentType.REDIS,
    ]:
    ec_properties = {
      'CacheClusterId': CACHE_KEY,
      'PreferredAvailabilityZones': [random.choice(constants_quine.REQUIRED_VPC_SUBNET_ZONES)],
      'NumCacheNodes': 1,
      # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elasticache.html#ElastiCache.Client.create_cache_cluster
      'CacheNodeType': 'cache.t2.medium',
      'Engine': 'redis',
      'EngineVersion': ec_details['latest-redis-version'],
      'PreferredMaintenanceWindow': 'sun:23:00-mon:01:30',
      'Port': constants_quine.REDIS_PORTS[0],
      'CacheSubnetGroupName': CACHE_SUBNET_KEY,
      'SecurityGroupIds': [sg_id for sg_id, sg in vpc_details['security-groups'].items() if sg['group-name'] == CACHE_SECURITY_GROUP_KEY],
      # redis engine 5 might have this enabled by default, I'm not sure
      # 'AuthToken': constants_quine.ENV_VARS['REDIS_AUTH_TOKEN'],
      # 'TransitEncryptionEnabled': True,
    }
    cache_cluster = ec_client.create_cache_cluster(**ec_properties)
    
  else:
    raise NotImplementedError

  vpc_details['elasticache-clusters'][cache_cluster['CacheCluster']['CacheClusterId']] = {
    'status': cache_cluster['CacheCluster']['CacheClusterStatus'],
    'node-count': cache_cluster['CacheCluster']['NumCacheNodes'],
    'engine': cache_cluster['CacheCluster']['Engine'],
    'engine-version': cache_cluster['CacheCluster']['EngineVersion'],
  }

def _sync_addresses(ec2_client: typing.Any, vpc: str, vpc_details: typing.Dict[str, typing.Any]) -> None:
  bastion_name = f'{constants_quine.CLUSTER_PREFIX}-bastion'
  for address in vpc_details['elastic-addresses']:
    if bastion_name in [tag['Value'] for tag in address['Tags'] if tag['Key'] == 'Name']:
      bastion_id = [_id for _id, instance in vpc_details['instances'].items() if instance['instance-name']['Value'].endswith('bastion') and instance['instance-name']['Value'].startswith(constants_quine.CLUSTER_PREFIX)][0]
      if bastion_id != address.get('InstanceId', None):
        try:
          ec2_client.associate_address(
              AllocationId=address['AllocationId'],
              InstanceId=bastion_id,
              AllowReassociation=True)
        except boto_exceptions.ClientError as err:
          logger.error(err)

      break

  else:
    # Create EIP
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.allocate_address<Paste>
    raise NotImplementedError

def _sync_route53_expectations(route53: typing.Any, vpc: str, vpc_details: typing.Dict[str, typing.Any], hosted_zones: typing.Dict[str, typing.Any]) -> None:
  def _sync_bastion():
    bastion = [instance for instance in vpc_details['instances'].values() if instance['instance-name']['Value'].endswith('bastion')][0]
    dns_name = f'bastion.{os.environ["DNS_NAME"]}.'
    zone_details = hosted_zones[constants_quine.DNS_NAME]
    def _update_bastion_ip() -> None:
      route53.change_resource_record_sets(
          HostedZoneId=zone_details['zone-id'],
          ChangeBatch={
            'Comment': 'Updating Bastion IP',
            'Changes': [
              {
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                  'TTL': 600,
                  'Name': dns_name,
                  'Type': 'A',
                  'ResourceRecords': [{'Value': bastion['public-ip-address']}]
                }
              }
            ]})

    if not dns_name in zone_details['records'].keys():
      _update_bastion_ip()

    else:
      record = [record['records'][0] for record in zone_details['records'][dns_name] if record['type'] == 'A'][0]
      if record != bastion['public-ip-address']:
        _update_bastion_ip()

  def _sync_alb():
    import ipdb; ipdb.set_trace()
    import sys; sys.exit(1)

  _sync_bastion()
  # _sync_alb()


def sync_aws_expectations(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  ec2_resource = boto3.resource('ec2')
  ec2_client = boto3.client('ec2')
  rds_client = boto3.client('rds')
  ec_client = boto3.client('elasticache')
  route53_client = boto3.client('route53')
  for vpc, vpc_details in payload['vpcs'].items():
    vpc_cidrblocks = [subnet['cidrblock'] for subnet in vpc_details['subnets'].values()]
    vpc_cidrblocks = _sync_subnet_expectations(ec2_resource, vpc, vpc_details, vpc_cidrblocks, SubnetType.PRIVATE)
    vpc_cidrblocks = _sync_subnet_expectations(ec2_resource, vpc, vpc_details, vpc_cidrblocks, SubnetType.PUBLIC)
    # _sync_route_tables(ec2_client, vpc, vpc_details)
    # _sync_nat_gateway(ec2_client, vpc, vpc_details)
    _sync_security_groups(ec2_client, vpc, vpc_details, payload['deployment-ips'])
    map_aws_security_groups(executor, payload)
    map_aws_subnets(executor, payload)
    _sync_bastion_expectations(ec2_resource, vpc, vpc_details, payload['ami-image-id'], payload['options'].deployment_type)
    _sync_appserver_expectations(ec2_resource, vpc, vpc_details, payload['ami-image-id'], payload['options'].deployment_type, payload['options'].instance_request_count)
    _sync_rds_expectations(rds_client, vpc, vpc_details, payload['options'].database_deployment_type)
    _sync_elastic_cache_expectations(ec_client, vpc, vpc_details, payload['options'].cache_deployment_type)
    map_aws_instances(executor, payload)
    _sync_addresses(ec2_client, vpc, vpc_details)
    _sync_route53_expectations(route53_client, vpc, vpc_details, payload['hosted-zones'])


async def map_cloudfront(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  cf = boto3.client('cloudfront')
  payload['cf-distributions'] = {}
  for page in cf.get_paginator('list_distributions').paginate():
    for dist in page['DistributionList']['Items']:
      distri = payload['cf-distributions'].get(dist['ARN'], {})
      distri['aliases'] = [ali for ali in {ali for ali in dist['Aliases']['Items']}]
      distri['domain-name'] = dist['DomainName']
      distri['id'] = dist['Id']
      payload['cf-distributions'][dist['ARN']] = distri

async def map_acm(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  acm = boto3.client('acm')
  payload['acm-certs'] = {}
  for page in acm.get_paginator('list_certificates').paginate():
    for cert in page['CertificateSummaryList']:
      payload['acm-certs'][cert['DomainName']] = {'arn': cert['CertificateArn']}
  
async def map_buckets(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  s3 = boto3.client('s3')
  payload['s3-buckets'] = [bucket['Name'] for bucket in s3.list_buckets()['Buckets']]

async def sync_bucket_for_client(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  s3 = boto3.client('s3')
  if not payload['options'].bucket_name in payload['s3-buckets']:
    bucket = s3.create_bucket(Bucket=payload['options'].bucket_name, ACL='public-read')

  try:
    s3.get_bucket_website(Bucket=payload['options'].bucket_name)
  except boto_exceptions.ClientError:
    website_configuration = {
        'ErrorDocument': {
          'Key': 'index.html',
        },
        'IndexDocument': {
          'Suffix': 'index.html',
        }
    }
    s3.put_bucket_website(Bucket=payload['options'].bucket_name, WebsiteConfiguration=website_configuration)

async def sync_aws_acm_for_client(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  acm = boto3.client('acm')
  route53 = boto3.client('route53')
  if not payload['options'].bucket_name in payload['acm-certs'].keys():
    result = acm.request_certificate(DomainName=payload['options'].bucket_name,
        IdempotencyToken='aoeu',
        ValidationMethod='DNS')
    cert = acm.describe_certificate(CertificateArn=result['CertificateArn'])

  else:
    cert = acm.describe_certificate(CertificateArn=payload['acm-certs'][payload['options'].bucket_name]['arn'])

  dns_validation = [awe for awe in cert['Certificate']['DomainValidationOptions'] if awe['ValidationMethod'] == 'DNS'][0]['ResourceRecord']
  for zone_name, zone_details in payload['hosted-zones'].items():
    if payload['options'].bucket_name.endswith(zone_name):
      if not dns_validation['Name'].strip('.') in [rec.strip('.') for rec in zone_details['records'].keys()]:
        route53.change_resource_record_sets(
            HostedZoneId=zone_details['zone-id'],
            ChangeBatch={
              'Comment': 'Updating Bastion IP',
              'Changes': [
                {
                  'Action': 'UPSERT',
                  'ResourceRecordSet': {
                    'TTL': 600,
                    'Name': dns_validation['Name'],
                    'Type': dns_validation['Type'],
                    'ResourceRecords': [{'Value': dns_validation['Value']}],
                  }
                }
              ]
            })

  delta: timedelta = timedelta(minutes=10)
  poll_start: datetime = datetime.utcnow()
  delay: int = 10
  while (poll_start + delta) > datetime.utcnow():
    cert = acm.describe_certificate(CertificateArn=payload['acm-certs'][payload['options'].bucket_name]['arn'])
    status = [awe for awe in cert['Certificate']['DomainValidationOptions'] if awe['ValidationMethod'] == 'DNS'][0]['ValidationStatus']
    if status == 'SUCCESS':
      break

    else:
      logger.info(f'Waiting on ACM Approval for Domain[{payload["options"].bucket_name}]')
      await asyncio.sleep(delay)

async def sync_cloudfront_for_client(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  cf = boto3.client('cloudfront')
  for cf_arn, cf_details in payload['cf-distributions'].items():
    if payload['options'].bucket_name in cf_details['aliases']:
      break

  else:
    origin_id = f'S3-{payload["options"].bucket_name}'
    cf_details = {
        'CallerReference': origin_id,
        'DefaultRootObject': '/index.html',
        'Aliases': {
          'Quantity': 1,
          'Items': [payload['options'].bucket_name],
        },
        'Origins': {
          'Quantity': 1,
          'Items': [
            {
              'DomainName': f'{payload["options"].bucket_name}.s3.amazonaws.com',
              'Id': origin_id,
              'CustomHeaders': {
                'Quantity': 0,
                'Items': []
              },
              'S3OriginConfig': {'OriginAccessIdentity': ''},
            }
          ]
        },
        'DefaultCacheBehavior': {
          'Compress': False,
          'DefaultTTL': 86500,
          'ForwardedValues': {
            'Cookies': {'Forward': 'none'},
            'Headers': {'Quantity': 0},
            'QueryString': False,
            'QueryStringCacheKeys': {'Quantity': 0}
          },
          'LambdaFunctionAssociations': {'Quantity': 0},
          'MaxTTL': 86400 * 2,
          'MinTTL': 0,
          'SmoothStreaming': False,
          'TargetOriginId': origin_id,
          'TrustedSigners': {'Enabled': False, 'Quantity': 0},
          'ViewerProtocolPolicy': 'redirect-to-https',
          'AllowedMethods': {
            'Quantity': 3,
            'Items': ['HEAD', 'GET', 'OPTIONS'],
            'CachedMethods': {
              'Quantity': 3,
              'Items': ['HEAD', 'GET', 'OPTIONS'],
            },
          },
          'FieldLevelEncryptionId': '',
        },
        'PriceClass': 'PriceClass_200',
        'ViewerCertificate': {
          'ACMCertificateArn': payload['acm-certs'][payload["options"].bucket_name]['arn'],
          'SSLSupportMethod': 'sni-only', # vip
          'CertificateSource': 'acm',
        },
        'Enabled': True,
        'Comment': f'Client for {constants_quine.CLUSTER_PREFIX}',
    }
    distribution = cf.create_distribution(DistributionConfig=cf_details)

