#!/usr/bin/env python

import aiofiles
import argparse
import asyncio
import inspect
import logging
import os
import typing

from quine import \
  tail_constants as constants_quine, \
  tail_common as common_quine, \
  tail_services as services_quine, \
  tail_checkpoints as checkpoints_quine

logger = logging.getLogger(__name__)
def capture_options() -> typing.Any:
  parser = argparse.ArgumentParser()
  parser.add_argument('-o', '--output_path', default=None, type=str, required=True)
  parser.add_argument('-d', '--deployment-type', default=constants_quine.DeploymentType.NOOP, type=constants_quine.DeploymentType)
  parser.add_argument('-b', '--database-deployment-type', default=constants_quine.DatabaseDeploymentType.NOOP, type=constants_quine.DatabaseDeploymentType)
  parser.add_argument('-c', '--cache-deployment-type', default=constants_quine.CacheDeploymentType.NOOP, type=constants_quine.CacheDeploymentType)
  parser.add_argument('-r', '--instance-request-count', default=1, type=int)
  parser.add_argument('-s', '--omit-service-definitions', default=False, action='store_true')
  parser.add_argument('-f', '--focal-type', default=constants_quine.FocalType.NOOP, type=constants_quine.FocalType)
  return parser.parse_args()

async def launch_services(cluster_info: typing.Dict[str, typing.Any]) -> typing.Dict[str, typing.Any]:
  call_chain = (
      services_quine.generate_ssh_configs,
      services_quine.generate_ssh_knownhosts,
      services_quine.install_docker_runtime,
      services_quine.force_reboot,
      services_quine.install_docker_registry,)

  with common_quine.obtain_executor() as executor:
    payload: typing.Dict[str, typing.Any] = {
      'options': capture_options(),
    }
    for operation in call_chain:
      if inspect.iscoroutinefunction(operation):
        await operation(executor, payload, cluster_info)

      else:
        task = executor.submit(operation, executor, payload, cluster_info)
        while not task.done() is True:
          await asyncio.sleep(.1)

        try:
          task.result()
        except Exception as err:
          raise err

  return payload

async def launch_cluster() -> typing.Dict[str, typing.Any]:
  call_chain = (
      common_quine.map_deployment_ips,
      common_quine.map_aws_route53,
      common_quine.map_aws_images,
      common_quine.map_aws_vpcs,
      common_quine.map_aws_ips,
      common_quine.map_aws_rds,
      common_quine.map_aws_elasticache,
      common_quine.map_aws_subnets,
      common_quine.map_aws_security_groups,
      common_quine.map_aws_instances,
      common_quine.sync_aws_expectations)
  with common_quine.obtain_executor() as executor:
    payload: typing.Dict[str, typing.Any] = {
      'options': capture_options(),
    }
    for operation in call_chain:
      if inspect.iscoroutinefunction(operation):
        await operation(executor, payload)

      else:
        task = executor.submit(operation, executor, payload)
        while not task.done() is True:
          await asyncio.sleep(.1)

        try:
          task.result()
        except Exception as err:
          raise err

  return payload

async def render_generated_envvars(cluster_info: typing.Dict[str, typing.Any], output_path: str) -> None:
  dir_path = os.path.dirname(output_path)
  if not os.path.exists(dir_path):
    os.makedirs(dir_path)

  env_vars = {key: value for key, value in constants_quine.ENV_VARS.items()}
  if not len(cluster_info['vpcs'].keys()) == 1:
    raise NotImplementedError

  for vpc, vpc_details in cluster_info['vpcs'].items():
    try:
      env_vars['PSQL_POOL'] = vpc_details['rds-instances'][common_quine.RDS_KEY]['uri']
    except KeyError:
      logger.info('Omitting PSQL_POOL ENVVar')
      env_vars['PSQL_POOL'] = ''

    env_vars['REDIS_POOL'] = vpc_details['elasticache-clusters'][common_quine.CACHE_KEY]['endpoint']

  template_path = os.path.join(os.getcwd(), 'quine/templates/env-source.sh')
  async with aiofiles.open(template_path, 'rb') as stream:
    template = services_quine.JINJA2_ENV.from_string(
        (await stream.read()).decode(constants_quine.ENCODING))
    logger.info(f'Writing ENVVar File[{output_path}]')
    async with aiofiles.open(output_path, 'wb') as stream:
      await stream.write(template.render({'ENVVars': env_vars}).encode(constants_quine.ENCODING))

async def main() -> None:
  while True:
    cluster_info = await launch_cluster()
    cluster_ready = await checkpoints_quine.is_cluster_ready_for_deployment(cluster_info)
    if cluster_ready:
      break

  if not capture_options().omit_service_definitions:
    logger.info('Sync Service Definitions')
    await launch_services(cluster_info)

  else:
    logger.info('Omitting Service Definitions')

  await render_generated_envvars(cluster_info, capture_options().output_path)
  
if __name__ in ['__main__']:
  event_loop = common_quine.obtain_event_loop()
  event_loop.run_until_complete(main())

