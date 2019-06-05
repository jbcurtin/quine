# Quine

## Design

`quine` orchestrates in one shell command to create complex and secure deployments. Taking basic components of Amazon Web Services, turning them into actionable notes of information with quine-map-scripts, a quine-orc-script can be utilized to decide what to do next in an AWS Account. Using quine, you'll be able to identify and designate any number of number of cluster configurations that'll allow testing software in isolated environments

https://jbcurtin.github.io/quine-project.jbcurtin.io/

## Fund Bounty Target Upgrades

The initial build of Quine took about two months of development. There are still some areas where the codebase could be upgraded to provide better support for larger companies to deploy hundreds of servers at a time. Please consider contributing to Quine Bounty Targets

https://www.patreon.com/jbcurtin

Today, Quine is capable of the following opinionated deployment scenarios
- AWS Cloud Front, ACM, and S3 delpoyment for custom domain
- Private VPC Configuration, complete with bastion service available from an Elastic IP. EC2 Nodes have `docker` and `docker-compose` installed
- Public VPC Configuration, complete with bastion service available from an Elastic IP. EC2 Nodes have `docker` and `docker-compose` installed
- Public VPC configuration, complete with bastion service available from an Elastic IP. This is done to advert malicious users from being able to scan and have access to the cluster
- ElasticCache(Redis) Single node deployment. ElasticCache(Redis) is configured to launch within a VPC private subnet only.
- RDS(PostrgeSQL) Single node deployment. RDS(PostgreSQL) is configured to launch within a VPC private subnet only.

[AWS Documentation about vpc deployment scenarios](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Scenarios.html)

`quine` is looking for funding for the following Bounty Target Upgrades
- ElasticCache(Redis) Multi Node Deployment ( $1,000 )
- RDS(PostgreSQL) High Availability Deployemnt with and without Aurora DB ( $10,000 )
- RDS(MySQL) Single Node Deployemnt without Aurora DB ( $2,000 )
- RDS(MySQL) High Availability Deployemnt with and without Aurora DB ( $10,000 )
- Overhaul of the Command Style interface using Python rather than a `bash operations.sh` file. This'll include complete documentation ( $25,000 )
- Private VPC Configuration, complete with bastion service available from an Elastic IP with Kubernetes ( $1,000 )
- Public VPC Configuration, complete with bastion service available from an Elastic IP with Kubernetes ( $1,000 )
- Conncurrent SSH Support, adds the ability to allocate hundreds of EC2 Nodes ( $10,000 )
- RnD around deploying Thousands of EC2 Nodes in the shortest amount of time possible ( hourly rate )
- Route53 Private Hosted Zone support ( https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/hosted-zones-private.html ) ( $5,000 )
- Enable intelligent ACM allocation and updates when new subdomains are added to TLDs within a Route53 Hosted Zone ( https://github.com/jbcurtin/quine#acm ) ( $15,000 )

## Build Steps

```
- First, creating the VPC, subnets, security groups, RDS, Elastic-Cache, finally allocating Load Balancers for Turtle and Forward Application Load Balancers. The first step completes with installation and execution of init scripts to install the Docker Runtime

- Second, Generates dockerfiles using jinja2, then builds docker images from the dockerfiles

- Third, maps out the cluster. Looking for EC2 instances that match the profile and deploys the docker containers accordingly

- Fourth, optionally create a Cloud Front distribution
```

The build steps can be managed by an `operations.sh` file
```
#!/usr/bin/env bash
set -x
set -e

if [ "$1" == 'client-map' ]; then
  assert_build_env_vars
  source build-tools/$RESOURCE_NAME.$DNS_NAME/env-var-names.sh
  source build-tools/$RESOURCE_NAME.$DNS_NAME/$STAGE.sh
  PYTHONPATH='.' python quine/generate-deployment-env.py -o build-tools/outputs/$DEPLOYMENT.$STAGE.$RESOURCE_NAME.$DNS_NAME.sh
  PYTHONPATH='.' python quine/build-client-distri.py -b $(build_bucket_name)
fi
if [ "$1" == 'client-bulid' ]; then
  assert_build_env_vars
  source build-tools/outputs/$DEPLOYMENT.$STAGE.$RESOURCE_NAME.$DNS_NAME.sh
  pushd $DNS_NAME 2>/dev/null
  export NODE_ENV=$STAGE
  export PATH="$(npm bin):$PATH"
  npm install @vue/cli
  npm install
  npm run build
  popd 2>/dev/null
fi
if [ "$1" == 'client-deploy' ]; then
  assert_build_env_vars
  pushd $DNS_NAME 2>/dev/null
  aws s3 sync . s3://$(build_bucket_name)/ --acl public-read
  popd 2>/dev/null
fi
if [ "$1" == 'full-deploy-client' ]; then
  assert_build_env_vars
  export SERVICE_DNS_NAME='https://'
  RESOURCE_NAME='client' DNS_NAME='quine.pspython.com' VERSION='latest' STAGE='develop' DEPLOYMENT='pleiades' bash operations.sh client-map
  RESOURCE_NAME='client' DNS_NAME='quine.pspython.com' VERSION='latest' STAGE='develop' DEPLOYMENT='pleiades' bash operations.sh client-build
  RESOURCE_NAME='client' DNS_NAME='quine.pspython.com' VERSION='latest' STAGE='develop' DEPLOYMENT='pleiades' bash operations.sh client-deploy
fi
if [ "$1" == 'forward-map' ]; then
  assert_build_env_vars
  source build-tools/$RESOURCE_NAME.$DNS_NAME/env-var-names.sh
  source build-tools/$RESOURCE_NAME.$DNS_NAME/$STAGE.sh
  PYTHONPATH='.' python quine/generate-deployment-env.py -o build-tools/outputs/$DEPLOYMENT.$STAGE.$RESOURCE_NAME.sh
  PYTHONPATH='.' python quine/build-cluster.py -o build-tools/outputs/$DEPLOYMENT.$STAGE.cluster-env-info.sh -d forward-array -b dynamodb -c redis
fi

# Turtle Utility Functions
if [ "$1" == 'turtle-map' ]; then
  assert_build_env_vars
  source build-tools/$RESOURCE_NAME.$DNS_NAME/env-var-names.sh
  source build-tools/$RESOURCE_NAME.$DNS_NAME/$STAGE.sh
  PYTHONPATH='.' python quine/generate-deployment-env.py -o build-tools/outputs/$DELPOYMENT.$STAGE.$RESOURCE_NAME.sh
  PYTHONPATH='.' python quine/build-cluster.py -o build-tools/outputs/$DEPLOYMENT.$STAGE.cluster-env-info.sh -d turtle -d rds -c redis
fi

# Union
if [ "$1" == 'turtle-build' ] || [ "$1" == 'forward-build' ]; then
  assert_build_env_vars
  source build-tools/$RESOURCE_NAME.$DNS_NAME/env-vars-name.sh
  source build-tools/$RESOURCE_NAME.$DNS_NAME/$STAGE.sh
  source build-tools/outputs/$DEPLOYMENT.$STAGE.$RESOURCE_NAME.sh
  source build-tools/outputs/$DEPLOYMENT.$STAGE.cluster-env-info.sh
  PYTHONPATH='.' python quine/render-template.py \
    -o build-tools/outputs/$RESOURCE_NAME.$DNS_NAME/build.Dockerfile \
    -t build-tools/$RESOURCE_NAME.$DNS_NAME/build.template.Dockerfile
  PYTHONPATH='.' python quine/render-template.py \
    -o build-tools/outputs/$RESOURCE_NAME.$DNS_NAME/ops.Dockerfile \
    -t build-tools/$RESOURCE_NAME.$DNS_NAME/ops.template.Dockerfile
  PYTHONPATH='.' python quine/render-template.py \
    -o build-tools/outputs/$RESOURCE_NAME.$DNS_NAME/webservice.Dockerfile \
    -t build-tools/$RESOURCE_NAME.$DNS_NAME/opts.template.Dockerfile
  PYTHONPATH='.' python quine/build-images.py -f build-tools/outputs/$RESOURCE_NAME.$DNS_NAME
fi
if [ "$1" == 'turtle-push' ] || [ "$1" == 'forward-push' ]; then
  assert_build_env_vars
  source build-tools/$RESOURCE_NAME.$DNS_NAME/env-var-names.sh
  source build-tools/outputs/$DEPLOYMENT.$STAGE.central.sh
  source build-tools/outputs/$DEPLOYMENT.$STAGE.cluster-env-info.sh
  docker tag $DEPLOYMENT-$STAGE-ops-$RESOURCE_NAME-$(flatten_dns_name $DNS_NAME):$VERSION bastion.$DNS_NAME/$DEPLOYMENT-$STAGE-ops-$RESOURCE_NAME-$(flatten_dns_name $DNS_NAME):$VERSION
  docker tag $DEPLOYMENT-$STAGE-webservice-$RESOURCE_NAME-$(flatten_dns_name $DNS_NAME):$VERSION bastion.$DNS_NAME/$DEPLOYMENT-$STAGE-webservice-$RESOURCE_NAME-$(flatten_dns_name $DNS_NAME):$VERSION

  docker push bastion.$DNS_NAME/$DEPLOYMENT-$STAGE-ops-$RESOURCE_NAME-$(flatten_dns_name $DNS_NAME):$VERSION &
  docker push bastion.$DNS_NAME/$DEPLOYMENT-$STAGE-webservice-$RESOURCE_NAME-$(flatten_dns_name $DNS_NAME):$VERSION &
fi
if [ "$1" == 'turtle-deploy' ] || [ "$1" == 'forward-deploy' ]; then
  assert_build_env_vars
  source build-tools/$RESOURCE_NAME.$DNS_NAME/env-var-names.sh
  source build-tools/$RESOURCE_NAME.$DNS_NAME/$STAGE.sh
  source build-tools/$RESOURCE_NAME.$DNS_NAME.$STAGE.cluster-env-info.sh
  unset AWS_ACCESS_KEY_ID
  unset AWS_SECRET_ACCESS_KEY
  unset AWS_DEFAULT_REGION
  PYTHONPATH='.' python quine/run-deployment.py
fi
if [ "$1" == 'turtle-focal-point' ] || [ "$1" == 'forward-focal-point' ]; then
  assert_build_env_vars
  source build-tools/$RESOURCE_NAME.$DNS_NAME/env-var-names.sh
  source build-tools/$RESOURCE_NAME.$DNS_NAME/$STAGE.sh
  source build-tools/outputs/$DEPLOYMENT.$STAGE.cluster-env-info.sh
  unset AWS_ACCESS_KEY_ID
  unset AWS_SECRET_ACCESS_KEY
  unset AWS_DEFAULT_REGION
  if [ "$1" == 'turtle-focal-point' ]; then
    PYTHONPATH='.' python quine/build-focal-poins.py -f turtle
  fi
  if [ "$1" == 'forward-focal-point' ]; then
    PYTHONPATH='.' python quine/build-focal-poins.py -f forward
  fi
fi

# Forward Array
if [ "$1" == 'full-deploy-forward' ]; then
  RESOURCE_NAME='forward' DNS_NAME='quine.pspython.com' VERSION='latest' STAGE='develop' DEPLOYMENT='pleiades' bash operations.sh service-map
  RESOURCE_NAME='forward' DNS_NAME='quine.pspython.com' VERSION='latest' STAGE='develop' DEPLOYMENT='pleiades' bash operations.sh service-bulid
  RESOURCE_NAME='forward' DNS_NAME='quine.pspython.com' VERSION='latest' STAGE='develop' DEPLOYMENT='pleiades' bash operations.sh service-push
  RESOURCE_NAME='forward' DNS_NAME='quine.pspython.com' VERSION='latest' STAGE='develop' DEPLOYMENT='pleiades' bash operations.sh service-deploy
  RESOURCE_NAME='forward' DNS_NAME='quine.pspython.com' VERSION='latest' STAGE='develop' DEPLOYMENT='pleiades' bash operations.sh service-focal-point
fi

# Turtle
if [ "$1" == 'full-deploy-turtle' ]; then
  RESOURCE_NAME='turtle' DNS_NAME='quine.pspython.com' VERSION='latest' STAGE='develop' DEPLOYMENT='pleiades' bash operations.sh central-map
  RESOURCE_NAME='turtle' DNS_NAME='quine.pspython.com' VERSION='latest' STAGE='develop' DEPLOYMENT='pleiades' bash operations.sh central-build
  RESOURCE_NAME='turtle' DNS_NAME='quine.pspython.com' VERSION='latest' STAGE='develop' DEPLOYMENT='pleiades' bash operations.sh central-push
  RESOURCE_NAME='turtle' DNS_NAME='quine.pspython.com' VERSION='latest' STAGE='develop' DEPLOYMENT='pleiades' bash operations.sh central-deploy
  RESOURCE_NAME='turtle' DNS_NAME='quine.pspython.com' VERSION='latest' STAGE='develop' DEPLOYMENT='pleiades' bash operations.sh central-focal-point
fi
```

## Limitations
### ACM

ACM only allows 10 certs per accounts relative to the domain. Updating certs to update subject alt-names is important to move forward with this.

https://docs.aws.amazon.com/acm/latest/userguide/acm-limits.html

ACM Logs Cert creation publically. This should be disabled in the future
https://docs.aws.amazon.com/acm/latest/userguide/acm-concepts.html#concept-transparency

### Route53

In order to save time, I've opted to bypass the requirement to manage private-DNS. For private DNS, I would have to add an additional Hosted Zone with VPC to route requests. In the future, it needs to be fixed so that DNS requests only happen locally.

### Concurrent SSH Connections

A plan has yet been created to connect to more than 20 servers at once.
