#!/usr/bin/env python

import logging
import typing

logger = logging.getLogger(__name__)

async def is_cluster_ready_for_deployment(info: typing.Dict[str, typing.Any]) -> bool:
  for vpc, vpc_details in info['vpcs'].items():
    try:
      bastion_id, bastion = [(_id, instance) for _id, instance in vpc_details['instances'].items() if instance['instance-name']['Value'].endswith('bastion')][0]
    except (IndexError, KeyError) as err:
      logger.info('Bastion Elastic-IP not updated')
      return False

    else:
      logger.info('Bastion Elastic-IP not updated')
      if not bastion['public-ip-address'] in [addr['PublicIp'] for addr in vpc_details['elastic-addresses']]:
        return False

    try:
      [awe['uri'] for awe in vpc_details['rds-instances'].values()]
    except KeyError as err:
      logger.info('RDSInstances not ready')
      return False

    try:
      [awe['endpoint'] for awe in vpc_details['elasticache-clusters'].values() if awe['status'] == 'available']

    except (KeyError, IndexError) as err:
      logger.info('Elasticache Clusters not ready')
      return False

  return True

