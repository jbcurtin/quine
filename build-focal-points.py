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
  tail_checkpoints as checkpoints_quine

logger = logging.getLogger(__name__)
def capture_options() -> typing.Any:
  parser = argparse.ArgumentParser()
  parser.add_argument('-f', '--focal-type', default=constants_quine.FocalType.NOOP, type=constants_quine.FocalType)
  #parser.add_argument('-d', '--deployment-type', default=constants_quine.DeploymentType.NOOP, type=constants_quine.DeploymentType)
  #parser.add_argument('-b', '--database-deployment-type', default=constants_quine.DatabaseDeploymentType.NOOP, type=constants_quine.DatabaseDeploymentType)
  #parser.add_argument('-c', '--cache-deployment-type', default=constants_quine.CacheDeploymentType.NOOP, type=constants_quine.CacheDeploymentType)
  #parser.add_argument('-s', '--omit-service-definitions', default=False, action='store_true')
  return parser.parse_args()


async def execute_map_call_chain(call_chain: typing.List[typing.Callable]) -> typing.Dict[str, typing.Any]:
  with common_quine.obtain_executor() as executor:
    payload = {
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


async def execute_call_chain(cluster_info: typing.Dict[str, typing.Any], call_chain: typing.List[typing.Callable]) -> typing.Dict[str, typing.Any]:
  with common_quine.obtain_executor() as executor:
    for operation in call_chain:
      if inspect.iscoroutinefunction(operation):
        await operation(executor, cluster_info)

      else:
        task = executor.submit(operation, executor, cluster_info)
        while not task.done() is True:
          await asyncio.sleep(.1)

        try:
          task.result()

        except Exception as err:
          raise err

  return cluster_info


async def launch_focal_points(cluster_info: typing.Dict[str, typing.Any]) -> typing.Dict[str, typing.Any]:
  call_chain = (
      common_quine.sync_aws_acm_for_albs,
      common_quine.sync_aws_alb_target_groups,
      common_quine.sync_aws_alb_target_group_members,
      common_quine.sync_aws_alb_instances,
      common_quine.sync_aws_alb_listeners,
      common_quine.sync_aws_alb_target_group_rules)
      #common_quine.sync_aws_alb_dns)

  return await execute_call_chain(cluster_info, call_chain)


async def map_cluster(cluster_info: typing.Dict[str, typing.Any]) -> typing.Dict[str, typing.Any]:
  call_chain = (
      common_quine.map_deployment_ips,
      common_quine.map_aws_route53,
      common_quine.map_acm,
      common_quine.map_aws_alb_target_groups,
      common_quine.map_aws_alb_target_group_members,
      common_quine.map_aws_alb_instances,
      common_quine.map_aws_alb_listeners,
      common_quine.map_aws_alb_target_group_rules,
      common_quine.map_aws_images,
      common_quine.map_aws_vpcs,
      common_quine.map_aws_ips,
      common_quine.map_aws_rds,
      common_quine.map_aws_elasticache,
      common_quine.map_aws_subnets,
      common_quine.map_aws_security_groups,
      common_quine.map_aws_instances)

  return await execute_map_call_chain(call_chain)


async def main() -> None:
  cluster_info = {}
  while True:
    cluster_info = await map_cluster(cluster_info)
    cluster_ready = await checkpoints_quine.is_cluster_ready_for_deployment(cluster_info)
    if cluster_ready:
      break

  await launch_focal_points(cluster_info)


if __name__ in ['__main__']:
  event_loop = common_quine.obtain_event_loop()
  event_loop.run_until_complete(main())

