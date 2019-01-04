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
    tail_deployment as deployment_quine

logger = logging.getLogger(__name__)
def capture_options() -> typing.Any:
  parser = argparse.ArgumentParser()
  parser.add_argument('-d', '--deployment-type', default=constants_quine.DeploymentType.NOOP, type=constants_quine.DeploymentType)
  parser.add_argument('-b', '--database-deployment-type', default=constants_quine.DatabaseDeploymentType.NOOP, type=constants_quine.DatabaseDeploymentType)
  parser.add_argument('-c', '--cache-deployment-type', default=constants_quine.CacheDeploymentType.NOOP, type=constants_quine.CacheDeploymentType)
  return parser.parse_args()

async def run_deployment() -> typing.Dict[str, typing.Any]:
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

      #deployment_quine.clear_containers,
      deployment_quine.sync_containers,
      deployment_quine.deploy,)
      #deployment_quine.clear_images,)

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

async def main() -> None:
  cluster_info = await run_deployment()

if __name__ in ['__main__']:
  event_loop = common_quine.obtain_event_loop()
  event_loop.run_until_complete(main())

