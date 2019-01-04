#!/usr/bin/env python

import aiofiles
import argparse
import asyncio
import inspect
import logging
import os
import typing

from quine import \
    tail_common as common_quine, \
    tail_build as build_quine

logger = logging.getLogger(__name__)
def capture_options() -> typing.Any:
  parser = argparse.ArgumentParser()
  parser.add_argument('-f', '--docker-file', default=None, type=str)
  return parser.parse_args()

async def run_deployment() -> typing.Dict[str, typing.Any]:
  call_chain = (
      build_quine.build,
      build_quine.ops,
      build_quine.webservice,)

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

