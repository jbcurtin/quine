#!/usr/bin/env python

import aiofiles
import asyncio
import argparse
import jinja2
import logging
import os
import typing

from quine import tail_common as common_quine, tail_constants as constants_quine

logger = logging.getLogger(__name__)

def capture_options() -> typing.Any:
  parser = argparse.ArgumentParser()
  parser.add_argument('-t', '--template-path', default=None, type=str)
  parser.add_argument('-o', '--output-path', default=None, type=str)
  #parser.add_argument('-e', '--env-file-path', default=None, type=str)
  return parser.parse_args()

async def main() -> None:
  options = capture_options()
  with common_quine.obtain_executor() as executor:
    results = []
    results.append(executor.submit(common_quine.create_dir_of_path, options.output_path))
    results.append(executor.submit(common_quine.obtain_jinja2_env))
    while not all([item.done() for item in results]):
      await asyncio.sleep(.1)

  async with aiofiles.open(options.output_path, 'w') as output_stream:
    async with aiofiles.open(options.template_path, 'r') as stream:
      template = await stream.read()
      template = constants_quine.JINJA2_ENV.from_string(template)
      template_context = {key: globals()[key] for key in ['constants_quine']}
      output = template.render(template_context)
      logger.info(f'Writing File to Path[{options.output_path}]')
      await output_stream.write(output)

if __name__ in ['__main__']:
  event_loop = common_quine.obtain_event_loop()
  event_loop.run_until_complete(main())

