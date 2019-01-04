#!/usr/bin/env python

import aiofiles
import asyncio
import argparse
import os
import logging
import typing

from quine import \
    tail_constants as constants_quine, \
    tail_common as common_quine

logger = logging.getLogger(__name__)
def capture_options() -> typing.Any:
  parser = argparse.ArgumentParser()
  parser.add_argument('-o', '--output-path', default=None, type=str)
  return parser.parse_args()

async def main() -> None:
  options = capture_options()
  with common_quine.obtain_executor() as executor:
    results = []
    results.append(executor.submit(common_quine.create_dir_of_path, options.output_path))
    results.append(executor.submit(common_quine.obtain_jinja2_env))
    while not all([item.done() for item in results]):
      await asyncio.sleep(.1)

  template = """#!/usr/bin/env bash
export DEPLOYMENT="{{constants_quine.DEPLOYMENT}}"
export STAGE="{{constants_quine.STAGE}}"
export VERSION="{{constants_quine.VERSION}}"
{% for var_name, value in constants_quine.ENV_VARS.items() %}
export {{var_name}}="{{value}}"
{% endfor %}
"""
  template = constants_quine.JINJA2_ENV.from_string(template)
  template_context = {key: globals()[key] for key in ['constants_quine']}
  output = template.render(template_context)
  logger.info(f'Writing ENVVars to path[{options.output_path}]')
  async with aiofiles.open(options.output_path, 'w') as stream:
    await stream.write(output)
  
if __name__ in ['__main__']:
  event_loop = common_quine.obtain_event_loop()
  event_loop.run_until_complete(main())


