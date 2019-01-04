import jinja2
import logging
import os
import subprocess
import time
import typing

from quine import tail_constants as constants_quine

JINJA2_ENV = jinja2.Environment(trim_blocks=True, autoescape=False, loader=jinja2.FileSystemLoader(os.path.abspath('.')))
logger = logging.getLogger(__name__)

def run_commands(commands: typing.List[str], expected_code: int=0) -> typing.List[str]:
  results: typing.List[str] = []
  for command in commands:
    logger.info(f'Running Command[{command}]')
    proc = subprocess.Popen([command], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    while proc.poll() is None:
      time.sleep(.1)

    if proc.poll() > 0:
      stderr = proc.stderr.read()
      if b'Connection timed out' in stderr and 'ssh' in command:
        raise Remote.SSHConnectTimeout

      if proc.poll() is expected_code:
        break

      logger.error(f'Unable to complete command[{command}]. Exit Code[{proc.poll()}]')
      logger.exception(stderr)
      raise NotImplementedError

    results.append((proc.poll(), proc.stdout.read()))

  return results

class Remote:
  _instance: typing.Dict[str, typing.Any]

  class SSHConnectTimeout(Exception):
    pass

  def __init__(self, instance: typing.Dict[str, typing.Any]) -> None:
    self._instance = instance

  def run_commands(self, commands: typing.List[str], expected_code: int=0) -> typing.List[str]:
    commands = [f'ssh {self._instance["instance-name"]["Value"]} "{command}"' for command in commands]
    return run_commands(commands, expected_code)

  def _sync_scripts(self, scripts: typing.List[str]) -> typing.List[str]:
    paths: typing.List[str] = []
    for script in scripts:
      path = tempfile.NamedTemporaryFile().name
      with codecs.open(path, 'w', 'utf-8') as stream:
        stream.write(script)

      paths.append(path)

    for path in paths:
      result = run_command([f'scp {path} {instance["instance-name"]["Value"]}:{path}'])
      logger.info(f'Synced Script[{path}] to Instance[{instance["instance-name"]["Value"]}]')

    return paths

  def run_scripts(self, scripts: typing.List[str], uber: bool=False) -> None:
    paths: typing.List[str] = self._sync_scripts(scripts)
    logger.info(f'Running Scripts on Instance[{instance["instance-name"]["Value"]}]')
    for path in paths:
      head, tail = path.rsplit('.')
      interpreter = {
          'py': 'python',
          'sh': 'bash'}.get(tail, None)
      if interpreter is None:
        raise NotImplementedError(interpreter)

      run_command([
        f'ssh {instance["instance-name"]["Value"]} "sudo {interpreter} {path}"' if uber else f'ssh {instance["instance-name"]["Value"]} "{interpreter} {path}"'
      ])

async def render_script(docker_script_path: str, context: typing.Dict[str, typing.Any]) -> str:
  path = os.path.join(os.getcwd(), docker_script_path)
  async with aiofiles.open(path, 'rb') as stream:
    template = JINJA2_ENV.from_string(
        (await stream.read()).decode(constants_quine.ENCODING))
    return template.render(context)

class Cluster:
  _cluster_info: typing.Dict[str, typing.Any]
  def __init__(self, cluster_info: typing.Dict[str, typing.Any]) -> None:
    self._cluster_info = cluster_info
    
  def run_commands_on_bastion(self, commands: typing.List[str], expected_code: int=0) -> typing.Dict[str, typing.List[str]]:
    results: typing.Dict[str, typing.List[str]] = {}
    for vpc, vpc_details in self._cluster_info['vpcs'].items():
      bastion_id, bastion = [(_id, instance) for _id, instance in vpc_details['instances'].items() if instance['instance-name']['Value'].endswith('bastion')][0]
      results[bastion_id] = Remote(bastion).run_commands(commands, expected_code)

    return results

  def run_commands_on_appservers(self, commands: typing.List[str], expected_code: int=0) -> typing.Dict[str, typing.List[str]]:
    results: typing.Dict[str, typing.List[str]] = {}
    for vpc, vpc_details in self._cluster_info['vpcs'].items():
      bastion_id, bastion = [(_id, instance) for _id, instance in vpc_details['instances'].items() if instance['instance-name']['Value'].endswith('bastion')][0]
      for instance_id, instance in vpc_details['instances'].items():
        if instance_id == bastion_id:
          continue

        if not instance['instance-name']['Value'].startswith(constants_quine.RESOURCE_PREFIX):
          continue

        results[instance_id] = Remote(instance).run_commands(commands, expected_code)

    return results

  def run_scripts_on_bastion(self, scripts: typing.List[str]) -> None:
    for vpc, vpc_details in cluster_info['vpcs'].items():
      bastion_id, bastion = [(_id, instance) for _id, instance in vpc_details['instances'].items() if instance['instance-name']['Value'].endswith('bastion')][0]
      Remote(instance).run_scripts(scripts, uber=True)

  def run_scripts_on_appservers(self, scripts: typing.List[str]) -> typing.List[str]:
    for vpc, vpc_details in cluster_info['vpcs'].items():
      bastion_id, bastion = [(_id, instance) for _id, instance in vpc_details['instances'].items() if instance['instance-name']['Value'].endswith('bastion')][0]
      for instance_id, instance in vpc_details['instances'].items():
        if instance_id == bastion_id:
          continue
  
        Remote(instance).run_scripts(scripts, uber=True)

