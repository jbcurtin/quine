import aiofiles
import asyncssh
import codecs
import concurrent
import logging
import jinja2
import os
import subprocess
import tempfile
import time
import typing

from datetime import datetime, timedelta

from pprint import pprint

from quine import tail_constants as constants_quine

class SSHConnectTimeout(Exception):
  pass

JINJA2_ENV = jinja2.Environment(trim_blocks = True, autoescape = False, loader=jinja2.FileSystemLoader(os.path.abspath('.')))
logger = logging.getLogger(__name__)

def _sync_scripts_to_remote(scripts: typing.List[str], instance: typing.Dict[str, typing.Any]) -> typing.List[str]:
  paths: typing.List[str] = []
  for script in scripts:
    path = tempfile.NamedTemporaryFile().name
    with codecs.open(path, 'w', 'utf-8') as stream:
      stream.write(script)

    paths.append(path)

  for path in paths:
    result = _run_command([f'scp {path} {instance["instance-name"]["Value"]}:{path}'])
    logger.info(f'Synced Script[{path}] to Instance[{instance["instance-name"]["Value"]}]')

  return paths

def _run_remote_scripts(paths: typing.List[str], instance: typing.Dict[str, typing.Any], uber:str=False) -> typing.List[str]:
  logger.info(f'Running Scripts on Instance[{instance["instance-name"]["Value"]}]')
  for path in paths:
    _run_command([
      f'ssh {instance["instance-name"]["Value"]} "sudo bash {path}"' if uber else f'ssh {instance["instance-name"]["Value"]} "bash {path}"'
    ])

def _run_command(commands: typing.List[str], shell: bool=True, expected_code: int=0) -> typing.List[str]:
  results: typing.List[str] = []
  for command in commands:
    logger.info(f'Running Command[{command}]')
    proc = subprocess.Popen([command], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=shell)
    while proc.poll() is None:
      time.sleep(.1)

    if proc.poll() > 0:
      stderr = proc.stderr.read()
      if b'Connection timed out' in stderr and 'ssh' in command:
        raise SSHConnectTimeout

      if proc.poll() is expected_code:
        break

      logger.error(f'Unable to complete command[{command}]. Exit Code[{proc.poll()}]')
      logger.exception(stderr)
      raise NotImplementedError

    results.append((proc.poll(), proc.stdout.read()))

  return results

async def _render_script(docker_script_path: str, context: typing.Dict[str, typing.Any]) -> str:
  path = os.path.join(os.getcwd(), docker_script_path)
  async with aiofiles.open(path, 'rb') as stream:
    template = JINJA2_ENV.from_string(
        (await stream.read()).decode(constants_quine.ENCODING))
    return template.render(context)

async def _run_scripts_on_bastion(cluster_info: typing.Dict[str, typing.Any], scripts: typing.List[str]) -> None:
  for vpc, vpc_details in cluster_info['vpcs'].items():
    bastion_id, bastion = [(_id, instance) for _id, instance in vpc_details['instances'].items() if instance['instance-name']['Value'].endswith('bastion')][0]
    paths = _sync_scripts_to_remote(scripts, bastion)
    _run_remote_scripts(paths, bastion, True)

async def _run_scripts_on_appservers(cluster_info: typing.Dict[str, typing.Any], scripts: typing.List[str]) -> None:
  for vpc, vpc_details in cluster_info['vpcs'].items():
    bastion_id, bastion = [(_id, instance) for _id, instance in vpc_details['instances'].items() if instance['instance-name']['Value'].endswith('bastion')][0]
    for instance_id, instance in vpc_details['instances'].items():
      if instance_id == bastion_id:
        continue

      paths = _sync_scripts_to_remote(scripts, instance)
      _run_remote_scripts(paths, instance, True)

async def force_reboot(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any], cluster_info: typing.Dict[str, typing.Any]) -> None:
  for vpc, vpc_details in cluster_info['vpcs'].items():
    bastion_id, bastion = [(_id, instance) for _id, instance in vpc_details['instances'].items() if instance['instance-name']['Value'].endswith('bastion')][0]
    for instance_id, instance in vpc_details['instances'].items():
      if instance_id == bastion_id:
        continue

      if not instance['instance-name']['Value'].startswith(constants_quine.RESOURCE_PREFIX):
        continue

      logger.info(f'Forcing Reboot[{instance["instance-name"]["Value"]}]')
      _run_command([f'ssh {instance["instance-name"]["Value"]} "sudo reboot"'], expected_code=255)
    logger.info(f'Forcing Reboot[{bastion["instance-name"]["Value"]}]')
    _run_command([f'ssh {bastion["instance-name"]["Value"]} "sudo reboot"'], expected_code=255)

  delta: timedelta = timedelta(minutes=5)
  poll_start: datetime = datetime.utcnow()
  while (poll_start + delta) > datetime.utcnow():
    for vpc, vpc_details in cluster_info['vpcs'].items():
      online: typing.List[bool] = []
      for instance in vpc_details['instances'].values():
        try:
          _run_command([f'ssh {instance["instance-name"]["Value"]} ls'])
        except Exception as err:
          online.append(False)
          break

        else:
          online.append(True)


    logger.info(f'Waiting for VPC AppServer Reboot[{vpc}]')
    logger.info(f'Instances[{len(online)}], Online[{len([o for o in online if o])}]')
    if all(online):
      break

    time.sleep(3)
  else:
    logger.info(f'Force Reboot Poll Expired')
    raise NotImplementedError

async def generate_ssh_configs(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any], cluster_info: typing.Dict[str, typing.Any]) -> None:
  async def _remove_ssh_config_entry(instance: typing.Dict[str, typing.Any]) -> None:
    _strip = ' '
    _split = '\n'
    _skip: bool = False
    _result: str = ''

    template_model: str = [line for line in instance['ssh-config'].split(_split) if line.strip(_strip)]
    template_comp: str = [line.strip(_strip) for line in instance['ssh-config'].split(_split) if line.strip(_strip)]
    head: str = template_comp[0]
    tail: str = template_comp[-1]
    assert len(template_model) == len(template_comp)
    for idx, line_comp in enumerate(template_comp):
      assert line_comp in template_model[idx]

    data_model: typing.List[str] = []
    data_comp: typing.List[str] = []
    if os.path.exists(constants_quine.SSH_CONFIG_PATH):
      async with aiofiles.open(constants_quine.SSH_CONFIG_PATH, 'rb') as stream:
        data = (await stream.read()).decode(constants_quine.ENCODING)
        data_model = [line for line in data.split(_split) if line.strip(_strip)]
        data_comp = [line.strip(_strip) for line in data.split(_split) if line.strip(_strip)]
        # Because we're altering a file that the User may touch, we want to make sure that the lines we alter are accurate.
        assert len(data_model) == len(data_comp)
        for idx, line_comp in enumerate(data_comp):
          assert line_comp in data_model[idx]

    result_model: typing.List[str] = []
    for idx, line_comp in enumerate(data_comp):
      if line_comp == tail:
        _skip = False

      elif line_comp == head:
        _skip = True
        continue

      elif _skip:
        continue

      elif line_comp == constants_quine.SSH_TAG_LINE:
        continue

      else:
        result_model.append(data_model[idx])

    async with aiofiles.open(constants_quine.SSH_CONFIG_PATH, 'wb') as stream:
      result = '\n'.join(result_model)
      await stream.write(result.encode(constants_quine.ENCODING))

  async def _render_ssh_config(instance: typing.Dict[str, typing.Any]) -> None:
    found: bool = False
    if os.path.exists(constants_quine.SSH_CONFIG_PATH):
      async with aiofiles.open(constants_quine.SSH_CONFIG_PATH, 'rb') as stream:
        data = (await stream.read()).decode(constants_quine.ENCODING)
        found = instance['ssh-config'] in data

    if found is False:
      async with aiofiles.open(constants_quine.SSH_CONFIG_PATH, 'ab') as stream:
        # await stream.write(b'\n')
        # await stream.write(constants_quine.SSH_TAG_LINE.encode(constants_quine.ENCODING))
        await stream.write(instance['ssh-config'].encode(constants_quine.ENCODING))

  def _build_appserver_config(bastion: typing.Dict[str, typing.Any], instance: typing.Dict[str, typing.Any]) -> None:
    instance['ssh-config'] = f"""
Host {instance["instance-name"]["Value"]}
  HostName {instance["private-ip-address"]}
  Port {constants_quine.EXPECTED_PORT}
  ConnectTimeout {constants_quine.SSH_TIMEOUT}
  User {constants_quine.EXPECTED_USERNAME}
  IdentityFile {constants_quine.ENV_VARS["AWS_KEY_PATH"]}
  ProxyCommand ssh -i {constants_quine.ENV_VARS["AWS_KEY_PATH"]} ubuntu@{bastion["public-ip-address"]} -W %h:%p # {instance["private-ip-address"]}
"""
  
  def _build_bastion_config(bastion: typing.Dict[str, typing.Any]) -> None:
    bastion['ssh-config'] = f"""
Host {bastion["instance-name"]["Value"]}
  HostName {bastion["public-ip-address"]}
  Port {constants_quine.EXPECTED_PORT}
  ConnectTimeout {constants_quine.SSH_TIMEOUT}
  User {constants_quine.EXPECTED_USERNAME}
  IdentityFile {constants_quine.ENV_VARS["AWS_KEY_PATH"]}
"""
    
  for vpc, vpc_details in cluster_info['vpcs'].items():
    bastion_id, bastion = [(_id, instance) for _id, instance in vpc_details['instances'].items() if instance['instance-name']['Value'].endswith('bastion')][0]
    _build_bastion_config(bastion)
    logger.info(f'Updating SSHConfig for Bastion[{bastion["instance-name"]}]')
    await _remove_ssh_config_entry(bastion)
    await _render_ssh_config(bastion)
    for instance_id, instance in vpc_details['instances'].items():
      if instance_id == bastion_id:
        continue

      _build_appserver_config(bastion, instance)
      logger.info(f'Updating SSHConfig for AppServer[{instance["instance-name"]}]')
      await _remove_ssh_config_entry(instance)
      await _render_ssh_config(instance)

async def generate_ssh_knownhosts(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any], cluster_info: typing.Dict[str, typing.Any]) -> None:
  async def _merge_files(primary_path: str, additional_info_path: str) -> None:
    additional: typing.List[str] = []
    async with aiofiles.open(primary_path, 'rb') as primary:
      primary_datum = [line for line in (await primary.read()).decode(constants_quine.ENCODING).split('\n') if line]
      async with aiofiles.open(additional_info_path, 'rb') as addon:
        for line in [line for line in (await addon.read()).decode(constants_quine.ENCODING).split('\n') if line]:
          if not line in primary_datum:
            additional.append(line)
   
    async with aiofiles.open(primary_path, 'ab') as primary:
      for line in additional:
        await primary.write(line.encode(constants_quine.ENCODING))
        await primary.write(b'\n')

  for vpc, vpc_details in cluster_info['vpcs'].items():
    bastion_id, bastion = [(_id, instance) for _id, instance in vpc_details['instances'].items() if instance['instance-name']['Value'].endswith('bastion')][0]
    key_scan_path: str = '/tmp/keys.txt'
    cmds = [
      f'/usr/bin/ssh-keygen -R {bastion["public-ip-address"]}',
      f'/usr/bin/ssh-keyscan -H {bastion["public-ip-address"]} >> {constants_quine.SSH_KNOWN_HOSTS_PATH}',
    ]
    results = _run_command(cmds)
    results = _run_command([
      f'ssh {bastion["instance-name"]["Value"]} rm -f {key_scan_path} || true',
      f'ssh {bastion["instance-name"]["Value"]} touch {key_scan_path}',
    ])
    for instance_id, instance in vpc_details['instances'].items():
      if instance_id == bastion_id:
        continue

      while True:
        try:
          results = _run_command([
            f'/usr/bin/ssh-keygen -R {instance["private-ip-address"]}',
            f'ssh {bastion["instance-name"]["Value"]} "/usr/bin/ssh-keyscan -H {instance["private-ip-address"]} >> {key_scan_path}"',
          ])
        except SSHConnectTimeout as err:
          logger.info('Unable to connect to AppServer[{instance["instance-name"]}]. Stalling 1 second.')
          await asyncio.sleep(1)
        else:
          break

    results = _run_command([
      f'scp {bastion["instance-name"]["Value"]}:{key_scan_path} {key_scan_path}',
    ])
    await _merge_files(constants_quine.SSH_KNOWN_HOSTS_PATH, key_scan_path)

async def install_ssh_keys(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any], cluster_info: typing.Dict[str, typing.Any]) -> None:
  for vpc, vpc_details in cluster_info['vpcs'].items():
    bastion_id, bastion = [(_id, instance) for _id, instance in vpc_details['instances'].items() if instance['instance-name']['Value'].endswith('bastion')][0]

async def install_software_replicator(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any], cluster_info: typing.Dict[str, typing.Any]) -> None:
  """
  A Peer to Peer syncronization package that will make sure the latest version of software is installed on every server.
  """
  for vpc, vpc_details in cluster_info['vpcs'].items():
    bastion_id, bastion = [(_id, instance) for _id, instance in vpc_details['instances'].items() if instance['instance-name']['Value'].endswith('bastion')][0]

async def install_docker_runtime(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any], cluster_info: typing.Dict[str, typing.Any]) -> None:
  docker_script = await _render_script('quine/templates/install-docker.sh', {
    'GROUP_NAME': 'docker',
    'USERNAME': constants_quine.EXPECTED_USERNAME
  })
  await _run_scripts_on_bastion(cluster_info, [docker_script])
  await _run_scripts_on_appservers(cluster_info, [docker_script])

async def _render_files_for_bastion(cluster_info: typing.Dict[str, typing.Any], start_dir: str, render_dir: str) -> None:
  for vpc, vpc_details in cluster_info['vpcs'].items():
    bastion_id, bastion = [(_id, instance) for _id, instance in vpc_details['instances'].items() if instance['instance-name']['Value'].endswith('bastion')][0]
    if not os.path.exists(start_dir):
      raise IOError(f'Missing DIR[{start_dir}]')

    if not os.path.exists(render_dir):
      os.makedirs(render_dir)

    async def _render_directory(local_dir: str) -> None:
      for root, _dirs, _files in os.walk(local_dir):
        for _file in _files:
          filepath = os.path.join(root, _file)
          async with aiofiles.open(filepath, 'rb') as input_stream:
            logger.info(f'Reading File[{filepath}]')
            template = JINJA2_ENV.from_string(
                (await input_stream.read()).decode(constants_quine.ENCODING))

            render_path = os.path.join(render_dir, root.split(start_dir)[1].strip('/'), _file)
            render_path_dir = os.path.dirname(render_path)
            if not os.path.exists(render_path_dir):
              os.makedirs(render_path_dir)

            async with aiofiles.open(render_path, 'wb') as output:
              logger.info(f'Writing File[{render_path}]')
              await output.write(template.render({
                'bastion': bastion,
                'DNS_NAME': constants_quine.DNS_NAME,
              }).encode(constants_quine.ENCODING))

    await _render_directory(start_dir)

async def _sync_files_to_bastion(cluster_info: typing.Dict[str, typing.Any], local_dir: str, remote_dir:str) -> None:
  for vpc, vpc_details in cluster_info['vpcs'].items():
    bastion_id, bastion = [(_id, instance) for _id, instance in vpc_details['instances'].items() if instance['instance-name']['Value'].endswith('bastion')][0]
    if not os.path.exists(local_dir):
      raise IOError(f'Missing DIR[{local_dir}]')

    _run_command([
      f'ssh {bastion["instance-name"]["Value"]} "mkdir -p {remote_dir}"',
      f'rsync -avp {local_dir} {bastion["instance-name"]["Value"]}:{remote_dir}',
    ])

async def install_docker_registry(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any], cluster_info: typing.Dict[str, typing.Any]) -> None:
  logger.warn('Incomplete Logic, should template the files for DNS_NAME')
  registry_scripts = [
    'cd /home/ubuntu/bastion-files && docker-compose -f docker-compose.yml down',
    'cd /home/ubuntu/bastion-files && docker-compose -f docker-compose.yml up -d',
  ]
  await _render_files_for_bastion(cluster_info, 'quine/templates/bastion-files', 'build-tools/outputs/quine/templates/bastion-files')
  await _sync_files_to_bastion(cluster_info, 'build-tools/outputs/quine/templates/bastion-files', '/home/ubuntu')
  await _run_scripts_on_bastion(cluster_info, registry_scripts)

