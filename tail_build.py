import concurrent
import docker
import logging
import os
import typing

from docker import errors as docker_errors

from quine import tail_constants as constants_quine, tail_deployment as deployment_quine

logger = logging.getLogger(__name__)

def _build_dockerfile(dockerfile_dir: str, build_filename: str, build_name: str) -> typing.Tuple[docker.DockerClient, str]:
  logger.info(f'Building Docker Image[{build_name}]')
  client = docker.DockerClient()
  dockerfile_path = os.path.join(dockerfile_dir, build_filename)
  if not os.path.exists(dockerfile_path):
    raise IOError(f'Missing Dockerfile[{dockerfile_path}]')

  return client, dockerfile_path


async def build(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  client, dockerfile_path = _build_dockerfile(payload['options'].docker_file, 'build.Dockerfile', constants_quine.CLUSTER_BUILD)
  docker_tag = f'bastion.{constants_quine.DNS_NAME}/{constants_quine.CLUSTER_BUILD}'
  max_attemps = 0
  while True:
    try:
      docker_image, build_log = client.images.build(
          nocache=True,
          path=os.getcwd(),
          dockerfile=dockerfile_path,
          tag=constants_quine.CLUSTER_BUILD)
    except docker_errors.BuildError as err:
      logging.info(f'Build Attempt Failed[{docker_tag}]')
      logging.error(err)
      max_attemps = max_attemps + 1
      if max_attemps > 5:
        import sys; sys.exit(1)

    else:
      break

  docker_image.tag(docker_tag, constants_quine.VERSION)


async def ops(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  client, dockerfile_path = _build_dockerfile(payload['options'].docker_file, 'ops.Dockerfile', constants_quine.CLUSTER_OPS)
  build_args = {key: value for key, value in constants_quine.ENV_VARS.items()}
  build_args['PSQL_POOL'] = os.environ['PSQL_POOL']
  build_args['REDIS_POOL'] = os.environ['REDIS_POOL']
  build_args['SENTRY_KEY'] = os.environ['SENTRY_KEY']
  build_args['PAYPAL_URI_BASE'] = os.environ['PAYPAL_URI_BASE']
  max_attemps = 0
  docker_tag = f'bastion.{constants_quine.DNS_NAME}/{constants_quine.CLUSTER_OPS}'
  while True:
    try:
      docker_image, build_log = client.images.build(
          nocache=True,
          path=os.getcwd(),
          dockerfile=dockerfile_path,
          tag=constants_quine.CLUSTER_OPS,
          buildargs=build_args)
    except docker_errors.BuildError as err:
      logging.info(f'Build Attempt Failed[{docker_tag}]')
      logging.error(err)
      max_attemps = max_attemps + 1
      if max_attemps > 5:
        import sys; sys.exit(1)

    else:
      break

  docker_image.tag(docker_tag, constants_quine.VERSION)


async def webservice(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  client, dockerfile_path = _build_dockerfile(payload['options'].docker_file, 'webservice.Dockerfile', constants_quine.CLUSTER_WEBSERVICE)
  docker_tag = f'bastion.{constants_quine.DNS_NAME}/{constants_quine.CLUSTER_WEBSERVICE}'
  max_attemps = 0
  while True:
    try:
      docker_image, build_log = client.images.build(
          nocache=True,
          path=os.getcwd(),
          dockerfile=dockerfile_path,
          tag=constants_quine.CLUSTER_WEBSERVICE)

    except docker_errors.BuildError as err:
      logging.info(f'Build Attempt Failed[{docker_tag}]')
      logging.error(err)
      max_attemps = max_attemps + 1
      if max_attemps > 5:
        import sys; sys.exit(1)

    else:
      break

  docker_image.tag(docker_tag, constants_quine.VERSION)


