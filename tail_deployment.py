import concurrent
import enum
import typing

from quine import tail_remoting as remoting_quine, tail_constants as constants_quine

KEYWORDS = ['container id', 'image id', 'container', 'image']

class DockerType(enum.Enum):
  CONTAINER = 'container'
  IMAGE = 'image'

def _parse_docker_results(results: typing.List[typing.Tuple[int, bytes]], docker_type: DockerType) -> typing.List[str]:
  lines = [line.strip() for line in results[0][1].decode(constants_quine.ENCODING).split('\n') if line]
  if docker_type is DockerType.CONTAINER:
    return [entry.split()[0] for entry in lines if not entry.split()[0].lower() in KEYWORDS]

  elif docker_type is DockerType.IMAGE:
    return [entry.split()[2] for entry in lines if not entry.split()[2].lower() in KEYWORDS]

  else:
    raise NotImplementedError(docker_type)

async def clear_containers(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  cluster = remoting_quine.Cluster(payload)
  for instance_id, results in cluster.run_commands_on_appservers(['docker ps -a']).items():
    container_ids = _parse_docker_results(results, DockerType.CONTAINER)
    if container_ids:
      cluster.run_commands_on_appservers([
        f'docker stop {" ".join(container_ids)}',
        f'docker rm {" ".join(container_ids)}',
      ])


async def clear_images(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  cluster = remoting_quine.Cluster(payload)
  for instance_id, results in cluster.run_commands_on_appservers(['docker image list']).items():
    image_ids = _parse_docker_results(results, DockerType.IMAGE)
    if image_ids:
      cluster.run_commands_on_appservers([f'docker rmi {" ".join(image_ids)}'])

async def sync_containers(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  cluster = remoting_quine.Cluster(payload)
  cluster.run_commands_on_appservers([
    f'docker pull bastion.{constants_quine.DNS_NAME}/{constants_quine.CLUSTER_WEBSERVICE}:{constants_quine.VERSION}',
    f'docker pull bastion.{constants_quine.DNS_NAME}/{constants_quine.CLUSTER_OPS}:{constants_quine.VERSION}'
  ])

async def deploy_ops(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  # Deestry ops?
  cluster = remoting_quine.Cluster(payload)
  cluster.run_commands_on_appservers([
    f'docker run bastion.{constants_quine.DNS_NAME}/{constants_quine.CLUSTER_OPS}:{constants_quine.VERSION}',
  ])
    
async def deploy(executor: concurrent.futures.ThreadPoolExecutor, payload: typing.Dict[str, typing.Any]) -> None:
  cluster = remoting_quine.Cluster(payload)
  docker_tag = f'bastion.{constants_quine.DNS_NAME}/{constants_quine.CLUSTER_WEBSERVICE}'
  container_name = f'{constants_quine.CLUSTER_WEBSERVICE}'
  cluster.run_commands_on_appservers([
    f'docker stop {constants_quine.CLUSTER_WEBSERVICE}',
    f'docker rm {constants_quine.CLUSTER_WEBSERVICE}',
  ], expected_code=1)
  www_port = constants_quine.ENV_VARS['WWW_PORT']
  cluster.run_commands_on_appservers([
    f'docker run -p {www_port}:{www_port} -d --restart=always --name={constants_quine.CLUSTER_WEBSERVICE} {docker_tag}:{constants_quine.VERSION}',
  ])

