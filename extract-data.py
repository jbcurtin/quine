# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import boto3
import json
import os
import shutil
import sys

from dynamodb_json import json_util as dynamodb_json

if os.environ.get('LOCAL_DB', None) == 'no':
  endpoint_url = None
else:
  endpoint_url = 'http://localhost:8000/'


try:
  table_name = sys.argv[1]
except IndexError:
  table_name = 'debug-table'

json_indent = 4
output_dir = os.path.join(os.getcwd(), 'build-tools', 'output', 'tables', table_name)
dynamodb = boto3.client('dynamodb', endpoint_url=endpoint_url)

if os.path.exists(output_dir):
  shutil.rmtree(output_dir)

table_names = []
for page in dynamodb.get_paginator('list_tables').paginate():
  table_names.extend(page['TableNames'])

if not table_name in table_names:
  raise NotImplementedError("TableNotFound[%s], available tables[%s]." % (table_name, ', '.join(table_names)))


os.makedirs(output_dir)
print("Extracting from %s" % table_name)
for page in dynamodb.get_paginator('scan').paginate(TableName=table_name):
  for item in page['Items']:
    item = dynamodb_json.loads(item)
    item_path = os.path.join(output_dir, ''.join([item['identity'], '.json']))  
    with open(item_path, 'w') as stream:
      stream.write(json.dumps(item, indent=json_indent))

