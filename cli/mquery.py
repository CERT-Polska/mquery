#!/usr/bin/python3
import argparse
import json
import os
import sys
import time
import urllib3

import requests
from tabulate import tabulate
from tqdm import tqdm

MQUERY_SSL_VERIFY = os.environ.get('MQUERY_SSL_VERIFY', '1') == '1'

if not MQUERY_SSL_VERIFY:
    urllib3.disable_warnings()

try:
    MQUERY_SERVER = os.environ['MQUERY_SERVER']
except KeyError:
    sys.stderr.write('Please set MQUERY_SERVER env variable\n')
    sys.stderr.flush()
    sys.exit(1)

parser = argparse.ArgumentParser(description='')
parser.add_argument('yara_file', help='Yara rule to be queried')
parser.add_argument('result_file', nargs='?', default='/tmp/mquery-last-result.json', help='output file')

args = parser.parse_args()


def print_matches(results):
    row = []

    for r in results:
        file = r['file']
        meta = ', '.join(filter(lambda o: o, list(map(lambda o: r['meta'][o].get('display_text'), r['meta'].keys()))))
        row.append([file, meta])

    print(tabulate(row))


with open(args.yara_file, 'rb') as f:
    yara_rule = f.read()

res = requests.post(MQUERY_SERVER + '/api/query', json={'method': 'query', 'raw_yara': yara_rule.decode('utf-8')}, verify=MQUERY_SSL_VERIFY)
out = res.json()

if 'error' in out:
    print(out['error'])
    sys.exit(1)

query_hash = res.json()['query_hash']
out = {"job": {"status": "processing"}, "matches": []}
last_reported = 0
offset = 0

with tqdm(total=0) as pbar:
    with open(args.result_file, 'w') as f:
      while out['job']['status'] not in ['cancelled', 'failed', 'done'] or out['matches']:
        if out:
            time.sleep(1.0)

        res = requests.get(MQUERY_SERVER + '/api/matches/{}?offset={}&limit=50'.format(query_hash, offset), verify=MQUERY_SSL_VERIFY)
        out = res.json()

        diff = int(out['job'].get('files_processed', 0)) - last_reported
        pbar.total = int(out['job'].get('total_files', 0))
        pbar.update(diff)
        last_reported += diff
        pbar.set_description(out['job']['status'])

        if out['matches']:
            offset += len(out['matches'])
            print_matches(out['matches'])
            for match in out['matches']:
                f.write(json.dumps(match) + "\n")

            f.flush()

if out['job']['status'] == 'done':
    sys.exit(0)
else:
    sys.stderr.write(out['job']['error'] + "\n")
    sys.exit(1)
