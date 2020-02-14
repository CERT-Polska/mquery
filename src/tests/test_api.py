import json
import logging
import time

import zmq
import pytest
import requests


# sanity check

@pytest.fixture(scope="session", autouse=True)
def check_operational(request):
    for attempt in range(300):
        try:
            res = requests.get('http://web:5000/api/backend', timeout=1)
            res.raise_for_status()

            if res.json()['db_alive']:
                return
            else:
                logging.getLogger().info('Database backend is not active.')
        except requests.exceptions.ConnectionError:
            if attempt % 15 == 0:
                logging.getLogger().info('Connection to mquery failed, retrying in a moment...')
        except requests.exceptions.RequestException:
            if attempt % 15 == 0:
                logging.getLogger().info('Request to mquery failed, retrying...')

        time.sleep(1)


def test_sth():
    with open('/mnt/samples/foo.txt', 'w') as f:
        f.write('lolwtf123')

    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.connect('tcp://ursadb:9281')

    socket.send_string('index "/mnt/samples" with [gram3, text4, hash4, wide8];')
    assert json.loads(socket.recv_string()).get('result').get('status') == 'ok'

    test_yara = '''
rule nymaim {
    strings:
        $check = "lolwtf123"
    condition:
        any of them
}    
'''

    res = requests.post('http://web:5000/api/query', json={'method': 'query', 'raw_yara': test_yara})
    res.raise_for_status()

    query_hash = res.json()['query_hash']
    
    while True:
        res = requests.get('http://web:5000/api/matches/{}?offset=0&limit=50'.format(query_hash))
        if res.json()['job']['status'] == 'done':
            break

    m = res.json()['matches']
    assert len(m) == 1
    assert m[0]['file'] == '/mnt/samples/foo.txt'
