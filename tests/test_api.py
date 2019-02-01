import logging
import time

import pytest
import requests


@pytest.fixture(scope="session", autouse=True)
def check_operational(request):
    for attempt in range(300):
        try:
            res = requests.get('http://web/status/backend', timeout=1)
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

    res = requests.post('http://web/api/admin/index', json={'path': '/mnt/samples'})
    res.raise_for_status()

    for _ in range(60):
        res = requests.get('http://web/api/backend', timeout=1)
        res.raise_for_status()

        # indexing process finished
        if len(res.json()['tasks']) <= 1:
            break

        time.sleep(1)

    test_yara = '''
rule nymaim {
    strings:
        $check = "lolwtf123"
    condition:
        any of them
}    
'''

    res = requests.post('http://web/api/query', json={'method': 'query', 'raw_yara': test_yara})
    res.raise_for_status()

    query_hash = res.json()['query_hash']
    
    while True:
        res = requests.get('http://web/api/matches/{}?offset=0&limit=50'.format(query_hash))
        if res.json()['job']['status'] == 'done':
            break

    m = res.json()['matches']
    assert len(m) == 1
    assert m[0]['file'] == '/mnt/samples/foo.txt'
