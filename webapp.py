import json
import logging
import os
import random
import string
import time

from flask import Flask, request, redirect, url_for, jsonify, send_file, send_from_directory
from werkzeug.exceptions import NotFound
from zmq import Again

from lib.ursadb import UrsaDb
from lib.yaraparse import YaraParser
import plyara

from util import make_redis, make_serializer
import config

redis = make_redis()
app = Flask(__name__)
s = make_serializer()
db = UrsaDb(config.BACKEND)


@app.after_request
def add_header(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'cache-control,x-requested-with,content-type,authorization'
    response.headers['Access-Control-Allow-Methods'] = 'POST, PUT, GET, OPTIONS, DELETE'
    return response


@app.route('/api/admin/index', methods=['POST'])
def admin_index():
    path = request.get_json()['path']

    if path not in config.INDEXABLE_PATHS:
        return jsonify({"error": "location denied"}), 403

    tasks = db.status().get('result', {}).get('tasks', [])

    if any(task['request'].startswith('index ') for task in tasks):
        return jsonify({"error": "index already queued"}), 400

    redis.rpush('queue-index', path)
    return jsonify({"status": "queued"})


@app.route('/api/download')
def download():
    job_id = request.args['job_id']
    file_path = request.args['file_path']
    ordinal = request.args['ordinal']

    file_list = redis.lrange('meta:' + job_id, ordinal, ordinal)

    if not file_list or file_path != json.loads(file_list[0])['file']:
        raise NotFound('No such file in result set.')

    attach_name, ext = os.path.splitext(os.path.basename(file_path))
    ext = ext + '_'

    return send_file(file_path, as_attachment=True, attachment_filename=attach_name + ext)


@app.route('/api/query', methods=['POST'])
def query():
    req = request.get_json()

    raw_yara = req['rawYara']

    try:
        rules = plyara.Plyara().parse_string(raw_yara)
    except Exception as e:
        return jsonify({'error': 'PLYara failed (not my fault): ' + str(e)}), 400

    if not rules:
        return jsonify({'error': 'No rule was specified.'}), 400

    if len(rules) > 1:
        return jsonify({'error': 'More than one rule specified!'}), 400

    rule_name = rules[0].get('rule_name')
    rule_author = rules[0].get('metadata', {}).get('author', '')

    try:
        parser = YaraParser(rules[0])
        pre_parsed = parser.pre_parse()
        parsed = parser.parse()
    except Exception as e:
        logging.exception('YaraParser failed')
        return jsonify({'error': 'YaraParser failed (msm\'s fault): {}'.format(str(e))}), 400

    if req['method'] == 'parse':
        return jsonify({'rule_name': rule_name, "parsed": parsed})

    job_hash = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(12))

    job_obj = {
        'status': 'new',
        'max_files': -1,
        'rule_name': rule_name,
        'rule_author': rule_author,
        'parsed': parsed,
        'pre_parsed': pre_parsed,
        'raw_yara': raw_yara,
        'submitted': int(time.time())
    }

    if req['method'] == 'query_100':
        job_obj.update({'max_files': 100})

    redis.hmset('job:' + job_hash, job_obj)
    redis.rpush('queue-search', job_hash)

    return jsonify({'query_hash': job_hash})


@app.route('/api/matches/<hash>')
def matches(hash):
    offset = int(request.args['offset'])
    limit = int(request.args['limit'])

    p = redis.pipeline(transaction=False)
    p.hgetall('job:' + hash)
    p.lrange('meta:' + hash, offset, offset + limit - 1)
    job, meta = p.execute()

    return jsonify({
        "job": job,
        "matches": [json.loads(m) for m in meta]
    })


@app.route('/api/job/<hash>')
def job_info(hash):
    return jsonify(redis.hgetall('job:' + hash))


@app.route('/api/job/<job_id>', methods=['DELETE'])
def job_cancel(job_id):
    redis.hmset('job:' + job_id, {
        'status': 'cancelled',
    })

    return jsonify({"status": "ok"})


@app.route('/api/job')
def job_statuses():
    jobs = redis.keys('job:*')
    jobs = sorted([dict({'id': job[4:]}, **redis.hgetall(job)) for job in jobs],
                  key=lambda o: o.get('submitted'), reverse=True)

    return jsonify({"jobs": jobs})


@app.route('/api/backend')
def backend_status():
    db_alive = True

    try:
        tasks = db.status().get('result', {}).get('tasks', [])
    except Again:
        db_alive = False
        tasks = []

    return jsonify({
        "db_alive": db_alive,
        "tasks": tasks,
    })


@app.route('/api/backend/datasets')
def backend_status_datasets():
    db_alive = True

    try:
        datasets = db.topology().get('result', {}).get('datasets', [])
    except Again:
        db_alive = False
        datasets = []

    return jsonify({
        "db_alive": db_alive,
        "datasets": datasets
    })


@app.route('/api/indexable_paths')
def admin_indexable_paths():
    return jsonify({
        "indexable_paths": config.INDEXABLE_PATHS
    })


@app.route('/query/<path:path>')
def serve_index(path):
    return send_file('mqueryfront/build/index.html')


@app.route('/recent')
@app.route('/status')
@app.route('/help')
@app.route('/query')
def serve_index_sub():
    return send_file('mqueryfront/build/index.html')


@app.route('/', defaults={'path': 'index.html'})
@app.route('/favicon.ico', defaults={'path': 'favicon.ico'})
@app.route('/manifest.json', defaults={'path': 'manifest.json'})
def serve_root(path):
    return send_from_directory('mqueryfront/build', path)


if __name__ == "__main__":
    app.run()
