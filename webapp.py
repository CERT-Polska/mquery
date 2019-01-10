import json
import logging
import os
import random
import string
import time

from flask import Flask, request, redirect, url_for, Response, jsonify, send_file, send_from_directory
from itsdangerous import BadSignature
from werkzeug.exceptions import Forbidden, NotFound
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


@app.route('/saved-rules')
def get_saved_rules():
    named_queries = redis.keys('named_query:*')
    saved_rules = []
    for query in named_queries:
        qid = query.split(':')[1]
        name = redis.get(query)
        saved_rules.append({'id': qid, 'name': name})
    return jsonify({"saved_rules": sorted(saved_rules, key=lambda x: x['name'])})


@app.route('/admin/index', methods=['POST'])
def admin_index():
    path = request.get_json()['path']

    if path not in config.INDEXABLE_PATHS:
        return jsonify({"error": "location denied"}), 403

    tasks = db.status().get('result', {}).get('tasks', [])

    if any(task['request'].startswith('index ') for task in tasks):
        return jsonify({"error": "index already queued"}), 400

    redis.rpush('queue-index', path)
    return jsonify({"status": "queued"})


@app.route('/download')
def download():
    job_id = request.args['job_id']
    file_path = request.args['file_path']

    if not redis.sismember('matches:' + job_id, file_path):
        raise NotFound('No such file in result set.')

    attach_name, ext = os.path.splitext(os.path.basename(file_path))
    ext = ext + '_'

    return send_file(file_path, as_attachment=True, attachment_filename=attach_name + ext)


@app.route('/query', methods=['POST'])
def query():
    req = request.get_json()

    raw_yara = req['rawYara']

    try:
        rules = plyara.Plyara().parse_string(raw_yara)
    except Exception as e:
        return jsonify({'error': 'PLYara failed (not my fault): ' + str(e)}), 400

    if len(rules) > 1:
        return jsonify({'error': 'More than one rule specified!'}), 400

    rule_name = rules[0].get('rule_name')

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


def generate_match_objs(hash, matches):
    meta_set = redis.smembers("meta:{}".format(hash))
    signed_matches = []

    meta_dict = {}

    for m in meta_set:
        m_obj = json.loads(m)
        meta_dict[m_obj['file']] = m_obj['meta']

    for m in matches:
        obj = {
            "matched_path": m,
            "metadata_available": False,
            "metadata": {}
        }

        if m in meta_dict:
            obj.update({
                "metadata_available": True,
                "metadata": meta_dict[m]
            })

        signed_matches.append(obj)

    return signed_matches


@app.route('/status/<hash>')
def status(hash):
    fetch_matches = not request.args.get('skipMatches', False)

    if fetch_matches:
        matches = redis.smembers('matches:' + hash)
    else:
        matches = []

    job = redis.hgetall('job:' + hash)
    error = job.get('error')

    fp_count = redis.scard('false_positives:{}'.format(hash))
    tp_count = redis.scard('meta:{}'.format(hash))

    if not tp_count:
        tp_count = 0

    return jsonify({
        "files_processed": int(tp_count) + int(fp_count),
        "matches": generate_match_objs(hash, matches),
        "job": job,
        "error": error
    })


@app.route('/save', methods=['POST'])
def save():
    qhash = request.form.get('hash')
    rule_name = request.form.get('rule_name')
    redis.set('named_query:{}'.format(qhash), rule_name)
    return redirect(url_for('query_by_hash', qhash=qhash))


@app.route('/job/<job_id>', methods=['DELETE'])
def admin_cancel(job_id):
    redis.hmset('job:' + job_id, {
        'status': 'cancelled',
    })

    return jsonify({"status": "ok"})


@app.route('/status/jobs')
def status_jobs():
    jobs = redis.keys('job:*')
    jobs = sorted([dict({'id': job[4:]}, **redis.hgetall(job)) for job in jobs],
                  key=lambda o: o.get('submitted'), reverse=True)

    return jsonify({"jobs": jobs})


@app.route('/status/backend')
def status_backend():
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


@app.route('/admin/indexable_paths')
def admin_indexable_paths():
    return jsonify({
        "indexable_paths": config.INDEXABLE_PATHS
    })


@app.route('/query/<path:path>')
def serve_index(path):
    return send_file('mqueryfront/build/index.html')


@app.route('/admin')
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
