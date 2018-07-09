import hashlib
import os
import re

from flask import Flask, render_template, send_from_directory, request, redirect, url_for, Response, jsonify, send_file
from itsdangerous import BadSignature
from werkzeug.exceptions import Forbidden
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


def get_saved_rules():
    named_queries = redis.keys('named_query:*')
    saved_rules = []
    for query in named_queries:
        qid = query.split(':')[1]
        name = redis.get(query)
        saved_rules.append({'id': qid, 'name': name})
    return sorted(saved_rules, key=lambda x: x['name'])


def get_analysis_meta(dump_fname):
    blank = {'analysis_id': None, 'binary_hash': None}
    m = re.search(r'analyses/([0-9]+)/', dump_fname)

    if not m:
        return blank

    analysis_id = int(m.group(1))

    try:
        target = os.readlink('/share/storage/analyses/{}/binary'.format(analysis_id))
    except OSError:
        return blank

    return {
        'analysis_id': analysis_id,
        'binary_hash': target.split('/')[-1],
    }


@app.route('/')
def index():
    return render_template('index.html', saved_rules=get_saved_rules())


@app.route('/admin/index', methods=['POST'])
def admin_index():
    path = request.form['path']

    if path not in config.INDEXABLE_PATHS:
        return redirect(url_for('admin', info='index_denied'))

    tasks = db.status().get('result', {}).get('tasks', [])

    if any(task['request'].startswith('index ') for task in tasks):
        return redirect(url_for('admin', info='index_already_queued'))

    redis.rpush('index-jobs', path)

    return redirect(url_for('admin', info='index_queued'))


@app.route('/sample')
def sample():
    try:
        sample_fname = s.unsign(request.args.get('name'))
    except BadSignature:
        raise Forbidden('Invalid access token. Corrupted URL or unauthorized access.')

    attach_name, ext = os.path.splitext(os.path.basename(sample_fname))

    if ext:
        ext = ext + '_'

    return send_file(sample_fname, as_attachment=True, attachment_filename=attach_name + ext)


@app.route('/query', methods=['POST'])
def query():
    raw_yara = request.form['yara']

    if 'clone' in request.form:
        return render_template('index.html', saved_rules=get_saved_rules(), yara=raw_yara)

    qhash = hashlib.sha256(raw_yara).hexdigest()

    redis.delete('matches:' + qhash, 'false_positives:' + qhash, 'job:' + qhash)

    redis_id = 'query:' + qhash
    if not redis.exists(redis_id):
        redis.set(redis_id, raw_yara)

    job_id = 'job:' + qhash
    if 'query_100' in request.form:
        redis.hmset(job_id, {
            'status': 'new',
            'max_files': 100,
        })
        redis.rpush('jobs', qhash)
    if 'query' in request.form:
        redis.hmset(job_id, {
            'status': 'new',
            'max_files': -1,
        })
        redis.rpush('jobs', qhash)

    debug_mode = 'debug' in request.form
    if debug_mode:
        return redirect(url_for('query_by_hash', qhash=qhash, debug='on'))
    else:
        return redirect(url_for('query_by_hash', qhash=qhash))


def error_page(yara, message):
    return render_template('index.html', yara=yara, errors=message, saved_rules=get_saved_rules())


def generate_match_objs(matches):
    signed_matches = []

    for m in matches:
        obj = {"matched_dump": s.sign(m)}
        obj.update(get_analysis_meta(m))
        signed_matches.append(obj)

    return sorted(signed_matches, key=lambda o: o.get('analysis_id'), reverse=True)


@app.route('/api/status/<hash>')
def status(hash):
    matches = redis.smembers('matches:' + hash)
    false_positives = redis.smembers('false_positives:' + hash)
    job = redis.hgetall('job:' + hash)
    error = job.get('error')

    return jsonify({
        "matches": generate_match_objs(matches),
        "false_positives": list(false_positives),
        "job": job,
        "error": error
    })


@app.route('/api/matches/<hash>')
def matches(hash):
    matches = redis.smembers('matches:' + hash)
    mobjs = generate_match_objs(matches)
    signed_matches = [url_for('sample', name=m["matched_dump"], _external=True)
                      + ' # ' + m["binary_hash"] for m in mobjs]

    return Response('\n'.join(signed_matches), content_type='text/plain')


@app.route('/save', methods=['POST'])
def save():
    qhash = request.form.get('hash')
    rule_name = request.form.get('rule_name')
    redis.set('named_query:{}'.format(qhash), rule_name)
    return redirect(url_for('query_by_hash', qhash=qhash))


@app.route('/query/<qhash>')
def query_by_hash(qhash):
    yara = redis.get('query:' + qhash)

    try:
        rules = plyara.Plyara().parse_string(yara)
    except Exception as e:
        return error_page(yara, 'PLYara failed (not my fault): ' + str(e))

    if len(rules) > 1:
        return error_page(yara, 'More than one rule specified')

    rule_name = rules[0].get('rule_name')

    try:
        parser = YaraParser(rules[0])
        pre_parsed = parser.pre_parse()
        parsed = parser.parse()
    except Exception as e:
        return error_page(yara, 'YaraParser failed (msm\'s fault): ' + str(e))

    matches = redis.smembers('matches:' + qhash)
    false_positives = redis.smembers('false_positives:' + qhash)
    job = redis.hgetall('job:' + qhash)
    debug = 'debug' in request.args

    error = job.get('error')

    body = render_template('index.html',
                           yara=yara,
                           pre_parsed=pre_parsed,
                           parsed=parsed,
                           job=job,
                           matches=matches,
                           errors=error,
                           false_positives=false_positives,
                           debug=debug,
                           saved_rules=get_saved_rules(),
                           qhash=qhash,
                           rule_name=rule_name,
                           repo_url=config.REPO_URL)

    return body


def admin_cancel(job_id):
    redis.hmset('job:' + job_id, {
        'status': 'cancelled',
    })


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        if 'cancel' in request.form:
            admin_cancel(request.form['cancel'])

    jobs = redis.keys('job:*')
    jobs = [dict({'id': job[4:]}, **redis.hgetall(job)) for job in jobs]

    db_alive = True

    try:
        tasks = db.status().get('result', {}).get('tasks', [])
    except Again:
        db_alive = False
        tasks = []

    return render_template('admin.html',
                           jobs=jobs,
                           db_alive=db_alive,
                           tasks=tasks,
                           info=request.args.get('info'),
                           admin_index_paths=config.INDEXABLE_PATHS)


@app.route('/help')
def help():
    return render_template('help.html')


@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)


if __name__ == "__main__":
    app.run()
