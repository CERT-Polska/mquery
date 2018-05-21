import hashlib
from os import walk, path
import sys
from redis import StrictRedis
redis = StrictRedis()


def register(filename):
    with open(filename, 'rb') as fobj:
        raw_yara = fobj.read()

    raw_yara = raw_yara.replace('\r\n', '\n')
    raw_yara = raw_yara.replace('\n', '\r\n')  # normalize all to \r\n

    hash = hashlib.sha256(raw_yara).hexdigest()
    name = path.basename(filename)
    name = name.split('.')[0]
    print 'populating', name, hash

    redis.set('named_query:' + hash, name)
    redis.set('query:' + hash, raw_yara)


def main():
    root = sys.argv[1]
    for (dirpath, dirnames, filenames) in walk(root):
        for f in filenames:
            if f.endswith('.yar'):
                fname = dirpath + '/' + f
                register(fname)
                

if __name__ == '__main__':
    main()
