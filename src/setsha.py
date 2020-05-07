import hashlib
 
def set_sha(filename):
    sha256_hash = hashlib.sha256()
    with open(filename,"rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    return {
        "sha256": {
            "display_text": sha256_hash.hexdigest(),
            "hidden": True
        }
    }