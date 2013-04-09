import hashlib

def shash(s):
    return hashlib.sha256(s).digest()

def dhash(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def rhash(s):
    try:
        md = hashlib.new('ripemd160')
        md.update(hashlib.sha256(s).digest())
        return md.digest()
    except:
        import ripemd
        md = ripemd.new(hashlib.sha256(s).digest())
        return md.digest()
