import binascii
from addrgen import gen_eckey, get_addr

class Address(object):

    @classmethod
    def from_secret(cls, secret):
        if len(secret) == 64:
            secret = binascii.unhexlify(secret)
        if len(secret) == 32:
            pub, priv = get_addr(gen_eckey(secret = secret))
            return Address(pub, priv)
        else:
            raise Exception("Secret has to be exactly 32 bytes")

    @classmethod
    def from_passphrase(cls, passphrase):
        pub, priv = get_addr(gen_eckey(passphrase = passphrase))
        return Address(pub, priv)

    @classmethod
    def from_seed(cls, seed, idx):
        raise NotImplementedError

    def __init__(self, pub = None, priv = None):
        if pub == None or priv == None:
            pub, priv = get_addr(gen_eckey())
        self.pub = pub
        self.priv = priv
