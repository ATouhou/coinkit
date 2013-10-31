import os
import binascii
import ecdsa
from base58 import base58_check_decode, base58_check_encode, base58_encode_padded
from hash import shash, rhash

class Address(object):

    @classmethod
    def from_secret(cls, secret):
        if len(secret) == 64:
            return Address(binascii.unhexlify(secret))
        elif len(secret) == 32:
            return Address(secret)
        else:
            raise Exception("Secret has to be exactly 32 bytes")

    @classmethod
    def from_passphrase(cls, passphrase):
        secret = passphrase.encode('utf8')
        for i in range(1): # just one round
            secret = shash(secret)
        return Address(secret)

    @classmethod
    def from_privkey(cls, privkey):
        secret = base58_check_decode(privkey, 0x80)
        return Address(secret)

    @classmethod
    def from_electrum_seed(cls, seed, idx):
        raise NotImplementedError

    def __init__(self, secret = None):
        if not secret:
            secret = os.urandom(32)
        self.secret = ecdsa.util.string_to_number(secret)
        self.pubkey = ecdsa.ecdsa.Public_key(ecdsa.ecdsa.generator_secp256k1, ecdsa.ecdsa.generator_secp256k1 * self.secret)
        self.privkey = ecdsa.ecdsa.Private_key(self.pubkey, secret)
        pubhex = ('04' + '%064x' % self.pubkey.point.x() + '%064x' % self.pubkey.point.y()).decode('hex')
        self.pub = base58_check_encode(rhash(pubhex))
        if self.pubkey.point.y() % 2:
            pubhex = ('03' + '%064x' % self.pubkey.point.x()).decode('hex')
        else:
            pubhex = ('02' + '%064x' % self.pubkey.point.x()).decode('hex')
        self.pubc = base58_check_encode(rhash(pubhex))
        self.priv = base58_check_encode(self.privkey.secret_multiplier, 0x80)
