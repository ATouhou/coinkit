import os
import binascii
import ecdsa
from base58 import base58_check_decode, base58_check_encode, base58_encode_padded
from hash import shash, rhash

_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_b = 0x0000000000000000000000000000000000000000000000000000000000000007L
_a = 0x0000000000000000000000000000000000000000000000000000000000000000L
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L
curve_secp256k1 = ecdsa.ellipticcurve.CurveFp( _p, _a, _b )
generator_secp256k1 = ecdsa.ellipticcurve.Point( curve_secp256k1, _Gx, _Gy, _r )
order = generator_secp256k1.order()
oid_secp256k1 = (1,3,132,0,10)
SECP256k1 = ecdsa.curves.Curve('SECP256k1', curve_secp256k1, generator_secp256k1, oid_secp256k1 )

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
    def from_seed(cls, seed, idx):
        raise NotImplementedError

    def __init__(self, secret = None):
        if not secret:
            secret = os.urandom(32)
        self.secret = ecdsa.util.string_to_number(secret)
        self.pubkey = ecdsa.ecdsa.Public_key(generator_secp256k1, generator_secp256k1 * self.secret)
        self.privkey = ecdsa.ecdsa.Private_key(self.pubkey, secret)
        pubhex = ('04' + '%064x' % self.pubkey.point.x() + '%064x' % self.pubkey.point.y()).decode('hex')
        self.pub = base58_check_encode(rhash(pubhex))
        self.priv = base58_check_encode(chr(128) + self.privkey.secret_multiplier)[1:51]
