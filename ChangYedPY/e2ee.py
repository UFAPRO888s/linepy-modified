# -*- coding: utf-8 -*-
from urllib.parse import quote, unquote, urlencode
from collections import namedtuple
from Crypto.Cipher import AES
import base64, hashlib, os
import axolotl_curve25519 as Curve25519
import hmac

def get_hashed_text_with_secret_key(secret_key: str, payload: str, method = hashlib.sha256) -> str:
    return hmac.new(secret_key.encode("utf-8"), payload.encode("utf-8"), method).hexdigest()

def get_encrypt_data(payload: str, secret_key: str, vector: str):
    b64_payload = base64.b64encode(payload.encode("utf-8"))

    if len(b64_payload) % 16 != 0:
        for _ in range(16 - (len(b64_payload) % 16)):
            b64_payload += b"_"

    secret_key = hashlib.sha256(secret_key.encode("utf-8")).digest()
    vector = hashlib.md5(vector.encode("utf-8")).digest()

    aes = AES.new(secret_key, AES.MODE_CBC, vector)
    cipher_data = aes.encrypt(b64_payload)
    return base64.b64encode(cipher_data).decode("utf-8")

def get_decrypt_data(b64_cipher: str, secret_key: str, vector: str):
    cipher_data = base64.b64decode(b64_cipher.encode("utf-8"))

    secret_key = hashlib.sha256(secret_key.encode("utf-8")).digest()
    vector = hashlib.md5(vector.encode("utf-8")).digest()
    aes = AES.new(secret_key, AES.MODE_CBC, vector)

    b64_payload = aes.decrypt(cipher_data)
    return base64.b64decode(b64_payload.partition(b"_")[0]).decode("utf-8")

# secret_key = "encrypted_mid_key"
# mid = "u35db685708155a4f03cce9c8e1799c41"
# primary_key = get_hashed_text_with_secret_key(secret_key, mid)
# print("primary key:", primary_key)

# token = "Ft9e3QReZB5i0oMQ9lS1.nDTOvWGvwK8dZoNi4xMCqq.wP1qGgy3y58cM7nJQ4kk26yWBWW9j1Vv61YxTmO/yQI="
# enc_token = get_encrypt_data(token, mid, primary_key)
# print("enc token:", enc_token)

# token = get_decrypt_data(enc_token, mid, primary_key)
# print("token:", token)

KeyPairCurve = namedtuple('KeyPair', ['private_key', 'public_key', 'nonce'])
AESKeyAndIV = namedtuple('AESKey', ['Key', 'IV'])

print(KeyPairCurve)
print(AESKeyAndIV)

class E2EE:

    def __init__(self):
        self.Curve = self.generateKeypair()

    def _xor(self, buf):
        buf_length = int(len(buf) / 2)
        buf2 = bytearray(buf_length)
        for i in range(buf_length):
            buf2[i] = buf[i] ^ buf[buf_length + i]
        return bytes(buf2)

    def _getSHA256Sum(self, *args):
        instance = hashlib.sha256()
        for arg in args:
            if isinstance(arg, str):
                arg = arg.encode()
            instance.update(arg)
        return instance.digest()

    def _encryptAESECB(self, aes_key, plain_data):
        aes = AES.new(aes_key, AES.MODE_ECB)
        return aes.encrypt(plain_data)

    def _decryptAESECB(self, aes_key, encrypted_data):
        aes = AES.new(aes_key, AES.MODE_ECB)
        return aes.decrypt(encrypted_data)

    def _encryptAESCBC(self, aes_key, aes_iv, plain_data):
        aes = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        return aes.encrypt(plain_data)

    def _decrpytAESCBC(self, aes_key, aes_iv, encrypted_data):
        aes = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        return aes.decrypt(encrypted_data)

    def generateKeypair(self):
        private_key = Curve25519.generatePrivateKey(os.urandom(32))
        public_key = Curve25519.generatePublicKey(private_key)
        nonce = os.urandom(16)
        return KeyPairCurve(private_key, public_key, nonce)

    def generateParams(self):
        secret = base64.b64encode(self.Curve.public_key).decode()
        return 'secret={secret}&e2eeVersion=2'.format(secret=quote(secret))

    def generateSharedSecret(self, public_key):
        private_key = self.Curve.private_key
        shared_secret = Curve25519.calculateAgreement(private_key, public_key)
        return shared_secret

    def generateAESKeyAndIV(self, shared_secret):
        aes_key = self._getSHA256Sum(shared_secret, 'Key')
        aes_iv = self._xor(self._getSHA256Sum(shared_secret, 'IV'))
        return AESKeyAndIV(aes_key, aes_iv)

    def generateSignature(self, aes_key, encrypted_data):
        data = self._xor(self._getSHA256Sum(encrypted_data))
        signature = self._encryptAESECB(aes_key, data)
        return signature

    def verifySignature(self, signature, aes_key, encrypted_data):
        data = self._xor(self._getSHA256Sum(encrypted_data))
        return self._decryptAESECB(aes_key, signature) == data

    def decryptKeychain(self, encrypted_keychain, public_key):
        public_key = base64.b64decode(public_key)
        encrypted_keychain = base64.b64decode(encrypted_keychain)
        shared_secret = self.generateSharedSecret(public_key)
        aes_key, aes_iv = self.generateAESKeyAndIV(shared_secret)
        keychain_data = self._decrpytAESCBC(aes_key, aes_iv, encrypted_keychain)
        return keychain_data
