import dataclasses
import base64

import json

from django.core.handlers.wsgi import WSGIRequest
from django.contrib.sessions.backends.cache import SessionStore

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


def jsonDumpDefault(target: any):
    if isinstance(target, set):
        return tuple(target)

    return f'{target}'


def jsonDumps(target):
    return json.dumps(
        target, default=jsonDumpDefault,
        ensure_ascii=False, sort_keys=True, indent=2,
    )


jsonLoads = json.loads


class RsaBase64Cipher:
    __publicCipher = None
    __privateCipher = None

    def __init__(self, publicKey: bytes = None, privateKey: bytes = None):
        if publicKey is not None:
            self.__publicCipher = PKCS1_OAEP.new(RSA.importKey(publicKey))
        if privateKey is not None:
            self.__privateCipher = PKCS1_OAEP.new(RSA.importKey(privateKey))

    def encrypt(self, dataStr: str) -> str:
        assert self.__publicCipher is not None, 'Encrypt fail without public key.'
        return base64.b64encode(
            self.__publicCipher.encrypt(dataStr.encode())
        ).decode()

    def decrypt(self, b64Str: str) -> str:
        assert self.__privateCipher is not None, 'Decrypt fail without private key.'
        return self.__privateCipher.decrypt(
            base64.b64decode(b64Str)
        ).decode()


class AesBase64Cipher:
    def __init__(self, secretKey: bytes):
        assert isinstance(secretKey, bytes), 'Secret key type must be bytes.'
        assert len(secretKey) == 16, 'Secret key length must be 16.'
        self.__cipher = AES.new(key=secretKey, mode=AES.MODE_ECB)

    def encrypt(self, dataStr: str) -> str:
        return base64.b64encode(
            self.__cipher.encrypt(
                pad(dataStr.encode(), block_size=16, style='pkcs7')
            )
        ).decode()

    def decrypt(self, b64str: str) -> str:
        return unpad(
            self.__cipher.decrypt(base64.b64decode(b64str)),
            block_size=16, style='pkcs7',
        ).decode()


@dataclasses.dataclass(frozen=True)
class NonceData:
    number: int
    time: int


class JsonRequestType(WSGIRequest):
    session: SessionStore
    JsonData: dict
    remoteIP: str
    remoteIP_group: str
    Nonce: NonceData
    isAjax: bool
