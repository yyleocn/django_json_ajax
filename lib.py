import dataclasses
import base64

import json

# You may also pick one without version check, of course
from typing_extensions import TypedDict, NotRequired

from django.core.handlers.wsgi import WSGIRequest
from django.contrib.sessions.backends.cache import SessionStore

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad


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

    def encrypt(self, sourceData: str | bytes) -> str:
        if isinstance(sourceData, str):
            dataBytes = sourceData.encode()
        else:
            dataBytes = sourceData
        return base64.b64encode(
            self.__cipher.encrypt(
                pad(dataBytes, block_size=16, style='pkcs7')
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
    encryptType: str | None


class JsonResponseDict(TypedDict):
    status: NotRequired[int]
    message: NotRequired[str]
    result: NotRequired[any]
