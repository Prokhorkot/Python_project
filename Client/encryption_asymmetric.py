from inspect import _void
import os
from unittest.util import _MAX_LENGTH
from cryptography.hazmat.primitives.asymmetric import rsa, types, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64


SUPERSECRET = b'sypersecretpassword'


def generateKeys(dirPath: str):

    if not os.path.exists(dirPath):
        os.mkdir(dirPath)

    privateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    with open(f'{dirPath}/private_key.pem', 'wb') as f:
        pem = privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                SUPERSECRET)
        )

        f.write(pem)

    publicKey = privateKey.public_key()
    with open(f'{dirPath}/public_key.pem', 'wb') as f:
        pem = publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        f.write(pem)


def loadKeys(dirPath: str):
    privateKey = publicKey = None

    with open(f'{dirPath}/private_key.pem', 'rb') as f:
        privateKey = serialization.load_pem_private_key(
            f.read(),
            password=SUPERSECRET
        )

    with open(f'{dirPath}/public_key.pem', 'rb') as f:
        publicKey = serialization.load_pem_public_key(f.read())

    return privateKey, publicKey


def encrypt(plainText: bytes, publicKey: types.PUBLIC_KEY_TYPES) -> bytes:
    cipherText = publicKey.encrypt(
        plaintext=plainText,
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return cipherText


def decrypt(cipherText: bytes, privateKey: types.PRIVATE_KEY_TYPES) -> bytes:
    plainText = privateKey.decrypt(
        ciphertext=cipherText,
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plainText


def sign(plainText, privateKey: types.PRIVATE_KEY_TYPES):
    signature = privateKey.sign(
        plainText,
        padding=padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        algorithm=hashes.SHA256()
    )

    return signature


# Throws InvalidSignature exception
def verify(cipherText, signature, publicKey: types.PUBLIC_KEY_TYPES):
    publicKey.verify(
        signature,
        cipherText,
        padding=padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        algorithm=hashes.SHA256()
    )


def getStringOfPublicKey(publicKey: types.PUBLIC_KEY_TYPES) -> str:
    publicKeyBytes = base64.b64encode(publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    return publicKeyBytes.decode('utf-8')


def getBytesOfStringPublicKey(publicKey: str) -> types.PUBLIC_KEY_TYPES:
    publicKeyTemp = publicKey.encode('utf-8')
    putlicKeyBytes = base64.b64decode(publicKeyTemp)
    publicKey = serialization.load_pem_public_key(putlicKeyBytes)

    return publicKey


def savePublicKey(publicKey: types.PUBLIC_KEY_TYPES, filePath: str):
    with open(filePath, 'wb') as f:
        pem = publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        f.write(pem)
