from Crypto.Cipher import AES


def encrypt(msg: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    cipherText, tag = cipher.encrypt_and_digest(msg)

    return nonce, cipherText, tag


def decrypt(nonce, cipherText, tag: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plainText = cipher.decrypt(cipherText)

    try:
        cipher.verify(tag)
        return plainText
    except:
        return False
