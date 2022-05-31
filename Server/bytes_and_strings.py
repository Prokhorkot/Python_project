import base64


def bytesToString(textBytes: bytes) -> str:
    textBytesTemp = base64.b64decode(textBytes)
    return textBytesTemp.decode('utf-8')


def stringToBytes(text: str) -> bytes:
    textBytesTemp = text.encode('utf-8')
    return base64.b64encode(textBytesTemp)


def encryptedBytesToString(textBytes: bytes) -> str:
    textBytesTemp = base64.b64encode(textBytes)
    return textBytesTemp.decode('utf-8')


def encryptedStringToBytes(text: str) -> bytes:
    textBytesTemp = text.encode('utf-8')
    return base64.b64decode(textBytesTemp)
