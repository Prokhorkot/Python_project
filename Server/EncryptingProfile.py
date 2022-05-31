import encryption_asymmetric


class EncryptingProfile:
    def __init__(self, dirPath) -> None:
        encryption_asymmetric.generateKeys(dirPath)
        self.privateKey, self.publicKey = encryption_asymmetric.loadKeys(
            dirPath)

        self.dirPath = dirPath
