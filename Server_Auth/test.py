import json
from tokenize import String
import requests
import os
import urllib3
from secrets import token_bytes
from EncryptingProfile import EncryptingProfile
import encryption_asymmetric
import encryption_symmetric
import bytes_and_strings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


os.system('clear')
BASE = 'https://127.0.0.1:5000/'
username = bytes_and_strings.stringToBytes('prokhor')
password = bytes_and_strings.stringToBytes('qwerty1234')
key = token_bytes(16)
myEncryption = EncryptingProfile('test_keys')

response = requests.get(BASE + 'publickey', verify=False)

publicKeyString = json.loads(response.text)['public key']
publicKey = encryption_asymmetric.getBytesOfStringPublicKey(publicKeyString)

encryption_asymmetric.savePublicKey(
    publicKey,
    'test_keys/server_public_key.pem')

parametres = {
    'username': '',
    'password': '',
    'symmetricKey': ''
    }

encUsername = encryption_asymmetric.encrypt(username, publicKey)
encPassword = encryption_asymmetric.encrypt(password, publicKey)
encSymmetricKey = encryption_asymmetric.encrypt(key, publicKey)

encUsernameString = bytes_and_strings.encryptedBytesToString(encUsername)
encPasswordString = bytes_and_strings.encryptedBytesToString(encPassword)
encSymmetricKeyString = \
    bytes_and_strings.encryptedBytesToString(encSymmetricKey)

parametres['username'] = encUsernameString
parametres['password'] = encPasswordString
parametres['symmetricKey'] = encSymmetricKeyString

response = requests.get(BASE + 'accounts', parametres, verify=False)

if(response.status_code == 200):
        info = json.loads(response.text)

        print(info['status'])
        tokenBytes = encryption_symmetric.decrypt(
            bytes_and_strings.encryptedStringToBytes(info['nonce']),
            bytes_and_strings.encryptedStringToBytes(info['token']),
            bytes_and_strings.encryptedStringToBytes(info['tag']),
            key
        )

        token = bytes_and_strings.bytesToString(tokenBytes)

        print(f'Your token: {token}')

        encToken1 = encryption_asymmetric.\
            encrypt(bytes_and_strings.stringToBytes(token[:223]), publicKey)
        encToken2 = encryption_asymmetric.\
            encrypt(bytes_and_strings.stringToBytes(token[223:]), publicKey)
        encTokenString1 = bytes_and_strings.encryptedBytesToString(encToken1)
        encTokenString2 = bytes_and_strings.encryptedBytesToString(encToken2)

        response = requests.get(
            BASE + 'existence',
            {'token1': encTokenString1,
             'token2': encTokenString2},
            verify=False
        )

        print(response.text[1:len(response.text) - 2])


# while True:
#     username = input('Enter login: ')
#     parametres['password'] = input('Enter password: ')

#     response = requests.get(BASE + 'accounts', parametres, verify=False)
#     if(response.status_code == 200):
#         info = json.loads(response.text)

#         print(info['status'])
#         print(f'Your token: {info["token"]}')
#         break
#     else:
#         print(json.loads(response.text)['message'])
