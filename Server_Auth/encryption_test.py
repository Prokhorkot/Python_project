import encryption_asymmetric
from EncryptingProfile import EncryptingProfile
import bytes_and_strings
from secrets import token_bytes
import os

os.system('clear')

privateKey, publicKey = encryption_asymmetric.loadKeys('test_folder')

encryption_asymmetric.encrypt(token_bytes(446), publicKey)
print('\033[32mSuccess!')

# message = 'Some message'

# message_enc = encryption_asymmetric.encrypt(bytes_and_strings.stringToBytes(message), publicKey)
# print(message_enc)

# # message_enc_string = bytes_and_strings.bytesToString(message_enc)
# print(message_enc.decode('utf-8'))

# message_decr_bytes = encryption_asymmetric.decrypt(message_enc, privateKey)
# print(message_decr_bytes)

# message = bytes_and_strings.bytesToString(message_decr_bytes)
# print(message)