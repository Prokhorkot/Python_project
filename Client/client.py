import json
import re
import socket
import threading
import os
import urllib3
import requests
import db_interface
import encryption_asymmetric
import encryption_symmetric
import bytes_and_strings

from secrets import token_bytes
from EncryptingProfile import EncryptingProfile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FORMAT = 'utf-8'
HEADER = 128
SERVER = socket.gethostbyname(socket.gethostname())

# Special messages for server
DISCONNECT_MESSAGE = '__DISCONNECT'
START_CHAT = '__STARTCHAT'
SEND_MESSAGE = '__SEND'
UNKNOWN = '__UNKNOWN'
PUBLIC_KEY = '__PUBKEY'
SYMM_KEY = '__SYMMKEY'
R_SYMM_KEY = '__RECIEVE_SYMMKEY'
LOGIN = '__LOGIN'

# Special commands for client
EXIT_COMM = '//exit'
BEGIN_TO_CHAT_COMM = '//start_chat'

# URL of Authentication server
AUTH_BASE = 'https://192.168.1.37:5000/'

# SPECIAL USERNAMES
SERVER_USERNAME = 'SERVER'
AUTH_USERNAME = 'AUTH_SERVER'


vars = {'currentInterlocutor': ''}

keys = {}

encProfile = EncryptingProfile('client_keys')


def connect(host: str = '192.168.1.37', port: int = 3030):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect((host, port))

    name, token = authorize()
    print(name)
    print(token)

    recieveCommand(server)

    loginToServer(server, name, token)

    startWorking(server)


def authorize():
    response = requests.get(AUTH_BASE + 'publickey', verify=False)

    publicKeyString = json.loads(response.text)['public key']
    publicKey = encryption_asymmetric.\
        getBytesOfStringPublicKey(publicKeyString)

    parameters = {
        'username': '',
        'password': '',
        'symmetricKey': ''}
    username = ''
    password = ''

    print('Login or register?')
    while True:
        comm = input().lower()

        if comm == 'login':
            while True:
                username = input('Enter login: ')
                password = input('Enter password: ')

                key = token_bytes(16)
                keys[AUTH_USERNAME] = key

                parameters['username'] = publicEncryptSToS(username, publicKey)
                parameters['password'] = publicEncryptSToS(password, publicKey)
                parameters['symmetricKey'] = publicEncryptBToS(key, publicKey)

                response = requests.get(AUTH_BASE + 'accounts',
                                        parameters, verify=False)

                if response.status_code != 200:
                    os.system('cls')
                    print('Wrong username or password')
                    continue

                info = json.loads(response.text)

                tokenBytes = encryption_symmetric.decrypt(
                    bytes_and_strings.encryptedStringToBytes(info['nonce']),
                    bytes_and_strings.encryptedStringToBytes(info['token']),
                    bytes_and_strings.encryptedStringToBytes(info['tag']),
                    key
                )

                token = bytes_and_strings.bytesToString(tokenBytes)

                break

            return username, token

        elif comm == 'register':
            while True:
                username = input('Enter login: ')
                password = input('Enter password: ')

                key = token_bytes(16)
                keys[AUTH_USERNAME] = key

                parameters['username'] = publicEncryptSToS(username, publicKey)
                parameters['password'] = publicEncryptSToS(password, publicKey)
                parameters['symmetricKey'] = publicEncryptBToS(key, publicKey)

                response = requests.post(AUTH_BASE + 'accounts',
                                         parameters, verify=False)

                if response.status_code != 201:
                    os.system('cls')
                    print('User already exists!')
                    continue

                info = json.loads(response.text)

                tokenBytes = encryption_symmetric.decrypt(
                    bytes_and_strings.encryptedStringToBytes(info['nonce']),
                    bytes_and_strings.encryptedStringToBytes(info['token']),
                    bytes_and_strings.encryptedStringToBytes(info['tag']),
                    key
                )

                token = bytes_and_strings.bytesToString(tokenBytes)

                break

            return username, token
        print('Sorry?')


def publicEncryptBToS(value: bytes, publicKey):
    cipherText = encryption_asymmetric.encrypt(value, publicKey)
    cipherText = bytes_and_strings.encryptedBytesToString(cipherText)
    return cipherText


def publicEncryptSToS(text: str, publicKey):
    text = bytes_and_strings.stringToBytes(text)
    return publicEncryptBToS(text, publicKey)


def loginToServer(server: socket.socket, name, token):
    while True:
        sendMessage(server, LOGIN, name, token, SERVER_USERNAME)

        command = recieveMessage(server)
        serverName = recieveMessage(server)

        answer = decryptMessage(server, SERVER_USERNAME)

        if answer == 'Connected successfully!':
            print('Logged in')
            break

        print('Failed to log in')
        name, token = authorize()
        continue


def startWorking(server: socket.socket):
    threading.Thread(target=listen, args=(server,), daemon=False).start()

    os.system('cls')

    startChat(server)


def startChat(server: socket.socket):
    os.system('cls')

    reciever = input('Please, enter reciever\'s name: ')

    if reciever in keys.keys():
        doChating(server, reciever)
        return

    if reciever == EXIT_COMM:
        return

    sendMessage(server, START_CHAT, reciever, endPoint=SERVER_USERNAME)


def doChating(server: socket.socket, reciever: str):
    vars['currentInterlocutor'] = reciever

    while True:
        message = input('you: ')
        if message == EXIT_COMM:
            vars['currentInterlocutor'] = ''
            return

        sendMessage(server, SEND_MESSAGE, reciever, message)


def listen(server: socket.socket):
    while True:
        recieveCommand(server)


def sendMessage(server: socket.socket,
                command: str, header: str,
                message: str = '',
                endPoint: str = ''):
    decrypter = header

    if endPoint != '':
        decrypter = endPoint

    nonce, encMessage, tag = encryptMessage(message, keys[decrypter])

    sendStrPacket(server, command)
    sendStrPacket(server, header)
    sendStrPacket(server, nonce)
    sendStrPacket(server, encMessage)
    sendStrPacket(server, tag)


def encryptMessage(message: str, key: str):
    nonce, encMessage, tag = encryption_symmetric.\
        encrypt(bytes_and_strings.stringToBytes(message), bytes(key))

    return \
        bytes_and_strings.encryptedBytesToString(nonce),\
        bytes_and_strings.encryptedBytesToString(encMessage),\
        bytes_and_strings.encryptedBytesToString(tag)


def sendStrPacket(server: socket.socket, content: str):
    content = content.encode(FORMAT)

    msgLenght = len(content)
    sendLength = str(msgLenght).encode(FORMAT)
    sendLength += b' ' * (HEADER - len(sendLength))

    server.send(sendLength)
    server.send(content)


def sendBytePacket(server: socket.socket, content: bytes):
    msgLenght = len(content)
    sendLength = str(msgLenght).encode(FORMAT)
    sendLength += b' ' * (HEADER - len(sendLength))

    server.send(sendLength)
    server.send(content)


def recieveMessage(server: socket.socket) -> str:
    while True:
        msgLength = server.recv(HEADER).decode(FORMAT)
        if not msgLength:
            continue

        msgLength = int(msgLength)
        message = server.recv(msgLength).decode(FORMAT)

        # print(f'{msgLength}: {message}')

        return message


def recieveCommand(server: socket.socket) -> int:
    command = recieveMessage(server)

    if command == START_CHAT:
        return onStartChat(server)
    if command == SEND_MESSAGE:
        recieveChatMessage(server)
        return
    if command == SYMM_KEY:
        onSendKey(server)
        return
    if command == PUBLIC_KEY:
        onSendPublicKey(server)
        return
    if command == R_SYMM_KEY:
        recieveSymmKey(server)
        return
    if command == UNKNOWN:
        return


def onSendPublicKey(server: socket.socket):
    name = recieveMessage(server)
    recieveMessage(server)

    publicKey = encryption_asymmetric.getStringOfPublicKey(
            encProfile.publicKey)

    sendPublicKey(server, name, publicKey)


def recieveSymmKey(server: socket.socket):
    sender = recieveMessage(server)
    encKey = recieveMessage(server)

    encKey = bytes_and_strings.encryptedStringToBytes(encKey)

    key = encryption_asymmetric.decrypt(encKey, encProfile.privateKey)

    keys[sender] = key


def sendPublicKey(server: socket.socket, reciever: str, key: str):
    sendStrPacket(server, PUBLIC_KEY)
    sendStrPacket(server, reciever)
    sendStrPacket(server, key)


def onSendKey(server: socket.socket):
    name = recieveMessage(server)
    public_key = recieveMessage(server)

    symm_key = token_bytes(16)
    keys[name] = symm_key

    public_key = encryption_asymmetric.getBytesOfStringPublicKey(public_key)
    symm_key = encryption_asymmetric.encrypt(symm_key, public_key)
    symm_key = bytes_and_strings.encryptedBytesToString(symm_key)

    sendSymmKey(server, name, symm_key)
    if name != SERVER_USERNAME:
        threading.Thread(target=listen, args=(server,), daemon=False).start()
        doChating(server, name)


def sendSymmKey(server: socket.socket, reciever: str, key: str):
    sendStrPacket(server, SYMM_KEY)
    sendStrPacket(server, reciever)
    sendStrPacket(server, key)


def onStartChat(server: socket.socket) -> int:
    interlocutor = recieveMessage(server)
    message = decryptMessage(server, interlocutor)

    if message == 'User found':
        return

    reciever = input('Please, enter reciever\'s name: ')

    if reciever == EXIT_COMM:
            return

    sendMessage(server, START_CHAT, reciever, endPoint=SERVER_USERNAME)
    return


def recieveChatMessage(server: socket.socket) -> int:
    sender = recieveMessage(server)
    message = decryptMessage(server, sender)

    db_interface.addRecievedMessage(sender, message)

    if sender == vars['currentInterlocutor']:
        print(f'\r\033[K\033[32m@{sender}: \033[37m{message}', end='\nyou:')
    return 0


def onSetName() -> str:
    while True:
        name = input('Enter name: @')

        if len(name) > 3 and re.fullmatch(r'.*\W.*', name) is None:
            return name

        print('\r\033[K!!!Invalid name. Please, try another one!!!')


def decryptMessage(server: socket.socket, name: str):
    nonce = recieveMessage(server)
    encMessage = recieveMessage(server)
    tag = recieveMessage(server)

    nonce = bytes_and_strings.encryptedStringToBytes(nonce)
    encMessage = bytes_and_strings.encryptedStringToBytes(encMessage)
    tag = bytes_and_strings.encryptedStringToBytes(tag)

    message = encryption_symmetric.decrypt(
        nonce,
        encMessage,
        tag,
        keys[name]
    )

    return bytes_and_strings.bytesToString(message)


if __name__ == '__main__':
    os.system('cls')
    print('Welcome to chat!')
    try:
        connect()
    except:
        connect(port=3031)
