from http.client import REQUESTED_RANGE_NOT_SATISFIABLE
import json
from multiprocessing.context import set_spawning_popen
from operator import contains
import os
import socket
import threading
import urllib3
import requests
import encryption_asymmetric
import encryption_symmetric
import bytes_and_strings

from Member import Member
from EncryptingProfile import EncryptingProfile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FORMAT = 'utf-8'
HEADER = 128
SERVER = socket.gethostbyname(socket.gethostname())

UNKNOWN = '__UNKNOWN'
DISCONNECT_MESSAGE = '__DISCONNECT'
START_CHAT = '__STARTCHAT'
SEND_MESSAGE = '__SEND'
PUBLIC_KEY = '__PUBKEY'
SYMM_KEY = '__SYMMKEY'
AUTH_BASE = 'https://127.0.0.1:5000/'
R_SYMM_KEY = '__RECIEVE_SYMMKEY'
LOGIN = '__LOGIN'

SERVER_USERNAME = 'SERVER'
lock = threading.Lock()

members = []
names: dict = {}
encProfile = EncryptingProfile('server_keys')
closed = False

def closeSocket():
    global closed
    while not closed:
        command = input()
        if command == 'close':
            closed = True


def startServer(host: str = '127.0.0.1', port: int = 3030):

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    try:
        server.listen()
        
        print(f'Listening at {host}:{port}')

        threading.Thread(target=closeSocket).start()

        while not closed:
            conn, address = server.accept()
            thread = threading.Thread(target=handleClient, args=(conn, address))
            thread.start()
            print(f"\033[32m[ACTIVE CONNECTIONS] {threading.activeCount() - 2}\033[37m")
    
    except:
        server.close()


def handleClient(conn: socket.socket, address: tuple):
    client = Member(conn, address)
    
    lock.acquire()
    try:
        members.append(client)
    finally:
        lock.release()

    sendPublicKey(client)
    handleCommand(client)

    authorize(client)

    while True:
        handleCommand(client)


def sendPublicKey(client: Member):
    sendPacketStrToClient(client, SYMM_KEY)
    sendPacketStrToClient(client, SERVER_USERNAME)
    sendPacketStrToClient(client, encryption_asymmetric.getStringOfPublicKey(encProfile.publicKey))


def handleCommand(client: Member):
    command = recieveMessage(client)

    if command == START_CHAT:
        onStartChat(client)
        return

    if command == SEND_MESSAGE:
        onSendMessage(client)
        return

    if command == SYMM_KEY:
        handleKeys(client)
        return

    if command == PUBLIC_KEY:
        routePublicKey(client)
        return

    sendMessageToClient(client, UNKNOWN, SERVER_USERNAME, '!!!Unknown command!!!')


def onStartChat(client: Member):
    reciever = recieveMessage(client)
    recieveMessage(client)
    recieveMessage(client)
    recieveMessage(client)
    print(f'С {reciever} хочет начать чат {client.userName}')

    for member in members:
        if member.userName == reciever:
            sendMessageToClient(client, START_CHAT, SERVER_USERNAME, 'User found')
            prepareChat(client, member)
            print(f'Chat {client.userName} - {reciever} started')
            return
    
    sendMessageToClient(client, START_CHAT, SERVER_USERNAME, '!!!User not found!!!')
    return


def onSendMessage(client: Member):
    reciever = recieveMessage(client)

    for member in members:
            if member.userName == reciever:
                routeMessage(client, member, SEND_MESSAGE)
                return
    
    sendMessageToClient(client, START_CHAT, SERVER_USERNAME, '!!!User not found!!!')
    return


def authorize(client: Member):
    response = requests.get(AUTH_BASE + 'publickey', verify=False)

    publicKeyString = json.loads(response.text)['public key']
    publicKey = encryption_asymmetric.getBytesOfStringPublicKey(publicKeyString)
    
    while True:
        recieveMessage(client)
        name = recieveMessage(client)
        token = handleEncryptedMsg(client)
        dividedToken = divideToken(token, publicKey)

        response = requests.get(AUTH_BASE + 'existence', dividedToken, verify=False)

        login = response.text[1:len(response.text) - 2]

        if name == login:
            sendMessageToClient(client, LOGIN, SERVER_USERNAME, 'Connected successfully!')
            print(f'Successfull sing in for {name}')
            client.userName = name
            for member in members:
                print(f'{member.userName}, ')
            break

        sendMessageToClient(client, LOGIN, SERVER_USERNAME, '!!!User not found!!!')


def divideToken(token: str, publicKey):
    encToken1 = encryption_asymmetric.encrypt(bytes_and_strings.stringToBytes(token[:223]), publicKey)
    encToken2 = encryption_asymmetric.encrypt(bytes_and_strings.stringToBytes(token[223:]), publicKey)

    encTokenString1 = bytes_and_strings.encryptedBytesToString(encToken1)
    encTokenString2 = bytes_and_strings.encryptedBytesToString(encToken2)

    return {'token1': encTokenString1, 'token2': encTokenString2}


def handleKeys(client: Member):
    reciever = recieveMessage(client)

    if reciever == SERVER_USERNAME:
        key = recieveMessage(client)
        symm_key = bytes_and_strings.encryptedStringToBytes(key)
        symm_key = encryption_asymmetric.decrypt(symm_key, encProfile.privateKey)

        client.symm_key = symm_key
    
    else:
        for member in members:
            if member.userName == reciever:
                routeMessage(client, member, SYMM_KEY)
                return
    
        sendMessageToClient(client, SYMM_KEY, SERVER_USERNAME, '!!!User not found!!!')
        return


def prepareChat(sender: Member, reciever: Member):
    sendMessageToClient(reciever, PUBLIC_KEY, sender.userName, message = '')
    routeKey(sender, reciever)


def routePublicKey(client: Member):
    name = recieveMessage(client)
    key = recieveMessage(client)
    for member in members:
        if member.userName == name:
            sendPacketStrToClient(member, SYMM_KEY)
            sendPacketStrToClient(member, client.userName)
            sendPacketStrToClient(member, key)


def routeKey(sender: Member, reciever: Member):
    recieveMessage(sender)
    recieveMessage(sender)

    key = recieveMessage(sender)

    sendPacketStrToClient(reciever, R_SYMM_KEY)
    sendPacketStrToClient(reciever, sender.userName)
    sendPacketStrToClient(reciever, key)


def sendMessageToClient(client: Member, command: str, header: str, message: str):
    nonce, encMessage, tag = encryptMessage(message, client.symm_key)

    sendPacketStrToClient(client, command)
    sendPacketStrToClient(client, header)
    sendPacketStrToClient(client, nonce)
    sendPacketStrToClient(client, encMessage)
    sendPacketStrToClient(client, tag)


def encryptMessage(message: str, key: bytes):
    nonce, encMessage, tag = encryption_symmetric.encrypt(
        bytes_and_strings.stringToBytes(message), bytes(key))

    return \
        bytes_and_strings.encryptedBytesToString(nonce),\
        bytes_and_strings.encryptedBytesToString(encMessage),\
        bytes_and_strings.encryptedBytesToString(tag)


def sendPacketStrToClient(client: Member, message: str):
    message = message.encode(FORMAT)
    sendPacketByteToClient(client, message)


def sendPacketByteToClient(client: Member, message: bytes):

    msgLenght = len(message)
    sendLength = str(msgLenght).encode(FORMAT)
    sendLength += b' ' * (HEADER - len(sendLength))

    print(f'\033[32m{client.userName}: {msgLenght}: {str(message)}\033[37m')

    client.conn.send(sendLength)
    client.conn.send(message)


def routeMessage(sender: Member, reciever: Member, command: str):
    nonce = recieveMessage(sender)
    encMessage = recieveMessage(sender)
    tag = recieveMessage(sender)

    sendPacketStrToClient(reciever, command)
    sendPacketStrToClient(reciever, sender.userName)
    sendPacketStrToClient(reciever, nonce)
    sendPacketStrToClient(reciever, encMessage)
    sendPacketStrToClient(reciever, tag)


def recieveMessage(client: Member) -> str:
    while True:
        msgLength = client.conn.recv(HEADER).decode(FORMAT)
        if not msgLength: continue

        msgLength = int(msgLength)
        message = client.conn.recv(msgLength).decode(FORMAT)

        print(f'{client.userName}: {msgLength}: {message}')
        return message


def handleEncryptedMsg(client):
    nonce = recieveMessage(client)
    encMessage = recieveMessage(client)
    tag = recieveMessage(client)

    nonce = bytes_and_strings.encryptedStringToBytes(nonce)
    encMessage = bytes_and_strings.encryptedStringToBytes(encMessage)
    tag = bytes_and_strings.encryptedStringToBytes(tag)

    message = encryption_symmetric.decrypt(
        nonce,
        encMessage,
        tag,
        client.symm_key
    )

    return bytes_and_strings.bytesToString(message)


def onJoinClient(members: list, address: tuple, name: str):
    curMember = Member(address, name)

    threading.Lock(members).acquire()
    try:
        members.append(curMember)
    finally:
        threading.Lock(members).release()
        
    print(f'Client {name} joined chat')

    return curMember


if __name__ == '__main__':
    os.system('clear')
    try:
        startServer()
    except:
        startServer(port=3031)
