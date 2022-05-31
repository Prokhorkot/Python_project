import socket
from typing import Any


class Member(object):
    def __init__(self,
            conn: socket.socket,
            address: tuple,
            userName: str = '',
            isOnline: bool = True,
            symm_key: bytes = b''):

        self.conn = conn
        self.address = address
        self.userName = userName
        self.isOnline = isOnline
        self.chats = []
        self.symm_key = symm_key