import os
from sqlalchemy import create_engine, Table, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session

id = 1


def mkdir(file: str):
    if not os.path.exists(file):
        os.mkdir(file)

mkdir('database')

engine_recieved = create_engine('sqlite:///database/recieved_messages.db')
engine_sent = create_engine('sqlite:///database/sent_messages.db')
engine_key = create_engine('sqlite:///database/keys.db')

Base_recieved = declarative_base()
Base_sent = declarative_base()
Base_keys = declarative_base()

session_recieved = Session(bind=engine_recieved)
session_sent = Session(bind=engine_sent)
session_keys = Session(bind=engine_key)


class RecievedMessage(Base_recieved):
    __tablename__ = 'recieved_messages'
    id = Column(Integer, primary_key=True)
    sender = Column(String)
    message = Column(String)


class SentMessage(Base_sent):
    __tablename__ = 'sent_messages'
    id = Column(Integer, primary_key=True)
    reciever = Column(String)
    message = Column(String)


class Key(Base_keys):
    __tablename__ = 'keys'
    id = Column(Integer, primary_key=True)
    username = Column(String)
    key = Column(String)


def addRecievedMessage(sender, message):
    message = RecievedMessage(sender=sender, message=message)

    session_recieved.add(message)
    session_recieved.commit()


def addSentMessage(reciever, message):
    message = SentMessage(reciever=reciever, message=message)

    session_sent.add(message)
    session_sent.commit()


def addKey(username, key):
    key = Key(username=username, key=key)

    session_keys.add(key)
    session_keys.commit()


Base_recieved.metadata.create_all(engine_recieved)
Base_sent.metadata.create_all(engine_sent)
Base_keys.metadata.create_all(engine_key)
