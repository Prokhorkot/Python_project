import base64
from tokenize import String
from flask import Flask
from flask_restful import Api, Resource, reqparse, abort, fields
from flask_sqlalchemy import SQLAlchemy
import string
import secrets
from EncryptingProfile import EncryptingProfile
import encryption_asymmetric
import encryption_symmetric
import bytes_and_strings

app = Flask(__name__)
api = Api(app)
db = SQLAlchemy(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users_db.db"
encProfile = EncryptingProfile('server_keys')


class UserModel(db.Model):
    username = db.Column(
        db.String(20), nullable=False,
        unique=True, primary_key=True)

    password = db.Column(db.String(30), nullable=False)
    token = db.Column(db.String(400), nullable=False)

    def __repr__(self):
        return f'''User(username = {self.username},
         password = {self.password}, token = {self.token})'''


resource_fields = {
    'username': fields.String,
    'password': fields.String
}

login_args = reqparse.RequestParser()

login_args.add_argument(
    'username', type=str, help='Username',
    required=True, location=['args', 'form']
    )

login_args.add_argument(
    'password', type=str, help='Password',
    required=True, location=['args', 'form']
    )

login_args.add_argument(
    'symmetricKey', type=str,
    help='Key for data protection', required=True,
    location=['args', 'form']
    )


check_existence = reqparse.RequestParser()

check_existence.add_argument(
    'token1', type=str, help='First part of User\'s token',
    required=True, location=['args']
)

check_existence.add_argument(
    'token2', type=str, help='Second part of User\'s token',
    required=True, location=['args']
)


class Secure(Resource):
    # Getting public key
    def get(self):
        publicKey = encryption_asymmetric.getStringOfPublicKey(
            encProfile.publicKey)

        return {'public key': publicKey}


class Existence(Resource):
    # Check if profile exists
    def get(self):
        args = check_existence.parse_args()
        token1 = handleEncryptedInput(args['token1'])
        token2 = handleEncryptedInput(args['token2'])

        token = token1 + token2
        
        result = UserModel.query.filter_by(
            token=token).first()
        
        if result:
            return result.__dict__['username'], 200

        return 'User not found', 404


class User(Resource):
    # Login into account
    def get(self):
        args = login_args.parse_args()

        username = handleEncryptedInput(args['username'])
        password = handleEncryptedInput(args['password'])
        symmetricKey = handleEncryptedSymmKey(args['symmetricKey'])

        print(f'Trying to login {username} : {password}')

        result = UserModel.query.filter_by(
            username=username, password=password).first()

        if not result:
            print('User not exists')
            abort(404, message='User does not exist')

        if tryLogin(username, password):
            print(f'{username} logged in')

            token = result.token

            print(f'token = {token}')

            nonce, cipherToken, tag = encryption_symmetric.encrypt(
                bytes_and_strings.stringToBytes(token),
                symmetricKey
            )

            return {
                    'status': 'Logged in successfully!',
                    'token': bytes_and_strings.encryptedBytesToString(cipherToken),
                    'nonce': bytes_and_strings.encryptedBytesToString(nonce),
                    'tag': bytes_and_strings.encryptedBytesToString(tag)
                    }, 200

        print('Invalid login or password')
        abort(403, message='Invalid login or password')

    # Create new account
    def post(self):
        args = login_args.parse_args()

        username = handleEncryptedInput(args['username'])
        password = handleEncryptedInput(args['password'])
        symmetricKey = handleEncryptedSymmKey(args['symmetricKey'])

        result = UserModel.query.filter_by(username=username).first()

        if result:
            print(f'User {username} already exists')
            abort(409, message='User already exists')

        token = createToken()
        user = UserModel(username=username, password=password, token=token)

        db.session.add(user)
        db.session.commit()

        print('Account  created successfully')

        nonce, cipherToken, tag = encryption_symmetric.encrypt(
                bytes_and_strings.stringToBytes(token),
                symmetricKey
            )

        return {
                'status': 'Account created successfully!',
                'token': bytes_and_strings.encryptedBytesToString(cipherToken),
                'nonce': bytes_and_strings.encryptedBytesToString(nonce),
                'tag': bytes_and_strings.encryptedBytesToString(tag)
                }, 201


def tryLogin(username: str, password: str) -> bool:
    result = UserModel.query.filter_by(
        username=username, password=password).first()

    if result:
        return True
    return False


def createToken() -> String:
    alphabet = string.ascii_letters + string.digits
    token = ''

    for i in range(400):
        token += secrets.choice(alphabet)
    print(f'Generated tocken: {token}')

    return token


def handleEncryptedInput(message: str) -> str:
    # Converting our string to bytes
    messageEncrypted = bytes_and_strings.encryptedStringToBytes(message)
    # Decrypting message in bytes
    messageBytes = encryption_asymmetric.decrypt(
        messageEncrypted, encProfile.privateKey)
    # Return result string
    return bytes_and_strings.bytesToString(messageBytes)


def handleEncryptedSymmKey(cipherKey: str) -> bytes:
    encSymmetricKey = bytes_and_strings.encryptedStringToBytes(cipherKey)
    symmetricKey = encryption_asymmetric.decrypt(encSymmetricKey, encProfile.privateKey)

    return symmetricKey

api.add_resource(User, '/accounts')
api.add_resource(Secure, '/publickey')
api.add_resource(Existence, '/existence')



if __name__ == "__main__":
    app.run(debug=True, ssl_context='adhoc', host='192.168.1.37')
