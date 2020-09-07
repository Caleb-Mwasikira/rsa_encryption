#!/usr/bin/env python
# -*- coding:utf-8 -*-

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP
from pathlib import Path
from dotenv import load_dotenv
import os


class Encryptor:
    def __init__(self):
        self.private_key = None
        self.public_key = None


    def genKeys(self):
        """Generating new private and public key pair"""
        print(f"[+] Generating new pair of private and public keys")
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()
        return self.private_key, self.public_key


    @staticmethod
    def pemSaveKey(key, key_file_path, pass_phrase):
        """Saving an encrypted key onto a .pem file"""
        with open(key_file_path, "wb") as f:
            f.write(key.export_key(format="PEM", passphrase=pass_phrase, pkcs=8))
        print(f"[+] Key successfully saved on file {key_file_path}")

    def pemLoadKey(self, key_file_path, pass_phrase):
        """Importing An Encrypted Key From A File"""
        try:
            with open(key_file_path, "rb") as f:
                data = f.read()
                key = RSA.import_key(data, passphrase=pass_phrase)
            print(f"[+] Key successfully imported from file")
            if key.has_private():
                self.private_key = key
                self.public_key = self.private_key.publickey()
            else:
                self.public_key = key
            return True

        except ValueError as error:
            print(f"[-] Error : {error}. Check your password and try again")
            return False

        except FileNotFoundError as error:
            print(f"[-] Error : {error}")
            return False

    def signMsg(self, message):
        """Signs a message with the private key"""

        # Instantiate a new signer object using the senders private key
        signer = pkcs1_15.new(self.private_key)

        # Instantiate a hasher object
        hasher = SHA256.new(message)

        # Sign the message
        signature = signer.sign(hasher)
        print(f"[+] Message signed successfully")

        return signature

    @staticmethod
    def verifySignedMsg(public_key, signature, message):
        """Verifies a signature to see if the message is authentic"""
        # Instantiate a new verifier object; using the senders public key to verify their messages
        verifier = pkcs1_15.new(public_key)

        # Instantiate a hasher object
        hasher = SHA256.new(message)

        # Verify The Message; using the hasher object and the signature received
        try:
            print(f"[*] Verifying message authenticity")
            verifier.verify(hasher, signature)
            print(f"[+] Message authenticated successfully")
            return True

        except ValueError as error:
            print(f"[-] Error : {error}")
            return False

    @staticmethod
    def hashPassword(password):
        # Instantiate a hasher object
        if type(password) != bytes:
            password = password.encode()

        hasher = SHA256.new(password)
        password_hash = hasher.digest()
        return password_hash

    @staticmethod
    def encryptMsg(message, key):
        if type(message) != bytes:
            msg = message.encode("utf-8")
        else:
            msg = message

        try:
            if key.has_private():
                raise AttributeError("[-] Invalid key parameter. Encryption key must be a public key.")

            print(f"[*] Encrypting message")
            cipher = PKCS1_OAEP.new(key)
            encrypted_msg = cipher.encrypt(msg)
            return encrypted_msg

        except AttributeError as error:
            print("[-] Invalid key parameter. Encryption key must be a public key.")
            return

    def decryptMsg(self, encrypted_message):
        try:
            if type(encrypted_message) != bytes:
                raise ValueError("[-] Invalid message format. Message must be in bytes format")
            else:
                encrypted_msg = encrypted_message

            print(f"[*] Decrypting message")
            cipher = PKCS1_OAEP.new(self.private_key)
            decrypted_msg = cipher.decrypt(encrypted_msg)
            return decrypted_msg

        except ValueError as error:
            print(f"[-] Something went wrong.\n"
                  f"\tThe data being decrypted may be corrupted or you may be using the wrong key for decryption")


def loadEnvVars(env_path='encryption.env'):
    env_path = Path(env_path)
    load_dotenv(dotenv_path= env_path)

def Main():
    loadEnvVars()
    PRIVATE_KEY_FILE = os.getenv('PRIVATE_KEY_FILE')
    PASSWORD = os.getenv('PASSWORD')

    encryptor = Encryptor()
    if encryptor.pemLoadKey(key_file_path=PRIVATE_KEY_FILE, pass_phrase=PASSWORD):
        private_key = encryptor.private_key
        public_key = encryptor.public_key
    else:
        private_key, public_key = encryptor.genKeys()
        encryptor.pemSaveKey(key=private_key, key_file_path=PRIVATE_KEY_FILE, pass_phrase=PASSWORD)

    encrypted_msg = encryptor.encryptMsg(message, public_key)
    print(encrypted_msg)
    decrypted_msg = encryptor.decryptMsg(encrypted_msg)
    print(decrypted_msg)


if __name__ == "__main__":
    message = b"My deep dark secrets"

    Main()