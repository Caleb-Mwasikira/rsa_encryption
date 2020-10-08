#!/usr/bin/env python
# -*- coding:utf-8 -*-

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP


class RSAEncryption:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    @staticmethod
    def genKeys():
        print(f"[+] Generating new pair of private and public keys")
        BITS = 2048
        private_key = RSA.generate(BITS)
        public_key = private_key.publickey()
        return private_key, public_key

    @staticmethod
    def pemSaveKey(key, key_file_path, password):
        """Storing an encrypted key onto a .pem file"""

        with open(key_file_path, "wb") as f:
            f.write(key.export_key(format="PEM", passphrase=password, pkcs=8))
        print(f"[+] Key successfully saved on file {key_file_path}")

    def pemLoadKey(self, key_file_path, password):
        """Loading an encrypted key from a .pem file"""
        try:
            print(f"[*] Loading key from file {key_file_path}")

            with open(key_file_path, "rb") as f:
                data = f.read()
                key = RSA.import_key(data, passphrase=password)

            if key.has_private():
                self.private_key = key
                self.public_key = self.private_key.publickey()
            else:
                self.public_key = key

            print(f"[+] Key successfully imported from file")
            return key

        except ValueError as error:
            print(f"[-] Error: {error}")
            return False

        except FileNotFoundError as error:
            print(f"[-] Error : {error}")
            return False

    @staticmethod
    def signMsg(msg, private_key):
        """Signs a message with the private key"""

        # Instantiate a new signer object using the senders private key
        signer = pkcs1_15.new(private_key)

        # Instantiate a hasher object
        hasher = SHA256.new(msg)

        # Sign the message
        signature = signer.sign(hasher)
        print(f"[+] Message signed successfully")

        return signature

    @staticmethod
    def verifySignedMsg(msg, signature, public_key):
        """Verifies a signature to see if the message is authentic"""
        try:
            print(f"[*] Verifying message authenticity")
            # Instantiate a new verifier object using the senders public key
            verifier = pkcs1_15.new(public_key)
            hasher = SHA256.new(msg)

            verifier.verify(hasher, signature)
            print(type(public_key))
            print(f"[+] Message authenticated successfully")
            return True

        except ValueError as error:
            print(f"[-] Error : {error}")
            return False

    @staticmethod
    def hashPassword(password):
        if type(password) != bytes:
            password = password.encode("utf-8")

        hasher = SHA256.new(password)
        password_hash = hasher.digest()
        return password_hash

    @staticmethod
    def encryptMsg(plain_text, public_key):
        try:
            print(f"[*] Encrypting message")
            if type(plain_text) != bytes:
                plain_text = plain_text.encode("utf-8")

            cipher = PKCS1_OAEP.new(public_key)
            cipher_text = cipher.encrypt(plain_text)
            print(f"[+] Message encrypted successfully")
            return cipher_text

        except AttributeError as err:
            print(f"[-] Error: {err}")
            return False

    @staticmethod
    def decryptMsg(cipher_text, private_key):
        try:
            print(f"[*] Decrypting message")
            cipher = PKCS1_OAEP.new(private_key)
            plain_text = cipher.decrypt(cipher_text)
            return plain_text

        except ValueError as error:
            print(f"[-] Error: {error}")
            return False


def Main():
    message = b"My deep dark secrets"

    private_key_file = "./keys/private_key.pem"
    public_key_file = "./keys/public_key.pem"
    password = "Sixteen byte keys"

    rsa_encryptor = RSAEncryption()
    private_key = rsa_encryptor.pemLoadKey(private_key_file, password)

    if private_key:
        public_key = rsa_encryptor.public_key
    else:
        private_key, public_key = rsa_encryptor.genKeys()
        rsa_encryptor.pemSaveKey(private_key, private_key_file, password)
        rsa_encryptor.pemSaveKey(public_key, public_key_file, password)

    cipher_text = rsa_encryptor.encryptMsg(message, public_key)
    print(cipher_text)

    plain_text = rsa_encryptor.decryptMsg(cipher_text, private_key)
    print(plain_text)

    sig = rsa_encryptor.signMsg(message, private_key)
    rsa_encryptor.verifySignedMsg(message, sig, public_key)


if __name__ == "__main__":
    Main()
