"""Implement CBC mode"""
from challenge_2 import xor
from challenge_7 import ECB
from challenge_6 import chunks
import base64


class CBC(ECB):
    """Allows encryption or decryption of plaintext/ciphertext using AES-128-CBC"""
    def __init__(self, key, iv):
        super().__init__(key)
        self.iv = iv
        self.keysize = 16

    def encrypt(self, plaintext):
        """encrypt ciphertext with key using AES-128-CBC"""
        p = chunks(plaintext, self.keysize)
        c = super().encrypt(xor(p[0], self.iv))
        ciphertext = c
        for chunk in p[1:]:
            c1 = super().encrypt(xor(c, chunk))
            ciphertext += c1
            c = c1
        return ciphertext

    def decrypt(self, ciphertext):
        """decrypt ciphertext with key using AES-128-CBC"""
        c = chunks(ciphertext, self.keysize)
        plaintext = xor(super().decrypt(c[0]), self.iv)
        for i in range(0, len(c)-1):
            plaintext += xor(c[i], super().decrypt(c[i+1]))
        return plaintext


key = b"YELLOW SUBMARINE"
keysize = 16
iv = b"\x00" * keysize

with open("10.txt", "r") as file:
    ciphertext = file.read()
    ciphertext = base64.b64decode(ciphertext)

plaintext = CBC(key, iv).decrypt(ciphertext).decode("utf-8")
# for line in plaintext.split("\n"):
#    print(line)
