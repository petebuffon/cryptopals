"""Implement CTR, the stream cipher mode"""
from base64 import b64decode
from struct import pack
from challenge_2 import xor
from challenge_6 import chunks
from challenge_7 import ECB


class CTR:
    """Allows encryption or decryption of plaintext/ciphertext using AES-128-CTR"""
    def __init__(self, key, nonce):
        self.key = key
        self.nonce = nonce
    
    def encrypt(self, plaintext):
        counter = 0
        ciphertext = b""
        c = chunks(plaintext, 16)
        for chunk in c:
            n = len(chunk)
            keystream = ECB(self.key).encrypt(self.nonce + pack("Q", counter))
            ciphertext += xor(keystream[0:n], chunk)
            counter += 1
        return ciphertext

    def decrypt(self, ciphertext):
        counter = 0
        plaintext = b""
        c = chunks(ciphertext, 16)
        for chunk in c:
            n = len(chunk)
            keystream = ECB(self.key).encrypt(self.nonce + pack("Q", counter))
            plaintext += xor(keystream[0:n], chunk)
            counter += 1
        return plaintext


ciphertext = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
KEY = b"YELLOW SUBMARINE"
NONCE = b"\x00\x00\x00\x00\x00\x00\x00\x00"

# print(CTR(KEY, NONCE).decrypt(ciphertext))
