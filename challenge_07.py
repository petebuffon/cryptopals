"""AES in ECB mode."""
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class ECB:

    def __init__(self, key):
        """Allows encryption or decryption of plaintext/ciphertext using AES-128-ECB."""
        self.cipher = Cipher(algorithms.AES(key), modes.ECB())

    def encrypt(self, plaintext):
        """Encrypt ciphertext with key using AES-128-ECB."""
        encryptor = self.cipher.encryptor()
        # return encryptor.update(plaintext) + encryptor.finalize()
        return encryptor.update(plaintext)
    
    def decrypt(self, ciphertext):
        """Decrypt ciphertext with key using AES-128-ECB."""
        decryptor = self.cipher.decryptor()
        return decryptor.update(ciphertext)


with open("7.txt", "r") as file:
    ciphertext = file.read()
    ciphertext = base64.b64decode(ciphertext)

# key = b"YELLOW SUBMARINE"
# plaintext = ECB(key).decrypt(ciphertext).decode("utf-8")
# for line in plaintext.split("\n"):
#    print(line)
