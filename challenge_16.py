"""CBC bitflipping attacks."""
from challenge_9 import pkcs7
from challenge_10 import CBC
from challenge_11 import generate_bytes


def encryption_oracle(your_string):
    """Encryption oracle with text input."""
    plaintext = "comment1=cooking%20MCs;userdata=" + your_string
    plaintext += ";comment2=%20like%20a%20pound%20of%20bacon"
    plaintext = plaintext.replace(";", "").replace("=", "").encode("utf-8")
    ciphertext = CBC(KEY, IV).encrypt(pkcs7(plaintext, 16))
    return ciphertext


def admin_check(ciphertext):
    """Check for ';admin=true;' in ciphertext."""
    plaintext = CBC(KEY, IV).decrypt(ciphertext)
    if b";admin=true;" in plaintext:
        return True
    else:
        return False


def insert_text(text):
    """Insert text using encryption oracle."""
    ciphertext = encryption_oracle("")
    plaintext = "comment1cooking%20MCsuserdatacomment2%20like%20a%20pound%20of%20bacon"
    inserted_text = b""
    for i in range(len(text)):
        inserted_text += bytes([ciphertext[i] ^ ord(plaintext[i+16]) ^ ord(text[i])])
    return inserted_text + ciphertext[len(inserted_text):]


ciphertext = encryption_oracle("*admin*true*")
plaintext = "comment1cooking%20MCsuserdata*admin*true*comment2%20like%20a%20pound%20of%20bacon"
KEY = generate_bytes(16)
IV = generate_bytes(16)

ciphertext = insert_text(";admin=true;")
print(admin_check(ciphertext))
