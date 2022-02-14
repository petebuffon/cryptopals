"""CTR bitflipping"""
from os import urandom
from challenge_02 import xor
from challenge_18 import CTR


def generate_token(your_string):
    """Quote out ';' and '=', then encrypt with CTR."""
    plaintext = "comment1=cooking%20MCs;userdata=" + your_string
    plaintext += ";comment2=%20like%20a%20pound%20of%20bacon"
    plaintext = plaintext.replace(";", "").replace("=", "").encode("utf-8")
    ciphertext = CTR(KEY, NONCE).encrypt(plaintext)
    return ciphertext


def admin_check(ciphertext):
    """Check for ';admin=true;' in ciphertext."""
    plaintext = CTR(KEY, NONCE).decrypt(ciphertext)
    if b";admin=true;" in plaintext:
        return True
    else:
        return False


KEY = urandom(16)
NONCE = urandom(8)
insert_text = b";admin=true;"
# token position for text insert minus ';' and '=' characters
insert_start = len("comment1=cooking%20MCs;userdata=") - 3
# insert text end position
insert_end = insert_start + len(insert_text)
# known text to insert
plaintext = "A" * len(insert_text)
token = generate_token(plaintext)
ciphertext = token[insert_start:insert_end]
# bit flip = ciphertext ^ plaintext ^ insert text
token = token[:insert_start] + xor(xor(ciphertext, plaintext.encode()), insert_text) + token[insert_end:]
print(admin_check(token))
