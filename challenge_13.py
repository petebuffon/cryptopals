"""ECB cut-and-paste."""
from challenge_7 import ECB
from challenge_9 import pkcs7
from challenge_11 import generate_bytes


def parser(ciphertext):
    """Decrypt and parse ciphertext."""
    encodedtext = ECB(KEY).decrypt(ciphertext)
    encodedtext = strip_padding(encodedtext).decode("utf-8")
    cookie_dict = {}
    for pair in encodedtext.split("&"):
        kv = pair.split("=")
        cookie_dict[kv[0]] = kv[1]
    return cookie_dict


def strip_padding(plaintext):
    """Strip PKCS#7 padding from plaintext."""
    pad_chrs = b""
    for i in range(1, 16):
        pad_chrs += bytes([i])
    stripped = b""
    for c in plaintext:
        if c not in pad_chrs:
            stripped += bytes([c])
    return stripped


def profile_for(email):
    """Generate profile from email."""
    email = email.replace("&", "").replace("=", "").encode("utf-8")
    return b"email=" + email + b"&uid=10&role=user"


def encryption_oracle(email):
    """Encryption oracle with email input."""
    plaintext = profile_for(email)
    plaintext = pkcs7(plaintext, 16)
    ciphertext = ECB(KEY).encrypt(plaintext)
    return ciphertext


def decrypt(ciphertext):
    """Decrypt ECB encrypted ciphertext."""
    plaintext = ECB(KEY).decrypt(ciphertext)
    return plaintext


KEY = generate_bytes(16)

# block_1: email=foo@gmail.
# block_2: com&uid=10&role=
# block_3: admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b
# "email=" len = 6

# generate admin profile with 13 character email address
block_1 = encryption_oracle("foo@gmail.com")[0:16]
block_2 = encryption_oracle("foo@gmail.com")[16:32]
block_3 = encryption_oracle("A"*10+"admin"+"\x0b"*11)[16:32]
ciphertext = block_1 + block_2 + block_3
# print(parser(ciphertext))
