"""The CBC padding oracle."""
from os import urandom
from secrets import choice
from challenge_09 import pkcs7_pad
from challenge_10 import CBC


def padding_oracle():
    """Padding oracle."""
    plaintexts = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    ]
    plaintext = plaintexts[choice(range(len(plaintexts)))].encode("utf-8")
    return CBC(KEY, IV).encrypt(pkcs7_pad(plaintext, 16))


def padding_validation(ciphertext):
    """PKCS#7 padding validation."""
    plaintext = CBC(KEY, IV).decrypt(ciphertext)[::-1]
    # valid padding
    for i in range(1, 17):
        if plaintext[0:i] == bytes([i]) * i:
            return True
    return False


def attack_block(ciphertext):
    """Attack block using side-channel leak in padding oracle."""
    c2 = ciphertext[16:32]
    plaintext = b""
    dc_string = b""
    h = 15
    for i in range(1, 17):
        for j in range(256):
            c1 = b"A"*h + bytes([j])
            if dc_string:
                for c in dc_string[::-1]:
                    c1 += bytes([c ^ i])
            if padding_validation(c1 + c2):
                dc = j ^ i
                dc_string += bytes([dc])
                plaintext += bytes([dc ^ ciphertext[h]])
                break
        h -= 1
    return plaintext[::-1]


# IV = urandom(16)
# KEY = urandom(16)

# ciphertext = IV + padding_oracle()
# plaintext = b""

# for i in range(0, len(ciphertext)-16, 16):
#     plaintext += attack_block(ciphertext[i:i+32])
# print(plaintext)
