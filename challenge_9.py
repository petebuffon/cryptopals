"""Implement PKCS#7 padding."""


def pkcs7(plaintext, keysize):
    """Add PKCS#7 padding to plaintext bytes object."""
    if len(plaintext) < keysize:
        pad = keysize - len(plaintext)
    elif len(plaintext) % keysize == 0:
        pad = keysize
    else:
        pad = keysize - len(plaintext) % keysize

    return plaintext + bytes([pad]) * pad


# plaintext = pkcs7(plaintext, keysize)
# print(plaintext)
