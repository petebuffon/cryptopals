"""Implement PKCS#7 padding."""


def pkcs7_pad(pt, keysize):
    """Add PKCS#7 padding to plaintext bytes object."""
    if len(pt) < keysize:
        pad = keysize - len(pt)
    elif len(pt) % keysize == 0:
        pad = keysize
    else:
        pad = keysize - len(pt) % keysize
    return pt + bytes([pad]) * pad


# pt = pkcs7_pad(pt, keysize)
# print(pt)
