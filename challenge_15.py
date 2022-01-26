"""PKCS#7 padding validation."""


def pkcs7_unpad(padded, keysize):
    """Remove PKCS#7 padding to padded bytes object."""
    last_byte = padded[-1:]
    if last_byte not in [bytes([i]) for i in range(1, 17)]:
        raise ValueError("Invalid PKCS#7 Padding")
    if padded[-last_byte[0]:] == last_byte * last_byte[0]:
        return padded[:-last_byte[0]]
    else:
        raise ValueError("Invalid PKCS#7 Padding")


# pt = b"ICE ICE BABY\x04\x04\x04\x04"
# print(pkcs7_unpad(pt, 16))
