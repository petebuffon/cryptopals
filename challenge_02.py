"""Fixed XOR."""
import sys


def xor(buffer1, buffer2):
    if len(buffer1) != len(buffer2):
        return sys.exit("buffers must be of equal length")
    try:
        return bytearray([c1 ^ c2 for c1, c2 in zip(buffer1, buffer2)])
    except TypeError:
        sys.exit("Buffers must be Byte objects")


# buffer1 = bytes.fromhex('1c0111001f010100061a024b53535009181c')
# buffer2 = bytes.fromhex('686974207468652062756c6c277320657965')
# print(xor(buffer1, buffer2).hex())
