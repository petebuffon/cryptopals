"""Fixed XOR."""
import sys


def xor(buffer1, buffer2):
    """Bitwise XOR."""
    if len(buffer1) != len(buffer2):
        print("Buffers must be of equal length")
        return exit(1)
    xor = b''
    try:
        for i in range(len(buffer1)):
            xor += bytes([buffer1[i] ^ buffer2[i]])
    except TypeError:
        print("Buffers must be Byte objects")
        return exit(1)
    return xor


buffer1 = bytes.fromhex('1c0111001f010100061a024b53535009181c')
buffer2 = bytes.fromhex('686974207468652062756c6c277320657965')

# print(xor(buffer1, buffer2).hex())
