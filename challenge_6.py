"""Break repeating-key XOR"""
from challenge_2 import xor
from challenge_3 import KeyScore
import base64


def edit_distance(buffer1, buffer2):
    """
    Calculate edit distance between two buffers.
    >>> edit_distance(b"this is a test", b"wokka wokka!!!")
    >>> 37
    """
    hamm = xor(buffer1, buffer2)
    cnt = 0
    for byte in hamm:
        cnt += bin(byte).count("1")
    return cnt


class KeySize:
    """Calculates most likely keysize from ciphertext and keyrange"""
    def __init__(self, ciphertext, keyrange):
        self.ciphertext = ciphertext
        self.keyrange = keyrange
        # dict of keysizes and scores
        self.keysizes = {}
        for i in self.keyrange:
            self.keysizes[i] = self.score_keysize(i)
        # most likely keysize
        self.keysize = min(self.keysizes, key=self.keysizes.get)

    def score_keysize(self, keysize):
        """score keysize based on neighboring chunk edit distance"""
        sum = 0
        cnt = 0
        for i in range(0, len(self.ciphertext) - 2 * keysize, keysize):
            sum += edit_distance(self.ciphertext[i:i+keysize], self.ciphertext[i+keysize:i+keysize*2]) / keysize
            cnt += 1
        return sum / cnt

    def print_scores(self):
        """print scores for all keysizes in keyrange"""
        sorted_keysizes = sorted(self.keysizes.items(), key=lambda x: x[1])
        print("{:<8} {:<8}".format("Keysize", "Edit Distance"))
        for k in sorted_keysizes:
            print("{:<8} {:<8}".format(k[0], k[1]))


def chunks(ciphertext, keysize):
    """separate text into keysize chunks (list of chunks)"""
    chunks = []
    for i in range(0, len(ciphertext), keysize):
        chunks.append(ciphertext[i: i + keysize])
    return chunks


def transpose(chunks, keysize):
    """transpose list of chunks into a list of chunks associated with each character of a given
    keysize"""
    transposed = []
    for i in range(keysize):
        transposed.append(b'')
    for chunk in chunks:
        for j in range(len(chunk)):
            transposed[j] += bytes([chunk[j]])
    return transposed


class BruteXor:
    """Brute force ciphertext encrypted with repeating-key XOR"""
    def __init__(self, ciphertext, keyrange):
        self.ciphertext = ciphertext
        self.keyrange = keyrange
        self.keysize = KeySize(self.ciphertext, self.keyrange).keysize
        self.chunks = chunks(self.ciphertext, self.keysize)
        self.transposed = transpose(self.chunks, self.keysize)
        self.key = b""
        for chunk in self.transposed:
            self.key += KeyScore(chunk).key
        n = len(self.ciphertext)
        k = self.keysize
        self.full_key = n // k * self.key + self.key[:n % k]
        # decrypted plaintext
        self.plaintext = xor(self.full_key, self.ciphertext)

    def print_plaintext(self):
        """plaintext line by line, decoded into strings"""
        for line in self.plaintext.decode("utf-8").split("\n"):
            print(line)


with open("6.txt", "r") as file:
    ciphertext = file.read()
    ciphertext = base64.b64decode(ciphertext)

brute_xor = BruteXor(ciphertext, range(2, 41))
