"""Break fixed-nonce CTR statistically"""
from base64 import b64decode
from challenge_2 import xor
from challenge_11 import generate_bytes
from challenge_18 import CTR

KEY = generate_bytes(16)
NONCE = b"\x00\x00\x00\x00\x00\x00\x00\x00"

ciphertexts = []
with open("20.txt", "r") as file:
    for line in file:
        plaintext = b64decode(line)
        ciphertexts.append(CTR(KEY, NONCE).encrypt(plaintext))


transposed = []
for i in range(0, len(max(ciphertexts, key=len))):
    tmp = b""
    for c in ciphertexts:
        try:
            tmp += bytes([c[i]])
        except IndexError:
            pass
    transposed.append(tmp)


# letter frequency dictionary
etaoin = {
    b"e": 13, b" ": 12, b"t": 11, b"a": 10, b"o": 9, b"i": 8, b"n": 7, b"s": 6, b"h": 5,
    b"r": 4, b"d": 3, b"l": 2, b"u": 1
}


def score_keys(position):
    # iterate through all possible keys
    scores = {}
    for key in range(256):
        key = bytes([key])
        full_key = key * len(position)
        xor_text = xor(position, full_key)

        # update frequency score
        scores[key] = 0
        for c in xor_text:
            if bytes([c]).lower() in etaoin:
                scores[key] += etaoin[bytes([c]).lower()]
            elif bytes([c]).isalnum() is False:
                scores[key] -= 1

    # most likely key
    return max(scores, key=scores.get)


def score_keys_list(position):
    # iterate through all possible keys
    scores = {}
    for key in range(256):
        key = bytes([key])
        full_key = key * len(position)
        xor_text = xor(position, full_key)

        # update frequency score
        scores[key] = 0
        for c in xor_text:
            if bytes([c]).lower() in etaoin:
                scores[key] += etaoin[bytes([c]).lower()]
            elif bytes([c]).isalnum() is False:
                scores[key] -= 1

    # most likely key
    return scores


def print_scores(scores):
    """print scores for all keys"""
    num = 0
    print("{:<12} {:<8}".format("Key", "Score"))
    sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    for score in sorted_scores:
        print("{:<12} {:<8}".format(str(score[0]), score[1]))


keystream = b""
for t in transposed:
    keystream += score_keys(t)

plaintexts = []
for c in ciphertexts:
    n = len(c)
    plaintexts.append(xor(keystream[0:n], c))
