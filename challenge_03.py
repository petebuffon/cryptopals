"""Single-byte XOR cipher."""
from challenge_02 import xor
from string import printable


class KeyScore:
    """Uses letter frequency analysis to break single-character xor."""

    def __init__(self, ciphertext):
        """Ciphertext to analyze for most likely single-character xor key."""
        self.ciphertext = ciphertext
        self.scores = {}

        # letter frequency dictionary
        etaoin = {
            b"a": 8.2, b"b": 1.5, b"c": 2.8, b"d": 4.3, b"e": 13, b"f": 2.2,
            b"g": 2, b"h": 6.1, b"i": 7, b"j": 0.15, b"k": 0.77, b"l": 4,
            b"m": 2.5, b"n": 6.7, b"o": 7.5, b"p": 1.9, b"q": 0.095, b"r": 6,
            b"s": 6.3, b"t": 9.1, b"u": 2.8, b"v": 0.98, b"w": 2.4,
            b"x": 0.15, b"y": 2, b"z": 0.074
        }

        # iterate through all possible keys
        for key in range(256):
            key = bytes([key])
            full_key = key * len(self.ciphertext)
            xor_text = xor(self.ciphertext, full_key)

            # update frequency score
            self.scores[key] = 0
            for c in xor_text:
                if bytes([c]).lower() in etaoin:
                    self.scores[key] += etaoin[bytes([c]).lower()]
                elif bytes([c]) not in printable.encode():
                    self.scores[key] -= 100

        # most likely key
        self.key = max(self.scores, key=self.scores.get)
        self.score = self.scores[self.key]

    def print_scores(self):
        """Print scores for all keys."""
        num = 0
        print("{:<8} {:<12} {:<8}".format("Num", "Key", "Score"))
        for k, v in self.scores.items():
            print("{:<8} {:<12} {:<8}".format(num, str(k), v))
            num += 1

    def decrypt(self):
        """Decrypt plaintext using brute force."""
        return xor(self.ciphertext, self.key * len(self.ciphertext))


# ciphertext = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
# key_score = KeyScore(ciphertext)
# print(key_score.key)
# print(key_score.decrypt())
