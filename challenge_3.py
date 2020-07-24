"""Single-byte XOR cipher."""
from challenge_2 import xor


class KeyScore:
    """Uses letter frequency analysis to break single-character xor."""

    def __init__(self, ciphertext):
        """Ciphertext to analyze for most likely single-character xor key."""
        self.ciphertext = ciphertext
        self.scores = {}

        # letter frequency dictionary
        etaoin = {
            b"e": 13, b" ": 12, b"t": 11, b"a": 10, b"o": 9, b"i": 8, b"n": 7, b"s": 6, b"h": 5,
            b"r": 4, b"d": 3, b"l": 2, b"u": 1
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
                elif bytes([c]).isalnum() is False:
                    self.scores[key] -= 1

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


ciphertext = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
key_score = KeyScore(ciphertext)
# print(key_score.key)
# print(key_score.decrypt())
