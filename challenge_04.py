"""Detect single-character XOR."""
from challenge_03 import KeyScore
from challenge_02 import xor


class DetectXor:
    """Detects single-character XOR."""

    def __init__(self, ciphertexts):
        """List of ciphertexts."""
        self.ciphertexts = ciphertexts
        self.scores = []

        # iterate through all lines of ciphertext
        cnt = 0
        for ciphertext in self.ciphertexts:
            key_score = KeyScore(ciphertext)
            self.scores.append((cnt, key_score.score, key_score.decrypt()))
            cnt += 1

        # most likely line
        self.ciphertext = max(self.scores, key=lambda x: x[1])[0]

    def print_scores(self):
        """Print scores for all ciphertexts."""
        print("{:<8} {:<12}".format("Ciphertext", "Score"), end="")
        print("Decrypted Text")
        for ciphertext in self.scores:
            print("{:<8} {:<12}".format(ciphertext[0], ciphertext[1]), end="")
            print(ciphertext[2])

    def print_sorted(self):
        """Print sorted scores for all lines."""
        sorted_scores = sorted(self.scores, key=lambda x: x[1], reverse=True)
        print("{:<8} {:<12}".format("Ciphertext", "Score"), end="")
        print("Decrypted Text")
        for ciphertext in sorted_scores:
            print("{:<8} {:<12}".format(ciphertext[0], ciphertext[1]), end="")
            print(ciphertext[2])


with open("4.txt", "r") as file:
    ciphertexts = []
    for ciphertext in file:
        ciphertexts.append(bytes.fromhex(ciphertext))

detect_xor = DetectXor(ciphertexts)
# print(detect_xor.ciphertext)
