"""Detect single-character XOR"""
from challenge_3 import KeyScore
from challenge_2 import xor


class DetectXor:
    """Detects single-character XOR in a list of text"""
    def __init__(self, ciphertext):
        self.ciphertext = ciphertext
        self.scores = []

        # iterate through all lines of ciphertext
        cnt = 0
        for line in self.ciphertext:
            key_score = KeyScore(line)
            self.scores.append((cnt, key_score.score, key_score.decrypt()))
            cnt += 1

        # most likely line
        self.line = max(self.scores, key=lambda x: x[1])[0]

    def print_scores(self):
        """print scores for all lines"""
        print("{:<8} {:<12}".format("Line", "Score"), end="")
        print("Decrypted Text")
        for line in self.scores:
            print("{:<8} {:<12}".format(line[0], line[1]), end="")
            print(line[2])

    def print_sorted(self):
        """print sorted scores for all lines"""
        sorted_scores = sorted(self.scores, key=lambda x: x[1], reverse=True)
        print("{:<8} {:<12}".format("Line", "Score"), end="")
        print("Decrypted Text")
        for line in sorted_scores:
            print("{:<8} {:<12}".format(line[0], line[1]), end="")
            print(line[2])


with open("4.txt", "r") as file:
    ciphertext = []
    for line in file:
        ciphertext.append(bytes.fromhex(line))

detect_xor = DetectXor(ciphertext)
# print(detect_xor.line)
