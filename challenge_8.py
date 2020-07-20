"""Detect AES in ECB mode"""
from challenge_6 import chunks


def count_repeats(text):
    """counts number of repeats in a list of strings"""
    return len(text) - len(set(text))


class DetectECB:
    """Detects ciphertext encrypted with AES-128-ECB in a list of text"""
    def __init__(self, ciphertext):

        self.ciphertext = ciphertext
        self.keysize = 16
        self.scores = []
        cnt = 1
        for line in self.ciphertext:
            c = chunks(line, self.keysize)
            self.scores.append((cnt, count_repeats(c)))
            cnt += 1
        # most likely line encrypted with AES-128-ECB
        self.line = max(self.scores, key=lambda x: x[1])[0]

    def print_scores(self):
        """print scores for all lines"""
        print("{:<8} {:<8}".format("Line", "Score"))
        for k in self.scores:
            print("{:<8} {:<8}".format(k[0], k[1]))

    def print_sorted(self):
        """print sorted scores for all lines"""
        sorted_scores = sorted(self.scores, key=lambda x: x[1], reverse=True)
        print("{:<8} {:<8}".format("Line", "Score"))
        for k in sorted_scores:
            print("{:<8} {:<8}".format(k[0], k[1]))


with open("8.txt", "r") as file:
    ciphertext = []
    for line in file:
        ciphertext.append(bytes.fromhex(line))

# ecb = DetectECB(ciphertext)
# ecb.line
# ecb.print_sorted()
