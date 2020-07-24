"""Detect AES in ECB mode."""
from challenge_6 import chunks


def count_repeats(text):
    """Repeats in a list of strings."""
    return len(text) - len(set(text))


class DetectECB:
    """Detects AES-128-ECB encryption."""

    def __init__(self, ciphertexts):
        """List of ciphertexts."""
        self.ciphertexts = ciphertexts
        self.keysize = 16
        self.scores = []
        cnt = 1
        for ciphertext in self.ciphertexts:
            c = chunks(line, self.keysize)
            self.scores.append((cnt, count_repeats(c)))
            cnt += 1
        # most likely ciphertext encrypted with AES-128-ECB
        self.ciphertext = max(self.scores, key=lambda x: x[1])[0]

    def print_scores(self):
        """Print scores for all ciphertexts."""
        print("{:<8} {:<8}".format("Ciphertext", "Score"))
        for k in self.scores:
            print("{:<8} {:<8}".format(k[0], k[1]))

    def print_sorted(self):
        """Print sorted scores for all ciphertexts."""
        sorted_scores = sorted(self.scores, key=lambda x: x[1], reverse=True)
        print("{:<8} {:<8}".format("Ciphertext", "Score"))
        for k in sorted_scores:
            print("{:<8} {:<8}".format(k[0], k[1]))


with open("8.txt", "r") as file:
    ciphertexts = []
    for ciphertext in file:
        ciphertexts.append(bytes.fromhex(ciphertext))

# ecb = DetectECB(ciphertexts)
# ecb.ciphertext
# ecb.print_sorted()
