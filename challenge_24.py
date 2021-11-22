"""Create the MT19937 stream cipher and break it"""
import random
import queue
import time
from challenge_21 import MT19937


def rnd_iter(mt):
	"""Keystream of """
	q = queue.Queue()
	while True:
		tmp = mt.extract_number().to_bytes(4, "big")
		for _byte in tmp:
			q.put(_byte)
		while not q.empty():
			yield q.get()


def get_bytes(key, n):
	mt = MT19937(key)
	_bytes = bytes(next(rnd_iter(mt)) for _ in range(n))
	return _bytes


def encrypt(plaintext, seed):
	mt = MT19937(seed)
	ciphertext = bytes(char ^ next(rnd_iter(mt)) for char in plaintext)
	return ciphertext


def decrypt(ciphertext, seed):
	mt = MT19937(seed)
	plaintext = bytes(char ^ next(rnd_iter(mt)) for char in ciphertext)
	return plaintext


"""
key = random.randint(1, 65535)
plaintext = bytes(random.randint(1,255) for _ in range(random.randint(1,100))) + b"A" * 14
ciphertext = encrypt(plaintext, key)

print("Brute force started...")
for key in range(1, 65535):
	print(f"Trying key: {key}")
	if plaintext == decrypt(ciphertext, key):
		print(f"Key found! {key}")
		break
"""

time.sleep(random.randint(1, 300))
key = int(time.time())
password_token = get_bytes(key, 32)

t = int(time.time())
print("Brute force started...")
for key in range(t, t - 300, -1):
	print(f"Trying key: {key}")
	if password_token == get_bytes(key, len(password_token)):
		print("Password token product of MT19937 PRNG seeded with timestamp from last 300 seconds.")
		print(f"Key found! {key}")
		break
