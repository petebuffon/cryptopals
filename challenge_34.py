"""Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection"""
import os
from secrets import randbits
from hashlib import sha1
from challenge_09 import pkcs7_pad
from challenge_10 import CBC
from challenge_15 import pkcs7_unpad


def send_msg(key, msg):
    """Sends message using key."""
    iv = os.urandom(16)
    msg = pkcs7_pad(msg.encode(), 16)
    ct = CBC(bytes.fromhex(key)[:16], iv).encrypt(msg)
    return (ct + iv).hex()


def receive_msg(key, msg):
    """Receives message using key and ciphertext."""
    iv = bytes.fromhex(msg)[-16:]
    ct = bytes.fromhex(msg)[:-16]
    padded = CBC(bytes.fromhex(key)[:16], iv).decrypt(ct)
    pt = pkcs7_unpad(padded, 16)
    return pt.decode()


def generate_key(s):
    """Generates key based on paramter s."""
    return sha1(int.to_bytes(s, (s.bit_length() + 7) // 8, "big")).hexdigest()


bits = 1536
p = ("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA"
    "63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C24"
    "5E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BF5A899FA5AE9F2411"
    "7C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08"
    "CA237327FFFFFFFFFFFFFFFF")
p = int(p, 16)
g = 2

# A->M
# Send "p", "g", "A"
a = randbits(bits)
A = pow(g, a, p)

# M->B
# Send "p", "g", "p"

# B->M
# Send "B"
b = randbits(bits)
B = pow(g, b, p)
# B will always calculate s = 0
s = pow(p, b, p)
key = generate_key(s)

# M->A
# Send "p"

# A->M
# when p is swapped for A and B, s always equals 0
s = pow(p, a, p)
msg_AB = send_msg(key, "secret message from A")
# print(receive_msg(key, msg_AB))

# M->B
# Relay that to B

# B->M
msg_BA = send_msg(key, "secret message from B")
# print(receive_msg(key, msg_BA))

# M->A
# Relay that to A
