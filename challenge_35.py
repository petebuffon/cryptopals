"""Implement DH with negotiated groups, and break with malicious "g" parameters"""
import os
from secrets import randbits
from challenge_34 import generate_key

bits = 1536
p = ("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA"
    "63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C24"
    "5E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BF5A899FA5AE9F2411"
    "7C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08"
    "CA237327FFFFFFFFFFFFFFFF")
p = int(p, 16)

for g in [1, p, p - 1]:
    a = randbits(bits)
    A = pow(g, a, p)
    b = randbits(bits)
    s = pow(A, b, p)
    # print(f"g: {g}, s: {s}, key: {generate_key(s)}")

# When g equals 1, s will always equal 1
# when g = p, s will always equal 1
# when g = p -1, s will always equal 0
# the key can be easily found by hashing either 0 or 1
