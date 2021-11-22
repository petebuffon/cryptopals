"""Implement Secure Remote Password (SRP)"""
from secrets import SystemRandom, randbelow
from hashlib import sha256
import hmac

# Define a NIST prime P-192 = 2**192 - 2**64 - 1
N = 627710173538668076383578942320766641608390
g = 2
k = 3

# S
I = "pete@example.com"
P = "password"
salt = SystemRandom().randbytes(8)
xH = sha256(salt + P.encode()).hexdigest()
x = int(xH, 16)
v = pow(g, x, N)

# C->S
a = randbelow(N)
A = pow(g, a, N)

# S->C
b = randbelow(N)
B = (k * v + pow(g, b, N)) % N 

# S, C
AB = A + B
AB = int.to_bytes(AB, (AB.bit_length() + 7) // 8, "big")
uH = sha256(AB).hexdigest()
u = int(uH, 16)

# C
S = pow(B - k * pow(g, x, N), a + u * x, N)
K = sha256(int.to_bytes(S, (S.bit_length() + 7) // 8, "big")).hexdigest()
hmac_c = hmac.digest(K.encode(), salt, "sha256")

# S
S = pow(A * pow(v, u, N), b, N)
K = sha256(int.to_bytes(S, (S.bit_length() + 7) // 8, "big")).hexdigest()
hmac_s = hmac.digest(K.encode(), salt, "sha256")
