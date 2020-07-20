
# coefficients
w, n , m , r = 32, 624, 397, 31
a = b"9908B0DF"
u, d = 11, b"FFFFFFFF"
s, b = 7, b"9D2C5680"
t, c = 15, b"EFC60000"
l = 18
f = 1812433253

MT = []
index = n + 1
lower_mask = (1 << r) - 1
# upper_mask = 


def seed_mt(seed):
    index = n
    MT.append(seed)
    for i in range(1, n):
        MT.append(2147483647 & (f * (MT[i-1] ^ (MT[i-1] >>  (w-2) ))) + i)

