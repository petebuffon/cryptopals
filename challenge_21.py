"""Implement the MT19937 Mersenne Twister RNG"""


class MT19937():
    """Implementation of the MT19937 Mersenne Twister."""
    def __init__(self, seed):
        self.w, self.n, self.r, self.m, self.a = 32, 624, 31, 397, 0x9908b0df
        self.b, self.c, self.d = 0x9d2c5680, 0xefc60000, 0xffffffff
        self.f, self.s, self.t, self.u, self.l = 1812433253, 6, 15, 11, 18
        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = 0x80000000
        self.index = self.n
        self.MT = self.seed_mt(seed)

    def seed_mt(self, seed):
        """Initialize the generator from a seed."""
        MT = []
        MT.append(seed)
        for i in range(1 , self.n):
            MT.append((self.f * (MT[i-1] ^ (MT[i-1] >> (self.w-2))) + i) & 0xffffffff)
        return MT

    def extract_number(self):
        """Extract a tempered value calling twist() every n numbers."""
        if self.index >= self.n:
            index = self.twist()

        y = self.MT[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)

        self.index += 1
        return y & 0xffffffff

    def twist(self):
        """Generate the next n values from the series x_i."""
        for i in range(self.n):
            x = (self.MT[i] & self.upper_mask) + (self.MT[(i+1) % self.n] & self.lower_mask)
            xA = x >> 1
            if (x % 2) != 0:  # lowest bit of x is 1
                xA = xA ^ self.a
            self.MT[i] = self.MT[(i+self.m) % self.n] ^ xA
        self.index = 0
