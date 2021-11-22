"""Clone an MT19937 RNG from its output"""
from challenge_22 import MT19937


class ClonedMT19937():
	"""Cloned instance of a MT19937 Mersenne Twister;"""
	def __init__(self, rnds):
		self.w, self.n, self.r, self.m, self.a = 32, 624, 31, 397, 0x9908b0df
		self.b, self.c, self.d = 0x9d2c5680, 0xefc60000, 0xffffffff
		self.f, self.s, self.t, self.u, self.l = 1812433253, 6, 15, 11, 18
		self.lower_mask = (1 << self.r) - 1
		self.upper_mask = 0x80000000
		self.index = self.n
		self.MT = self.generate_mt(rnds)

	def reverse_rxorshift(self, tempered, shift):
		"""Reverses right xor shift."""
		y = tempered
		initial_mask = ((1 << shift) - 1) << self.w - shift
		for i in range(0, self.w, shift):
			mask = initial_mask >> i
			tmp = y & mask
			y ^= tmp >> shift
		return y

	def reverse_lxorshift(self, tempered, shift, coeff):
		"""Reverses left xor shift."""
		y = tempered
		initial_mask = (1 << shift) - 1
		for i in range(0, self.w, shift):
			mask = initial_mask << i
			tmp = y & mask
			y ^= ((tmp << shift) & coeff)
		return y

	def untemper(self, y):
		"""Untemper function."""
		y = self.reverse_rxorshift(y, self.l)
		y = self.reverse_lxorshift(y, self.t, self.c)
		y = self.reverse_lxorshift(y, self.s, self.b)
		y = self.reverse_rxorshift(y, self.u)
		return y

	def generate_mt(self, rnds):
		"""Initialize generator from list of rnds."""
		MT = [self.untemper(rnd) for rnd in rnds]
		return MT

	def extract_number(self):
		"""Extract tempered value calling twist() every n numbers."""
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


mt = MT19937(5489)
rnds = [mt.extract_number() for _ in range(624)]
clone = ClonedMT19937(rnds)
