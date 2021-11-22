"""Crack an MT19937 seed"""
import time
import random
from challenge_21 import MT19937


def generate_rand():
  """Generates a seed based on a random timestamp."""
  time.sleep(random.randint(40, 1000))
  timestamp = int(time.time())
  mt = MT19937(timestamp)
  time.sleep(random.randint(40, 1000))
  random_num = mt.extract_number()
  return timestamp, random_num


timestamp, random_num = generate_rand()
print(random_num)
t = int(time.time())
print("Brute force started...")
while True:
  print(f"Trying seed: {t}")
  mt = MT19937(t)
  if mt.extract_number() == random_num:
    print(f"Seed found: {t}")
    break
  t -= 1
