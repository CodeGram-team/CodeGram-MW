# tests/sample_safe.py
import math
from typing import List

def primes_upto(n: int) -> List[int]:
    """Return primes up to n (simple sieve)."""
    if n < 2:
        return []
    sieve = [True] * (n + 1)
    sieve[0:2] = [False, False]
    for i in range(2, int(n**0.5) + 1):
        if sieve[i]:
            for j in range(i*i, n+1, i):
                sieve[j] = False
    return [i for i, v in enumerate(sieve) if v]

if __name__ == "__main__":
    print("First 10 primes:", primes_upto(30))