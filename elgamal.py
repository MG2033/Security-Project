import random
import math


class ElGamalDS:
    def generate(self, x_a, a, q, m):
        """Used to generate a digital signature for a message m using ElGamal Digital Signature Algorithm"""
        # Step 1: Make sure that hash of M satisfies the following condition
        assert 0 <= m <= (q - 1)

        # Step 2: Choose random integer K
        K = random.randint(1, q - 1)
        while math.gcd(K, q - 1) != 1:
            K = random.randint(1, q - 1)

    def verify(self):
        """Used to verify a digital signature for a message m using ElGamal Digital Signature Algorithm"""
        pass
