from utils import generate_safe_prime
import math
import random
import gmpy


class RSA:
    def __init__(self, rsa_key_bits):
        # Alice and Bob RSA parameters
        self.__p_rsa = generate_safe_prime(rsa_key_bits)
        self.__q_rsa = generate_safe_prime(rsa_key_bits)

        self.n_rsa = self.__p_rsa * self.__q_rsa
        self.__phi_n_rsa = (self.__p_rsa - 1) * (self.__q_rsa - 1)

    def generate_key_pair(self):
        e = random.randint(2, self.__phi_n_rsa)
        while math.gcd(e, self.__phi_n_rsa) != 1:
            e = random.randint(2, self.__phi_n_rsa)
        d = int(gmpy.invert(e, self.__phi_n_rsa))
        return d, e, self.n_rsa

    def encrypt(self, e, m):
        return pow(m, e, self.n_rsa)

    def decrypt(self, c, d):
        return pow(c, d, self.n_rsa)


# Test Drive
# rsa = RSA(512)
# print(rsa.generate_key_pair())
