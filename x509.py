from OpenSSL import crypto
from utils import generate_safe_prime
import random


class CA:
    def __init__(self, NBYTES):
        self.__x509_SN = 0
        BYTES_TO_BITS = 8

        self.q_ca = generate_safe_prime(NBYTES * BYTES_TO_BITS)
        self.a_ca = random.randint(2, self.q_ca - 1)
        self.__x_ca = random.randint(2, self.q_ca - 1)
        self.y_ca = pow(self.a_ca, self.__x_ca, self.q_ca)

    def generate_x509_certificate(self, issuer_name, issuer_id, issuer_public_key, start_time=0, end_time=100000):
        cert = crypto.X509()
        cert.set_serial_number(self.__x509_SN)
        cert.set_issuer(issuer_name + str(issuer_id))
        cert.set_pubkey(issuer_public_key)
        cert.gmtime_adj_notBefore(start_time)
        cert.gmtime_adj_notAfter(end_time)
        cert.sign(self.__x_ca, b'sha1')
