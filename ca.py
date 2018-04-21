from utils import generate_safe_prime
import random
from datetime import datetime, timedelta
from Crypto.Hash import SHA
from utils import generate_hash
import pickle
from elgamal import ElGamalDS


class CA:
    __x509_SN = 0
    __VERSION__ = 1
    __BYTES_TO_BITS = 8

    def __init__(self, NBYTES):
        self.q_ca = generate_safe_prime(NBYTES * CA.__BYTES_TO_BITS)
        self.a_ca = random.randint(2, self.q_ca - 1)
        self.__x_ca = random.randint(2, self.q_ca - 1)
        self.y_ca = pow(self.a_ca, self.__x_ca, self.q_ca)

    def generate_x509_certificate(self, issuer_name: str, subject_name: str, issuer_public_key: int,
                                  not_valid_before: datetime, not_valid_after: datetime, hash_type=SHA):
        # Sanity Checks
        if not isinstance(subject_name, str):
            raise TypeError("Subject name should be a string instance")
        if not isinstance(issuer_name, str):
            raise TypeError("Issuer name should be a string instance")
        if not isinstance(issuer_public_key, int):
            raise TypeError("Issuer public key should be an integer instance")
        if not isinstance(not_valid_before, datetime):
            raise TypeError("Not valid before should be an datetime instance")
        if not isinstance(not_valid_after, datetime):
            raise TypeError("Not valid after should be an datetime instance")

        # Generating the certificate
        cert = dict()
        cert['issuer_name'] = issuer_name
        cert['subject_name'] = subject_name
        cert['issuer_public_key'] = issuer_public_key
        cert['serial_number'] = CA.__x509_SN
        cert['not_valid_before'] = not_valid_before
        cert['not_valid_after'] = not_valid_after
        CA.__x509_SN += 1

        # Signing the certificate
        m = generate_hash(pickle.dumps(cert), hash_type)
        signature = ElGamalDS.sign(self.__x_ca, self.a_ca, self.q_ca, m)
        return cert, signature

    def verify_certificate(self, cert: dict, signature: tuple, hash_type=SHA):
        """Verifying the signature"""
        m = generate_hash(pickle.dumps(cert), hash_type)
        return ElGamalDS.verify(self.y_ca, self.a_ca, m, self.q_ca, *signature)
