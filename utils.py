import gmpy
import Crypto.Util.number as number
from Crypto.Hash import SHA
from elgamal import ElGamalDS
import pickle


def generate_safe_prime(nbits):
    """ Finds a safe prime of nbits using probabilistic method rather than deterministic;
    because a large prime number is required. """
    q = gmpy.mpz(number.getRandomNBitInteger(nbits))
    while not gmpy.is_prime(q):
        q = gmpy.next_prime(q)
    return q


def generate_hash(M, hash_type=SHA):
    m = hash_type.new()
    # Hash library works only on bytes, so we have to convert the integer into string of bytes.
    m.update(str(M).encode("ASCII"))
    return int(m.hexdigest(), 16)


def verify_certificate(cert: dict, signature: tuple, y_ca, a_ca, q_ca, hash_type=SHA):
    """Verifying the signature"""
    m = generate_hash(pickle.dumps(cert), hash_type)
    return ElGamalDS.verify(y_ca, a_ca, m, q_ca, *signature)
