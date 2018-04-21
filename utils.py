import gmpy
import Crypto.Util.number as number
from Crypto.Hash import SHA


def generate_safe_prime(nbits):
    """ Finds a safe prime of nbits using probabilistic method rather than deterministic;
    because a large prime number is required. """
    q = gmpy.mpz(number.getRandomNBitInteger(nbits))
    while not gmpy.is_prime(q):
        q = gmpy.next_prime(q)
    return q


def generate_sha_hash(M):
    m = SHA.new()
    # Hash library works only on bytes, so we have to convert the integer into string of bytes.
    m.update(str(M).encode("ASCII"))
    return int(m.hexdigest(), 16)
