from Crypto.Hash import SHA
from utils import generate_safe_prime
from elgamal import ElGamalDS

NBYTES = SHA.digest_size + 1
BYTES_TO_BITS = 8

q = generate_safe_prime(NBYTES)

elgamal = ElGamalDS()
elgamal.generate(0, 0, q, 6)
