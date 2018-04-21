from Crypto.Hash import SHA
from utils import generate_safe_prime, generate_sha_hash
from elgamal import ElGamalDS
import random

# Global Constants
NBYTES = SHA.digest_size + 1
BYTES_TO_BITS = 8
MAX_ID = 10

# Message to be sent by Alice
M = 23

# Alice and Bob Parameters
q = generate_safe_prime(NBYTES * BYTES_TO_BITS)
a = random.randint(2, q - 1)

# Alice Keys
x_a = random.randint(2, q - 1)
y_a = pow(a, x_a, q)
id_a = random.randint(1, MAX_ID)

# Bob Keys
x_b = random.randint(2, q - 1)
y_b = pow(a, x_b, q)
id_b = random.randint(1, MAX_ID)

# ID-A should be different than ID-B
assert id_a != id_b

# CA Creation

# Message Hashing
m = generate_sha_hash(M)

##############################################33
elgamal = ElGamalDS()
S1, S2 = elgamal.generate(x_a, a, q, m)
if elgamal.verify(y_a, a, m, q, S1, S2):
    print("Signature matches!")
else:
    print("Signature doesn't match!")
