from Crypto.Hash import SHA
from rsa import RSA
from utils import generate_safe_prime, generate_hash
from elgamal import ElGamalDS
import random
from ca import CA
from datetime import datetime, timedelta
from utils import verify_certificate

# Global Constants
NBYTES = SHA.digest_size + 1
BYTES_TO_BITS = 8
MAX_ID = 30
RSA_KEY_BITS = 512

########################################################################################################################
# CA Creation
ca = CA(NBYTES)

# RSA Creation
rsa = RSA(RSA_KEY_BITS)

# Alice and Bob Parameters
q = generate_safe_prime(NBYTES * BYTES_TO_BITS)
a = random.randint(2, q - 1)

########################################################################################################################

# Alice Keys
x_a = random.randint(2, q - 1)
y_a = pow(a, x_a, q)
id_a = random.randint(1, MAX_ID)
ca.generate_x509_certificate("Alice", id_a, "Alice_Sub", [a, q], y_a, datetime.now(), datetime.now() + timedelta(365))

# Alice RSA Keys
d_a, e_a, n = rsa.generate_key_pair()
########################################################################################################################
# Bob Keys
x_b = random.randint(2, q - 1)
y_b = pow(a, x_b, q)
id_b = random.randint(1, MAX_ID)
z, r = ca.generate_x509_certificate("Bob", id_b, "Bob_Sub", [a, q], y_b, datetime.now(),
                                    datetime.now() + timedelta(365))

# Bob RSA Keys
d_b, e_b, n = rsa.generate_key_pair()
########################################################################################################################
# Some other keys
for i in range(MAX_ID):
    if i != id_a and i != id_b:
        x = random.randint(2, q - 1)
        y = pow(a, x, q)
        ca.generate_x509_certificate("Random" + str(i), i, "Random_Sub" + str(i), [a, q], y, datetime.now(),
                                     datetime.now() + timedelta(365))

########################################################################################################################
# AT ALICE PART:
##################
# Message to be sent by Alice
print("Alice Part!")
M = 23
m = generate_hash(M, SHA)

# Sign the message by Alice
m_alice_signature = ElGamalDS.sign(x_a, a, q, m)

# Get Bob's certificate
bob_cert, ca_bob_signature = ca.get_x509_certificate(id_b)

# Verify the certificate from CA
if verify_certificate(bob_cert, ca_bob_signature, ca.y_ca, ca.a_ca, ca.q_ca):
    print("Bob Certificate verified!")
else:
    raise ValueError("Bob Certificate is incorrect!")

# Get Bob's public key
bob_public_key = bob_cert['issuer_public_key']

# Assert that it's the true public key (Used for debugging)
assert bob_public_key == y_b

# First byte specifies the length of each of the signature parts, then each of the signature parts are added, then the message.
# Concatenate to send
q_len = len(str(q))
q_len_str = chr(q_len)
print("Length of q: " + str(q_len))

sig0 = str(m_alice_signature[0])
for _ in range(q_len - len(sig0)):
    sig0 = '0' + sig0

sig1 = str(m_alice_signature[1])
for _ in range(q_len - len(sig1)):
    sig1 = '0' + sig1
msg = q_len_str + sig0 + sig1 + str(M)
print("Message before conversion to int: " + msg)
total_message = int.from_bytes(msg.encode('UTF-8'), byteorder='big')
print("Message after conversion to int: " + str(total_message))

encrypted = rsa.encrypt(e_b, int(total_message))
print("Encrypted Message to be sent: " + str(encrypted) + "\n")
########################################################################################################################
# AT BOB PART:
##################
print("Bob Part!")
print("Encrypted Message that is received: " + str(encrypted))

decrypted = rsa.decrypt(encrypted, d_b)
print("Decrypted Message that is received: " + str(decrypted))

msg_r = int.to_bytes(decrypted, decrypted.bit_length(), byteorder='big').decode('UTF-8').replace('\0', '')
print("Decrypted Message after conversion from int: " + str(msg_r))

q_len_r = ord(msg_r[0])
sig0_r = int(msg_r[1: q_len_r + 1])
sig1_r = int(msg_r[q_len_r + 1: 2 * q_len_r + 1])
M_r = int(msg_r[2 * q_len_r + 1:])

# Get Alice's certificate
alice_cert, ca_alice_signature = ca.get_x509_certificate(id_a)

# Verify the certificate from CA
if verify_certificate(alice_cert, ca_alice_signature, ca.y_ca, ca.a_ca, ca.q_ca):
    print("Alice Certificate verified!")
else:
    raise ValueError("Alice Certificate is incorrect!")

# Get Alice's public key
alice_public_key = alice_cert['issuer_public_key']
alice_a, alice_q = alice_cert['issuer_public_parameters']

# Assert that it's the true public key (Used for debugging)
assert alice_public_key == y_a

# Calculate the hash for the received message
m_r = generate_hash(M_r, SHA)

# Verify the signature of the message
if ElGamalDS.verify(alice_public_key, alice_a, m_r, alice_q, [sig0_r, sig1_r]):
    print("Message signature verified!")
else:
    print("Message signature failed!")

# End of the program!
