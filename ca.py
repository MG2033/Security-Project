from utils import generate_safe_prime
import random
from datetime import datetime, timedelta
from Crypto.Hash import SHA
from utils import generate_hash
from elgamal import ElGamalDS
from pymongo import MongoClient
from utils import verify_certificate
import collections
import dateutil
from dateutil import parser

class CA:
    __x509_SN = 0
    __VERSION__ = 1
    __BYTES_TO_BITS = 8

    def __init__(self, NBYTES, database_host='localhost', database_port=27017):
        self.q_ca = generate_safe_prime(NBYTES * CA.__BYTES_TO_BITS)
        self.a_ca = random.randint(2, self.q_ca - 1)
        self.__x_ca = random.randint(2, self.q_ca - 1)
        self.y_ca = pow(self.a_ca, self.__x_ca, self.q_ca)
        self.certificates = self.__initalize_database(database_host, database_port)

    def generate_x509_certificate(self, issuer_name: str, issuer_id: int, subject_name: str,
                                  issuer_public_parameters: list, issuer_public_key: list,
                                  not_valid_before: dateutil, not_valid_after: dateutil, hash_type=SHA):
        # Generating the certificate
        cert = collections.OrderedDict()
        cert['issuer_name'] = issuer_name
        cert['issuer_id'] = issuer_id
        cert['subject_name'] = subject_name
        cert['issuer_public_parameters'] = issuer_public_parameters
        cert['issuer_public_key'] = issuer_public_key
        cert['serial_number'] = CA.__x509_SN
        cert['not_valid_before'] = not_valid_before
        cert['not_valid_after'] = not_valid_after
        CA.__x509_SN += 1

        returned_cert = cert.copy()

        # Signing the certificate
        m = generate_hash(str(cert), hash_type)
        signature = ElGamalDS.sign(self.__x_ca, self.a_ca, self.q_ca, m)
        cert['signature'] = signature.copy()

        # Conversion from MPZ to integer
        for i in range(len(signature)):
            signature[i] = int(signature[i])

        # Conversion into strings to be stored in the database properly
        for i in range(len(cert['issuer_public_key'])):
            cert['issuer_public_key'][i] = str(cert['issuer_public_key'][i])

        for i in range(len(cert['signature'])):
            cert['signature'][i] = str(cert['signature'][i])

        cert['issuer_public_parameters'] = returned_cert['issuer_public_parameters'].copy()
        for i in range(len(cert['issuer_public_parameters'])):
            cert['issuer_public_parameters'][i] = str(cert['issuer_public_parameters'][i])

        cert['not_valid_before'] = str(cert['not_valid_before'])
        cert['not_valid_after'] = str(cert['not_valid_after'])

        # Insert into the database or update if it exists
        cur = self.certificates.find({'issuer_id': issuer_id})
        if cur.count() > 0:
            self.certificates.update({'issuer_id': issuer_id}, cert)
        else:
            self.certificates.insert_one(cert)

        return returned_cert, signature

    def get_x509_certificate(self, issuer_id: int):
        cert, signature = dict(), None
        cur = self.certificates.find({'issuer_id': issuer_id})
        returned_cert = collections.OrderedDict()
        for cert in cur:
            # Reverting back what is done before saving to the database
            returned_cert['issuer_name'] = cert['issuer_name']
            returned_cert['issuer_id'] = int(cert['issuer_id'])
            returned_cert['subject_name'] = cert['subject_name']
            returned_cert['issuer_public_parameters'] = cert['issuer_public_parameters']
            returned_cert['issuer_public_key'] = cert['issuer_public_key']
            returned_cert['serial_number'] = int(cert['serial_number'])
            returned_cert['not_valid_before'] = parser.parse(cert['not_valid_before'])
            returned_cert['not_valid_after'] = parser.parse(cert['not_valid_after'])

            signature = []
            for i in range(len(cert['signature'])):
                signature.append(int(cert['signature'][i]))

            for i in range(len(returned_cert['issuer_public_key'])):
                returned_cert['issuer_public_key'][i] = int(returned_cert['issuer_public_key'][i])

            for i in range(len(returned_cert['issuer_public_parameters'])):
                returned_cert['issuer_public_parameters'][i] = int(returned_cert['issuer_public_parameters'][i])


            break
        return returned_cert, signature

    def __initalize_database(self, database_host='localhost', database_port=27017):
        client = MongoClient(database_host, database_port)
        db = client.certificates_database
        return db.certificates


# Test Drive
# ca = CA(21)
# cert2, signature2 = ca.generate_x509_certificate("Bob", 1, "Bob_Sub", [5, 7], 10, datetime.now(), datetime.now() + timedelta(365))
# cert, signature = ca.get_x509_certificate(1)
# print(cert == cert2, verify_certificate(cert, signature, ca.y_ca, ca.a_ca, ca.q_ca))
# for k in cert.keys():
#     if cert[k] != cert2[k]:
#         print(k, cert[k], cert2[k])
