import logging
import re

from Crypto.Hash import SHA256, RIPEMD160
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

"""
The rcrypt module implements various cryptographic functions that are required  
by the Helium cryptocurrency application
This module requires the pycryptodome package to be installed.
The base58 package encodes strings into base58 format.
This module uses Python's regular expression module re.
This module uses the secrets module in the Python standard library to generate 
cryptographically secure hexadecimal encoded strings.
"""

logging.basicConfig(filename="debug.log", filemode="w", format='%(asctime)s%:%(levelname)s%:%(message)s%',
                    level=logging.DEBUG)


def make_sha256_hash(msg: str) -> str:
    """
    make_sha256_hash computes the SHA-256 message digest or cryptographic hash for a received string argument. The
    secure hash value that is generated is converted into a sequence of hexadecimal digits and then returned by the
    function. The hexadecimal format of the message digest is 64 bytes long.
    """

    hash_object = SHA256.new()
    hash_object.update(bytes(msg, 'ascii'))

    return hash_object.hexdigest()


def validate_sha256_hash(digest: str) -> bool:
    """
    validate_SHA256_hash: tests whether a string has an encoding conforming
    to a SHA-256 message digest in hexadecimal string format (64 bytes).
    """

    if len(digest) != 64:
        return False

    # String should contain hexadecimals chars only
    if re.search('[^0-9a-fA-F]', digest) is None:
        return True

    return False


def make_ripemd160_hash(message: str) -> str:
    """
    RIPEMD-160 is a cryptographic algorithm that emits a 20 byte message digest. This function computes the
    RIPEMD-160 message digest of a message and returns the hexadecimal string encoded representation of the message
    digest (40 bytes).
    """

    # convert message to an ascii byte stream
    b_str = bytes(message, 'ascii')

    # generate the RIPEMD hash of message
    r_hash = RIPEMD160.new()
    r_hash.update(b_str)

    # convert to a hexadecimal encoded string
    return r_hash.hexdigest()


def validate_ripemd160_hash(digest: str) -> bool:
    """
    tests that a received string has an encoding conforming to a RIPE160 hash in hexadecimal format
    """

    if len(digest) != 40:
        return False

    # Test that received string only contains hexadecimal characters
    if re.search('[^0-9a-fA-F]+', digest) is None:
        return True

    return False


def make_ecc_keys():
    """
    Make a private-public key pair using the elliptic curve cryptographic functions in the pycryptodome package.
    Returns a tuple with the private key and public key in PEM format
    """

    # generate an ecc object
    ecc_key = ECC.generate(curve='P-256')

    # get the public key object
    pk_object = ecc_key.public_key()

    # export the private-public key pair in PEM format
    return ecc_key.export_key(format='PEM'), pk_object.export_key(format='PEM')


def sign_message(private_key: str, message: str) -> str:
    """
    Digitally signs a message using a private key generated using the elliptic curve cryptography module of the
    pycryptodome package. Receives a private key in PEM format and the message that is to be digitally signed.
    returns a hex encoded signature string.
    """

    # import the PEM format private key
    p_key = ECC.import_key(private_key)

    # convert the message to a byte stream and compute the SHA-256 message digest of the message
    b_str = bytes(message, 'ascii')
    hash_str = SHA256.new(b_str)

    # create a digital signature object from the private key
    signer = DSS.new(p_key, 'fips-186-3')

    # sign the SHA-256 message digest.
    signature = signer.sign(hash_str)

    return signature.hex()
