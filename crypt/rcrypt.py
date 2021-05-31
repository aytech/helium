"""
The rcrypt module implements various cryptographic functions that are required
by the Helium cryptocurrency application
This module requires the pycryptodome package to be installed.
The base58 package encodes strings into base58 format.
This module uses Python"s regular expression module re.
This module uses the secrets module in the Python standard library to generate
cryptographically secure hexadecimal encoded strings.
"""

import logging
import re
import secrets

import base58
from Crypto.Hash import SHA256, RIPEMD160
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

# logging.basicConfig(filename="debug.log", filemode="w", level=logging.DEBUG)


def make_sha256_hash(msg: str) -> str:
    """
    make_sha256_hash computes the SHA-256 message digest or cryptographic hash for a received string argument. The
    secure hash value that is generated is converted into a sequence of hexadecimal digits and then returned by the
    function. The hexadecimal format of the message digest is 64 bytes long.
    """

    hash_object = SHA256.new()
    hash_object.update(bytes(msg, "ascii"))

    logging.debug(f"SHA256 hash created: {hash_object.hexdigest()}")

    return hash_object.hexdigest()


def validate_sha256_hash(digest: str) -> bool:
    """
    validate_SHA256_hash: tests_ whether a string has an encoding conforming
    to a SHA-256 message digest in hexadecimal string format (64 bytes).
    """

    if len(digest) != 64:
        return False

    # String should contain hexadecimals chars only
    if re.search("[^0-9a-fA-F]", digest) is None:
        return True

    return False


def make_ripemd160_hash(message: str) -> str:
    """
    RIPEMD-160 is a cryptographic algorithm that emits a 20 byte message digest. This function computes the
    RIPEMD-160 message digest of a message and returns the hexadecimal string encoded representation of the message
    digest (40 bytes).
    """

    # convert message to an ascii byte stream
    b_str = bytes(message, "ascii")

    # generate the RIPEMD hash of message
    r_hash = RIPEMD160.new()
    r_hash.update(b_str)

    # convert to a hexadecimal encoded string
    return r_hash.hexdigest()


def validate_ripemd160_hash(digest: str) -> bool:
    """
    tests_ that a received string has an encoding conforming to a RIPE160 hash in hexadecimal format
    """

    if len(digest) != 40:
        return False

    # Test that received string only contains hexadecimal characters
    if re.search("[^0-9a-fA-F]+", digest) is None:
        return True

    return False


def make_ecc_keys():
    """
    Make a private-public key pair using the elliptic curve cryptographic functions in the pycryptodome package.
    Returns a tuple with the private key and public key in PEM format
    """

    # generate an ecc object
    ecc_key = ECC.generate(curve="P-256")

    # get the public key object
    pk_object = ecc_key.public_key()

    # export the private-public key pair in PEM format
    return ecc_key.export_key(format="PEM"), pk_object.export_key(format="PEM")


def sign_message(private_key: str, message: str) -> str:
    """
    Digitally signs a message using a private key generated using the elliptic curve cryptography module of the
    pycryptodome package. Receives a private key in PEM format and the message that is to be digitally signed.
    returns a hex encoded signature string.
    """

    # import the PEM format private key
    p_key = ECC.import_key(private_key)

    # convert the message to a byte stream and compute the SHA-256 message digest of the message
    b_str = bytes(message, "ascii")
    hash_str = SHA256.new(b_str)

    # create a digital signature object from the private key
    signer = DSS.new(p_key, "fips-186-3")

    # sign the SHA-256 message digest.
    # noinspection PyTypeChecker
    signature = signer.sign(hash_str)

    return signature.hex()


def verify_signature(public_key: str, message: str, signature: str) -> bool:
    """
    tests_ whether a message is digitally signed by a private key to which a public key is paired. Receives a ECC
    public key in PEM format, the message that is to to be verified and the digital signature of the message. Returns
    True or False
    """
    try:
        # convert the message to a byte stream and compute the SHA-256 hash
        message = bytes(message, "ascii")
        message_hash = SHA256.new(message)

        # signature to bytes
        signature = bytes.fromhex(signature)

        # import the PEM formatted public key and create a signature verifier
        # object from the public key
        pub_key = ECC.import_key(public_key)
        verifier = DSS.new(pub_key, "fips-186-3")

        # verify authenticity of the signed message
        # noinspection PyTypeChecker
        verifier.verify(message_hash, signature)

        return True
    except Exception as ex:
        logging.debug("Failed to verify signature: " + str(ex))
        return False


def make_address(prefix: str) -> str:
    """
    generates a Helium address from a ECC public key in PEM format. Prefix is a single numeric character which
    describes the type of the address. This prefix must be "1"
    """
    key = ECC.generate(curve="P-256")
    __private_key = key.export_key(format="PEM")
    public_key = key.public_key().export_key(format="PEM")

    value = make_sha256_hash(public_key)
    value = make_ripemd160_hash(value)

    tmp = prefix + value

    # make a checksum
    checksum = make_sha256_hash(tmp)
    checksum = checksum[len(checksum) - 4:]

    # add the checksum to the tmp result
    address = tmp + checksum

    # encode address as base58 sequence of bytes
    address = base58.b58encode(address.encode())

    # the decode function converts a byte sequence to a string
    address = address.decode("ascii")

    return address


def validate_address(address: str) -> bool:
    """
    validates a Helium address using the four character checksum appended to the address. Receives a base58 encoded
    address.
    """

    # encode the string address as a sequence of bytes
    _address = address.encode("ascii")

    # reverse the base58 encoding of the address
    _address = base58.b58decode(_address)

    # convert the address into a string
    _address = _address.decode("ascii")

    # length must be RIPEMD-160 hash length + length of checksum + 1
    if len(_address) != 45:
        return False

    if _address[0] != "1":
        return False

    # extract the checksum
    extracted_checksum = _address[len(_address) - 4:]

    # extract the checksum out of the address and compute the SHA-256 hash of the remaining address string
    tmp = _address[:len(_address) - 4]
    tmp = make_sha256_hash(tmp)

    # get the computed checksum from tmp
    checksum = tmp[len(tmp) - 4:]

    if extracted_checksum == checksum:
        return True

    return False


def make_uuid() -> str:
    """
    makes an universally unique 256 bit id encoded as a hexadecimal string that is used as a transaction identifier.
    Uses the Python standard library secrets module to generate a cryptographic strong random 32 byte string encoded
    as a hexadecimal string (64 bytes)
    """

    return secrets.token_hex(32)
