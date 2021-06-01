import json
import logging
import pickle

import rcrypt

from config import hconfig

logging.basicConfig(filename="debug.log", filemode="w", format='%(asctime)s:%(levelname)s:%(message)s',
                    level=logging.DEBUG)

"""
A block is a Python dictionary that has the following structure. The type of an attribute is denoted in angle 
delimiters. 
    { 
        "prev_block_hash": <string> 
        "version": <string> 
        "timestamp": <integer> 
        "difficulty_bits": <integer> 
        "nonce": <integer> 
        "merkle_root": <string> 
        "height": <integer> 
        "tx": <list> 
    } 
The blockchain is a list where each list element is a block This is also referred to as the primary blockchain 
when used by miners. 
"""

blockchain = []


def add_block(block: dict) -> bool:
    """
    Adds a block to the blockchain. Receives a block. The block attributes are checked for validity and each
    transaction in the block is tested for validity. If there are no errors, the block is written to a file as a
    sequence of raw bytes. Then the block is added to the blockchain. returns True if the block is added to the
    blockchain and False otherwise
    """
    try:
        # validate the received block parameters
        if not validate_block(block):
            raise ValueError('Block validation error')
        # serialize the block to a file
        if not serialize_block(block):
            raise ValueError('Serialize block error')
        # Add the block to the blockchain in memory
        blockchain.append(block)
        return True
    except Exception as ex:
        print(str(ex))
        logging.debug(f'Add block exception: {str(ex)}')
        return False


def serialize_block(block: dict) -> bool:
    """
    Serializes a block to a file using pickle. Returns True if the block is serialized and False otherwise.
    """
    index = len(blockchain)
    filename = f'block_{str(index)}.dat'

    # create the block file and serialize the block
    try:
        with open(filename, 'wb') as file:
            pickle.dump(block, file)
        return True
    except Exception as error:
        logging.debug(f'Exception serializing the block: {error}')
        return False


def read_block(block_no: int) -> dict or False:
    """
    Receives an index into the Helium blockchain. Returns a block or False if the block does not exist.
    """
    try:
        block = blockchain[block_no]
        return block
    except Exception as error:
        logging.debug(f'Exception reading block {error}')
        return False


def block_header_hash(block: dict) -> str or False:
    """
    Computes and returns SHA-256 message digest of a block header as a hexadecimal string. Receives a block those
    block header hash is to be computed. Returns False if there is an error, otherwise returns a SHA-256 hexadecimal
    string. The block header consists of the following block fields: (1) version, (2) previous block hash, (3) merkle
    root (4) timestamp, (5) difficulty_bits, and (6) nonce.
    """
    try:
        return rcrypt.make_sha256_hash(
            block['version'] +
            block['prev_block_hash'] +
            block['merkle_root'] +
            str(block['timestamp']) +
            str(block['difficulty_bits']) +
            str(block['nonce'])
        )
    except Exception as error:
        logging.debug(f'Exception generating block header hash: {error}')
        return False


def validate_block(block: dict) -> bool:
    """
    validate_block: receives a block and verifies that all its attributes have valid values. Returns True if the
    block is valid and False otherwise.
    """
    try:
        if type(block) != dict:
            raise ValueError('Block type error')
        # Validate scalar block attributes
        if type(block['version']) != str:
            raise ValueError('Block version type error')
        if block['version'] != hconfig.conf['VERSION_NO']:
            raise ValueError('Block wrong version')
        if type(block['timestamp']) != int:
            raise ValueError('Block timestamp value error')
        if block['timestamp'] < 0:
            raise ValueError('Block invalid timestamp')
        if type(block['difficulty_bits']) != int:
            raise ValueError('Block difficulty bits type error')
        if block['difficulty_bits'] <= 0:
            raise ValueError('Block difficulty bits is less then or equals 0')
        if type(block['nonce']) != int:
            raise ValueError('Block nonce type error')
        if block['nonce'] != hconfig.conf['NONCE']:
            raise ValueError('Block nonce is invalid')
        if type(block['height']) != int:
            raise ValueError('Block height type error')
        if block['height'] < 0:
            raise ValueError('Block height is less than 0')
        if len(blockchain) == 0 and block['height'] != 0:
            raise ValueError('Genesis block invalid height')
        if len(blockchain) > 0:
            if block['height'] != blockchain[-1]['height'] + 1:
                raise ValueError('Block height is not in order')
        # The length of the block must be less than the maximum block size that specified in the config module.
        # json.dumps converts the block into a json format string.
        if len(json.dumps(block)) > hconfig.conf['MAX_BLOCK_SIZE']:
            raise ValueError('Block length error')
        # Validate the merkle root
        if block['merkle_root'] != merkle_root(block['tx'], True):
            raise ValueError('merkle roots do not match')
        # Validate the previous block by comparing message digests.
        # The genesis block does not have a predecessor block
        if block['height'] > 0:
            if block['prev_block_hash'] != block_header_hash(blockchain[block['height'] - 1]):
                raise ValueError('Previous block header hash does not match')
            else:
                if block['prev_block_hash'] != '':
                    raise ValueError('Genesis block has previous block hash!')
        # genesis block does not have any input transactions
        if block['height'] == 0 and block['tx'][0]['vin'] != []:
            raise ValueError('Missing coinbase transaction')
        # A block other than the genesis block must have at least
        # two transactions: the coinbase transaction and at least
        # one more transaction
        if block['height'] > 0 and len(block['tx']) < 2:
            raise ValueError('Block only has one transaction')
        return True
    except Exception as error:
        logging.error(f'Exception validating the block: {error}')
        return False


def merkle_root(buffer: list, start: bool = False) -> bool or str:
    """
    Computes the merkle root for a list of transactions. Receives a list of transactions and a boolean flag to
    indicate whether the function has been called for the first time or whether it is a recursive call from within
    the function. Returns the root of the merkle tree or False if there is an error.
    """
    pass
