import os
import secrets
from block import hblockchain
from config import hconfig
from crypt import rcrypt


def teardown_module():
    """
    after all of the tests have been executed, remove any blocks that were created
    """
    os.system("rm *.dat")
    hblockchain.blockchain.clear()


def make_random_transaction(block_height):
    tx = {
        "version": "1",
        "transaction_id": rcrypt.make_uuid(),
        "lock_time": secrets.randbelow(hconfig.conf["MAX_LOCK_TIME"]),
        "value_in": [],
        "value_out": []
    }

    # public-private key pair for previous transaction
    prev_keys = rcrypt.make_ecc_keys()

    # public-private key pair for this transaction
    keys = rcrypt.make_ecc_keys()

    # Build value_in
    if block_height > 0:
        ctr = secrets.randbelow(hconfig.conf["MAX_INPUTS"]) + 1
        index = 0
        while index > 0:
            signed = rcrypt.sign_message(prev_keys[0], prev_keys[1])
            script_sig = [signed[0], prev_keys[1]]
            tx["value_in"].append({
                "tx_id": rcrypt.make_uuid(),
                "value_out_index": ctr,
                "ScriptSig": script_sig
            })
            index += 1

    # Build value_out
    ctr = secrets.randbelow(hconfig.conf["MAX_OUTPUTS"]) + 1
    index = 0
    while index < ctr:
        tx["value_out"] = {
            # helium cents
            "value": secrets.randbelow(10000000) + 10000000,
            "ScriptPubKey": ["DUP", "HASH-160", keys[1], "EQ-VERIFY", "CHECK-SIG"]
        }
        index += 1

    return tx


#############################################
# Build Three Synthetic Blocks For Testing
#############################################
block_0 = {
    "prev_block_hash": "",
    "version": "1",
    "timestamp": 0,
    "difficulty_bits": 20,
    "nonce": 0,
    "merkle_root": rcrypt.make_sha256_hash("msg0"),
    "height": 0,
    "tx": [make_random_transaction(0)]
}
block_1 = {
    "prev_block_hash": hblockchain.block_header_hash(block_0),
    "version": "1",
    "timestamp": 0,
    "difficulty_bits": 20,
    "nonce": 0,
    "merkle_root": rcrypt.make_sha256_hash("msg1"),
    "height": 1,
    "tx": [make_random_transaction(1), make_random_transaction(1)]
}
block_2 = {
    "prev_block_hash": hblockchain.block_header_hash(block_1),
    "version": "1",
    "timestamp": 0,
    "difficulty_bits": 20,
    "nonce": 0,
    "merkle_root": rcrypt.make_sha256_hash("msg2"),
    "height": 2,
    "tx": [make_random_transaction(2), make_random_transaction(2)]
}


def test_block_type(monkeypatch):
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg0"))
    assert hblockchain.validate_block(block_0) is True


def test_add_good_block(monkeypatch):
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg0"))
    assert hblockchain.add_block(block_0) is True

    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg1"))
    assert hblockchain.add_block(block_1) is True

    hblockchain.blockchain.clear()


def test_missing_version(monkeypatch):
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg1"))
    monkeypatch.setitem(block_1, "version", "")

    assert hblockchain.add_block(block_1) is False


def test_version_bad(monkeypatch):
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg1"))
    monkeypatch.setitem(block_1, "version", -1)

    assert hblockchain.add_block(block_1) is False


def test_bad_timestamp_type(monkeypatch):
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg1"))
    monkeypatch.setitem(block_1, "timestamp", "12345")

    assert hblockchain.add_block(block_1) is False


def test_negative_timestamp(monkeypatch):
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg0"))
    monkeypatch.setitem(block_0, "timestamp", -2)

    assert hblockchain.add_block(block_0) is False


def test_missing_timestamp(monkeypatch):
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg1"))
    monkeypatch.setitem(block_1, "timestamp", "")

    assert hblockchain.add_block(block_1) is False


def test_block_height_type(monkeypatch):
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg0"))
    monkeypatch.setitem(block_0, "height", "0")

    assert hblockchain.add_block(block_0) is False
    hblockchain.blockchain.clear()


def test_bad_nonce(monkeypatch):
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg1"))
    monkeypatch.setitem(block_1, "nonce", -1)

    assert hblockchain.add_block(block_1) is False


def test_missing_nonce(monkeypatch):
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg0"))
    monkeypatch.setitem(block_0, "nonce", "")

    assert hblockchain.add_block(block_0) is False


def test_block_nonce_type(monkeypatch):
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg0"))
    monkeypatch.setitem(block_0, "nonce", "0")

    assert hblockchain.add_block(block_0) is False


def test_negative_difficulty_bit(monkeypatch):
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg1"))
    monkeypatch.setitem(block_1, "difficulty_bits", -5)

    assert hblockchain.add_block(block_1) is False


def test_difficulty_type(monkeypatch):
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg0"))
    monkeypatch.setitem(block_0, "difficulty_bits", "20")

    assert hblockchain.add_block(block_0) is False


def test_missing_difficulty_bit(monkeypatch):
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("data"))
    monkeypatch.setitem(block_1, "difficulty_bits", "")

    assert hblockchain.add_block(block_1) is False


def test_read_genesis_block(monkeypatch):
    hblockchain.blockchain.clear()
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg0"))

    hblockchain.add_block(block_0)
    assert hblockchain.read_block(0) == block_0
    hblockchain.add_block(block_0)


def test_genesis_block_height(monkeypatch):
    hblockchain.blockchain.clear()
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg0"))
    block_0["height"] = 0

    assert hblockchain.add_block(block_0) is True
    bulk = hblockchain.read_block(0)
    assert bulk is not False
    assert bulk["height"] == 0
    hblockchain.blockchain.clear()


def test_read_second_block(monkeypatch):
    hblockchain.blockchain.clear()
    assert len(hblockchain.blockchain) == 0

    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg0"))
    monkeypatch.setitem(block_1, "prev_block_hash", hblockchain.block_header_hash(block_0))

    result = hblockchain.add_block(block_0)
    assert result is True

    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg1"))
    result = hblockchain.add_block(block_1)
    assert result is True
    block = hblockchain.read_block(1)
    assert block is not False
    hblockchain.blockchain.clear()


def test_block_height(monkeypatch):
    # test height of the the second block
    hblockchain.blockchain.clear()
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg0"))
    monkeypatch.setitem(block_0, "height", 0)
    monkeypatch.setitem(block_0, "prev_block_hash", "")
    monkeypatch.setitem(block_1, "height", 1)
    monkeypatch.setitem(block_1, "prev_block_hash", hblockchain.block_header_hash(block_0))
    assert hblockchain.add_block(block_0) is True

    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg1"))
    assert hblockchain.add_block(block_1) is True

    bulk = hblockchain.read_block(1)
    assert bulk is not False
    assert bulk["height"] == 1

    hblockchain.blockchain.clear()


def test_block_size(monkeypatch):
    # The block size must be less than hconfig["MAX_BLOCKS"]
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg0"))

    arr = []
    filler = "0" * 2000000
    arr.append(filler)
    monkeypatch.setitem(block_0, "tx", arr)

    hblockchain.blockchain.clear()
    assert hblockchain.add_block(block_0) is False


def test_genesis_block_prev_hash(monkeypatch):
    # test that the previous block hash for the genesis block is empty
    hblockchain.blockchain.clear()
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg0"))
    monkeypatch.setitem(block_0, "height", 0)
    monkeypatch.setitem(block_0, "prev_block_hash", rcrypt.make_uuid())

    assert len(hblockchain.blockchain) == 0
    assert hblockchain.add_block(block_0) == False


def test_computes_previous_block_hash(monkeypatch):
    # test previous block hash has correct format
    value = hblockchain.block_header_hash(block_0)
    assert rcrypt.validate_sha256_hash(value) is True


def test_invalid_previous_hash(monkeypatch):
    hblockchain.blockchain.clear()
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg0"))
    monkeypatch.setitem(block_2, "prev_block_hash", "188a1fd32a1f83af966b31ca781d71c40f756a3dc2a7ac44ce89734d2186f632")
    hblockchain.blockchain.clear()
    assert hblockchain.add_block(block_0) is True

    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg1"))
    assert hblockchain.add_block(block_1) is True

    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg2"))
    assert hblockchain.add_block(block_2) is False

    hblockchain.blockchain.clear()


def test_no_consecutive_duplicate_blocks(monkeypatch):
    # test cannot add the same block twice consecutively to the blockchain
    hblockchain.blockchain.clear()
    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg0"))
    assert hblockchain.add_block(block_0) is True

    monkeypatch.setattr(hblockchain, "merkle_root", lambda x, y: rcrypt.make_sha256_hash("msg1"))
    monkeypatch.setitem(block_1, "prev_block_hash", hblockchain.block_header_hash(block_0))
    assert hblockchain.add_block(block_1) is True

    monkeypatch.setitem(block_1, "height", 2)
    assert hblockchain.add_block(block_1) is False

    hblockchain.blockchain.clear()


