conf = {

    # The Helium version number
    'VERSION_NO': "1",

    # The maximum number of Helium coins that can be mined
    'MAX_HELIUM_COINS': 21000000,

    # The smallest Helium currency unit in terms of one Helium coin
    'HELIUM_CENT': 1 / 100000000,

    # The maximum size of a Helium block in bytes
    'MAX_BLOCK_SIZE': 1000000,

    # The maximum amount of time in seconds that a transaction can be locked
    'MAX_LOCK_TIME': 30 * 1440 * 60,

    # The maximum number of Inputs in a Helium Transaction
    'MAX_INPUTS': 10,

    # The maximum number of Outputs in a Helium Transaction
    'MAX_OUTPUTS': 10,

    # The number of new blocks from a reference block that must be mined before
    # coinbase transaction in the previous reference block can be spent
    'COINBASE_INTERVAL': 100,

    # The starting nonce value for the mining proof of work computations
    'NONCE': 0,

    # Difficulty number used in mining proof of work computations
    'DIFFICULTY_BITS': 20,
    'DIFFICULTY_NUMBER': 1 / (10 ** (256 - 20)),

    # Retargeting interval in blocks in order to adjust the DIFFICULTY_NUMBER
    'RETARGET_INTERVAL': 1000,

    # Mining reward
    'MINING_REWARD': 5000000000,

    # Mining reward halving interval in blocks
    'REWARD_INTERVAL': 210000
}
