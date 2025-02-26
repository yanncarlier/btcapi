'''
Demonstrates BIP85: Derives a new BIP39 mnemonic from a master mnemonic using bip32utils.
BIP85 uses the derivation path m/83696968'/39'/i' to generate child entropy for a new mnemonic.
'''
from mnemonic import Mnemonic
from bip32utils import BIP32Key, BIP32_HARDEN

# Example master mnemonic and passphrase
mnemonic = "caution blush hill vintage park empower coin mystery earth unaware control fault"
passphrase = ""  # Optional passphrase

try:
    # Initialize Mnemonic object
    mnemo = Mnemonic("english")

    # Validate mnemonic
    if not mnemo.check(mnemonic):
        raise ValueError("Invalid master mnemonic phrase.")

    print("Master Mnemonic:", mnemonic)
    print("Passphrase:", passphrase if passphrase else "<empty>")

    # Generate seed from mnemonic
    seed = mnemo.to_seed(mnemonic, passphrase=passphrase)
    print("Master Seed (hex):", seed.hex())

    # Generate master private key
    master_key = BIP32Key.fromEntropy(seed)

    # Number of child mnemonics to generate
    num_mnemonics = 1
    print("Generating BIP85 Child Mnemonics:")

    for i in range(num_mnemonics):
        # Derive child key at path m/83696968'/39'/i'
        child_key = (master_key
                     .ChildKey(83696968 + BIP32_HARDEN)  # BIP85 purpose
                     .ChildKey(39 + BIP32_HARDEN)       # BIP39 mnemonic app
                     .ChildKey(i + BIP32_HARDEN))       # Indexs

        # Child entropy is the private key (32 bytes)
        child_entropy = child_key.PrivateKey()

        # Generate a 12-word mnemonic (128 bits = 16 bytes)
        child_mnemonic = mnemo.to_mnemonic(child_entropy[:16])

        # Derivation path
        derivation_path = f"m/83696968'/39'/{i}'"

        # Output
        print("{")
        print(f"  derivation_path: {derivation_path}")
        print(f"  child_mnemonic: {child_mnemonic}")
        print("}")

except ValueError as e:
    print(f"Error: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")