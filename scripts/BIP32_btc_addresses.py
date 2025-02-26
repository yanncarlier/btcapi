from mnemonic import Mnemonic
from bip32utils import BIP32Key, BIP32_HARDEN

# Example BIP39 mnemonic seed phrase
mnemonic = "caution blush hill vintage park empower coin mystery earth unaware control fault"

try:
    # Initialize Mnemonic object for English wordlist
    mnemo = Mnemonic("english")

    # Validate the mnemonic phrase
    if not mnemo.check(mnemonic):
        raise ValueError("Invalid mnemonic phrase provided. Please check the words and try again.")

    print("Mnemonic Phrase:", mnemonic)

    # Convert mnemonic to seed (with empty passphrase)
    seed = mnemo.to_seed(mnemonic, passphrase="")
    print("Seed (hex):", seed.hex())

    # Generate BIP32 root key from the seed
    root_key = BIP32Key.fromEntropy(seed)

    # Generate a set number of addresses
    num_addresses = 5
    for i in range(num_addresses):
        # Derive Bitcoin address using BIP44 path: m/44'/0'/0'/0/i
        # Note: Original script used m/32', but BIP44 for Bitcoin uses 44'. Adjusted accordingly.
        address_key = (root_key
                       .ChildKey(32 + BIP32_HARDEN)  # Purpose (BIP44)
                       .ChildKey(0 + BIP32_HARDEN)   # Coin type (Bitcoin)
                       .ChildKey(0 + BIP32_HARDEN)   # Account 0
                       .ChildKey(0)                  # External chain
                       .ChildKey(i))                 # Address index

        # Extract required information
        derivation_path = f"m/32'/0'/0'/0/{i}"
        address = address_key.Address()
        public_key = address_key.PublicKey().hex()
        private_key = address_key.WalletImportFormat()

        # Print the output in the specified order
        print("++++++++++++++++++++++++++++++++++++++++++++")
        print(f"derivation_path: {derivation_path}")
        print(f"address: {address}")
        print(f"public_key: {public_key}")
        print(f"private_key: {private_key}")

except ValueError as e:
    print(f"Error: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")