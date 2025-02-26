'''
Generates Native SegWit (P2WPKH) addresses using BIP84, an implementation of Segregated Witness (BIP141).
BIP141 defines SegWit as a protocol upgrade; BIP84 specifies the derivation path m/84'/0'/0'/0/i for Native SegWit addresses.
'''
from bip_utils import (
    Bip39SeedGenerator,
    Bip39MnemonicValidator,
    Bip84,
    Bip84Coins,
    Bip44Changes
)
from bip_utils.utils.mnemonic import MnemonicChecksumError

# Example BIP39 mnemonic seed phrase
mnemonic = "caution blush hill vintage park empower coin mystery earth unaware control fault"
passphrase = ""  # Optional passphrase (default is empty string; can be changed by user)

try:
    # Validate the mnemonic phrase
    if not Bip39MnemonicValidator().IsValid(mnemonic):
        raise ValueError("Invalid mnemonic phrase provided. Please check the words and try again.")
    
    print("Mnemonic Phrase:", mnemonic)
    print("Passphrase:", passphrase if passphrase else "<empty>")

    # Generate seed from mnemonic with passphrase
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase=passphrase)

    # Display the generated seed (in hex)
    print("Seed (hex):", seed_bytes.hex())

    # Initialize BIP84 for Bitcoin mainnet and derive the default account (m/84'/0'/0')
    bip84_mst_ctx = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)
    bip84_acc_ctx = bip84_mst_ctx.Purpose().Coin().Account(0)

    # Generate a set number of BIP84 addresses (Native SegWit, enabled by BIP141)
    num_addresses = 1  # Consistent with provided scripts; adjustable for more addresses
    print("Generating BIP141-Compatible Native SegWit (P2WPKH) Addresses via BIP84:")

    for i in range(num_addresses):
        # Derive the external chain and address at index i
        bip84_chg_ctx = bip84_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
        bip84_addr_ctx = bip84_chg_ctx.AddressIndex(i)

        # Construct derivation path manually (BIP84: m/84'/0'/0'/0/i)
        derivation_path = f"m/84'/0'/0'/0/{i}"
        address = bip84_addr_ctx.PublicKey().ToAddress()  # Native SegWit address (starts with 'bc1q')
        public_key = bip84_addr_ctx.PublicKey().RawCompressed().ToHex()  # Compressed public key in hex
        private_key = bip84_addr_ctx.PrivateKey().ToWif()  # Private key in WIF format

        # Output in specified order, matching provided format
        print("{")
        print(f"derivation_path: {derivation_path}")
        print(f"address: {address}")
        print(f"public_key: {public_key}")
        print(f"private_key: {private_key}")
        print("},")

except MnemonicChecksumError as e:
    print(f"Error: Invalid mnemonic checksum. Details: {e}")
except ValueError as e:
    print(f"Error: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")