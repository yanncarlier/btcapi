'''
Generates Wrapped SegWit (P2SH-P2WPKH) addresses using BIP49, an implementation of Segregated Witness (BIP141).
BIP141 defines SegWit as a protocol upgrade; BIP49 specifies the derivation path m/49'/0'/0'/0/i for Wrapped SegWit addresses.
'''
from bip_utils import (
    Bip39SeedGenerator,
    Bip39MnemonicValidator,
    Bip49,
    Bip49Coins,
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

    # Initialize BIP49 for Bitcoin mainnet and derive the default account (m/49'/0'/0')
    bip49_mst_ctx = Bip49.FromSeed(seed_bytes, Bip49Coins.BITCOIN)
    bip49_acc_ctx = bip49_mst_ctx.Purpose().Coin().Account(0)

    # Generate a set number of BIP49 addresses (Wrapped SegWit, enabled by BIP141)
    num_addresses = 1  # Adjustable for more addresses
    print("Generating BIP141-Compatible Wrapped SegWit (P2SH-P2WPKH) Addresses via BIP49:")

    for i in range(num_addresses):
        # Derive the external chain and address at index i
        bip49_chg_ctx = bip49_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
        bip49_addr_ctx = bip49_chg_ctx.AddressIndex(i)

        # Construct derivation path manually (BIP49: m/49'/0'/0'/0/i)
        derivation_path = f"m/49'/0'/0'/0/{i}"
        address = bip49_addr_ctx.PublicKey().ToAddress()  # Wrapped SegWit address (starts with '3')
        public_key = bip49_addr_ctx.PublicKey().RawCompressed().ToHex()  # Compressed public key in hex
        private_key = bip49_addr_ctx.PrivateKey().ToWif()  # Private key in WIF format

        # Output in a structured format
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