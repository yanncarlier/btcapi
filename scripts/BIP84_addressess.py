'''
Generates BIP84 (Native SegWit P2WPKH) Addresses.
BIP84 (Native SegWit, P2WPKH) uses 84'.
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
mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
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

    # Print the Account Extended Public Key (xpub)
    account_xpub = bip84_acc_ctx.PublicKey().ToExtended()
    print("Account Extended Public Key (xpub):", account_xpub)
    
    # Generate a set number of BIP84 addresses
    num_addresses = 1
    print("Generating BIP84 (Native SegWit P2WPKH) Addresses:")

    for i in range(num_addresses):
        # Derive the external chain and address at index i
        bip84_chg_ctx = bip84_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
        bip84_addr_ctx = bip84_chg_ctx.AddressIndex(i)

        # Construct derivation path manually (BIP84: m/84'/0'/0'/0/i)
        derivation_path = f"m/84'/0'/0'/0/{i}"
        address = bip84_addr_ctx.PublicKey().ToAddress()  # Native SegWit address (P2WPKH)
        public_key = bip84_addr_ctx.PublicKey().RawCompressed().ToHex()
        private_key = bip84_addr_ctx.PrivateKey().Raw().ToHex()  # Private key in hex
        wif = bip84_addr_ctx.PrivateKey().ToWif()  # Private key in WIF format

        # Output in specified order
        print("{")
        print(f"derivation_path: {derivation_path}")
        print(f"address: {address}")
        print(f"public_key: {public_key}")
        print(f"private_key: {private_key}")
        print(f"wif: {wif}")
        print("},")

except MnemonicChecksumError as e:
    print(f"Error: Invalid mnemonic checksum. Details: {e}")
except ValueError as e:
    print(f"Error: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")