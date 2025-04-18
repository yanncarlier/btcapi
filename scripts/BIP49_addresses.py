'''
Generates both Native SegWit (BIP44, P2WPKH) and 
Wrapped SegWit (BIP49, P2SH-P2WPKH) Bitcoin addresses.
BIP49 (Wrapped SegWit, P2SH-P2WPKH) uses 49'.
'''
from bip_utils import (
    Bip39SeedGenerator,
    Bip39MnemonicValidator,
    Bip44,
    Bip44Coins,
    Bip44Changes,
    Bip49,
    Bip49Coins
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

    # Number of addresses to generate
    num_addresses = 1

    # Generate Native SegWit (P2WPKH) addresses using BIP44
    # print("Generating Native SegWit (P2WPKH) Addresses:")

    # bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
    # bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)

    # for i in range(num_addresses):
    #     bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
    #     bip44_addr_ctx = bip44_chg_ctx.AddressIndex(i)

    #     # Construct derivation path manually (BIP44: m/44'/0'/0'/0/i)
    #     derivation_path = f"m/44'/0'/0'/0/{i}"
    #     address = bip44_addr_ctx.PublicKey().ToAddress()
    #     public_key = bip44_addr_ctx.PublicKey().RawCompressed().ToHex()
    #     private_key = bip44_addr_ctx.PrivateKey().ToWif()

    #     # Output in specified order
    #     print("++++++++++++++++++++++++++++++++++++++++++++")
    #     print(f"derivation_path: {derivation_path}")
    #     print(f"address: {address}")
    #     print(f"public_key: {public_key}")
    #     print(f"private_key: {private_key}")

    # print("\n")

    # Generate Wrapped SegWit (P2SH-P2WPKH) addresses using BIP49
    print("Generating Wrapped SegWit (P2SH-P2WPKH) Addresses:")
    bip49_mst_ctx = Bip49.FromSeed(seed_bytes, Bip49Coins.BITCOIN)
    bip49_acc_ctx = bip49_mst_ctx.Purpose().Coin().Account(0)

    for i in range(num_addresses):
        bip49_chg_ctx = bip49_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
        bip49_addr_ctx = bip49_chg_ctx.AddressIndex(i)

        # Construct derivation path manually (BIP49: m/49'/0'/0'/0/i)
        derivation_path = f"m/49'/0'/0'/0/{i}"
        address = bip49_addr_ctx.PublicKey().ToAddress()
        public_key = bip49_addr_ctx.PublicKey().RawCompressed().ToHex()
        private_key = bip49_addr_ctx.PrivateKey().ToWif()

        # Output in specified order
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