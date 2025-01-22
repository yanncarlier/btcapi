'''
Here's how you can generate Bitcoin addresses from a BIP39 seed phrase using Python. We'll use the bip-utils library which simplifies the process of dealing with BIP39 seeds, BIP32 key derivation, and address generation:
'''
'''
Explanation:
Mnemonic: Replace "your bip39 mnemonic here" with your actual BIP39 seed phrase.
Seed Generation: We use Bip39SeedGenerator to convert the mnemonic to seed bytes.
BIP44 Derivation: We derive keys using BIP44 standard which is commonly used for Bitcoin. The path used here would be something like m/44'/0'/0'/0/i where i increments for each address.
Purpose() sets the purpose to BIP44 (44').
Coin() specifies Bitcoin (0').
Account(0) sets the account to the first one (0').
Change(Bip44Changes.CHAIN_EXT) specifies external chain (0).
AddressIndex(i) sets the index for each new address.
Address Generation: This script generates addresses for external use (like receiving Bitcoin). Remember, for internal use (change addresses), you would use Bip44Changes.CHAIN_INT.
This script generates 5 addresses, but you can change num_addresses to generate more or fewer. Always ensure to handle your seed phrase securely as anyone with access to it can control all derived addresses.
'''
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
# Example BIP39 mnemonic seed phrase
mnemonic = "caution blush hill vintage park empower coin mystery earth unaware control fault"
# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
# Initialize BIP44 with BTC main net and derive the default account
bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
# Generate addresses
num_addresses = 5  # Number of addresses to generate
for i in range(num_addresses):
    bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
    bip44_addr_ctx = bip44_chg_ctx.AddressIndex(i)
    addr = bip44_addr_ctx.PublicKey().ToAddress()
    # Print the derived address
    print(f"Address {i + 1}: {addr}")