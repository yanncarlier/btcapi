'''
BIP84 (Bitcoin Improvement Proposal 84) introduces native SegWit addresses for Bitcoin, using the bc1q... format. This differs from BIP44 for legacy addresses or BIP49 for wrapped SegWit addresses. 
'''
'''
Explanation:
Mnemonic: Replace "your bip39 mnemonic here" with your actual BIP39 seed phrase.
Seed Generation: Converts the mnemonic into a seed using Bip39SeedGenerator.
BIP84 Derivation: 
Bip84.FromSeed initializes the BIP84 context for Bitcoin. 
The derivation path for BIP84 is m/84'/0'/0'/0/i, where:
84' signifies BIP84 (native SegWit)
0' is for Bitcoin mainnet
0' is for the first account (you can have multiple accounts)
0 for external addresses (change=0 for receiving, change=1 for internal/change addresses)
i is the address index.
Address Generation: We derive to the change level (for external addresses) before deriving individual addresses.
Key Points:
Security: Always handle your mnemonic phrase securely to protect your funds.
Compatibility: BIP84 addresses (bc1q...) are only supported by wallets that have implemented native SegWit. Ensure compatibility before using these addresses for transactions.
Usage: These addresses offer better scalability and transaction privacy compared to legacy addresses.
This script will generate native SegWit addresses that can be used for receiving Bitcoin with the BIP84 standard. Remember to manage your keys securely.
'''
from bip_utils import Bip39SeedGenerator, Bip84, Bip84Coins, Bip44Changes
# Example BIP39 mnemonic seed phrase
mnemonic = "caution blush hill vintage park empower coin mystery earth unaware control fault"
# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
# Initialize BIP84 with BTC main net and derive the default account
bip84_mst_ctx = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)
bip84_acc_ctx = bip84_mst_ctx.Purpose().Coin().Account(0)
# Generate BIP84 addresses
num_addresses = 5  # Number of BIP84 addresses to generate
for i in range(num_addresses):
    bip84_chg_ctx = bip84_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
    bip84_addr_ctx = bip84_chg_ctx.AddressIndex(i)
    addr = bip84_addr_ctx.PublicKey().ToAddress()
    # Print the derived BIP84 address
    print(f"BIP84 Address {i + 1}: {addr}")