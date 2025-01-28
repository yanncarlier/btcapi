'''
To generate SegWit (Segregated Witness) addresses from a BIP39 seed phrase in Python, you'll need to adjust the derivation path and use the appropriate address type. SegWit introduced new address formats which are more efficient and enable better scalability for Bitcoin. Here are the two main SegWit address formats:
P2WPKH (Pay to Witness Public Key Hash) - Native SegWit: Starts with bc1q...
P2SH-P2WPKH (Pay to Script Hash - Pay to Witness Public Key Hash) - Wrapped SegWit: Starts with 3...
'''
'''
Explanation:
Native SegWit (P2WPKH):
Uses BIP44 derivation path m/44'/0'/0'/0/i. 
These addresses start with bc1q....
Wrapped SegWit (P2SH-P2WPKH):
Uses BIP49 derivation path m/49'/0'/0'/0/i.
These addresses start with 3... and are backwards compatible with older software that might not support native SegWit.
Key Points:
Ensure you have the correct mnemonic phrase entered for mnemonic.
BIP44 is used for native SegWit addresses, while BIP49 is used for wrapped SegWit addresses.
Security considerations: Never expose your mnemonic phrase or derived private keys.
Remember, handling cryptographic keys and addresses involves significant security risks. Always use secure methods for generating and storing your keys, and ensure that your environment is secure when dealing with these operations.
'''
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes, Bip49, Bip49Coins
# Example BIP39 mnemonic seed phrase
mnemonic = "caution blush hill vintage park empower coin mystery earth unaware control fault"
# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
# Generate Native SegWit (P2WPKH) addresses
bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
for i in range(5):  # Generate 5 addresses
    bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
    bip44_addr_ctx = bip44_chg_ctx.AddressIndex(i)
    addr = bip44_addr_ctx.PublicKey().ToAddress()
    print(f"Native SegWit Address {i + 1}: {addr}")
print("\n")
# Generate Wrapped SegWit (P2SH-P2WPKH) addresses using BIP49
bip49_mst_ctx = Bip49.FromSeed(seed_bytes, Bip49Coins.BITCOIN)
bip49_acc_ctx = bip49_mst_ctx.Purpose().Coin().Account(0)
for i in range(5):  # Generate 5 addresses
    bip49_chg_ctx = bip49_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
    bip49_addr_ctx = bip49_chg_ctx.AddressIndex(i)
    addr = bip49_addr_ctx.PublicKey().ToAddress()
    print(f"Wrapped SegWit Address {i + 1}: {addr}")