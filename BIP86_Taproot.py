'''
In the BIP86 context, you need to derive down to the change level before you can derive individual addresses. The full derivation path for BIP86 should be m/86'/0'/0'/0/i where:
86' is the purpose for Taproot (BIP86)
0' is for Bitcoin mainnet
0' is the account (you can have multiple accounts, but here we're using the first one)
0 is for external (receiving) addresses (0 for external, 1 for internal/change)
i is the index of the address
'''
'''
Explanation:
Change Level: We added bip86_chg_ctx = bip86_acc_ctx.Change(Bip44Changes.CHAIN_EXT) to move to the correct depth in the derivation path. Bip44Changes.CHAIN_EXT represents external (receiving) addresses.
Address Derivation: After moving to the change level, we can then derive individual addresses with bip86_chg_ctx.AddressIndex(i).
'''
from bip_utils import Bip39SeedGenerator, Bip86, Bip86Coins, Bip44Changes
# Example BIP39 mnemonic seed phrase
mnemonic = "caution blush hill vintage park empower coin mystery earth unaware control fault"
# Generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
# Initialize BIP86 with BTC main net and derive the default account
bip86_mst_ctx = Bip86.FromSeed(seed_bytes, Bip86Coins.BITCOIN)
bip86_acc_ctx = bip86_mst_ctx.Purpose().Coin().Account(0)
# Derive to the change level (0 for external addresses)
bip86_chg_ctx = bip86_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
# Generate Taproot addresses
num_addresses = 5  # Number of Taproot addresses to generate
for i in range(num_addresses):
    bip86_addr_ctx = bip86_chg_ctx.AddressIndex(i)
    addr = bip86_addr_ctx.PublicKey().ToAddress()
    # Print the derived Taproot address
    print(f"Taproot Address {i + 1}: {addr}")