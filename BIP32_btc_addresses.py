from bip_utils import Bip39SeedGenerator, Bip32, Bip32KeyData, Bip32Path, Bip32KeyNetVersions
# Mnemonic phrase (replace with your own)
mnemonic = "caution blush hill vintage park empower coin mystery earth unaware control fault"
# Generate the seed from the mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
# Define BIP32 network versions for Bitcoin (mainnet)
net_ver = Bip32KeyNetVersions(
    bip32_pub_key=b"\x04\x88\xB2\x1E",
    bip32_priv_key=b"\x04\x88\xAD\xE4"
)
# Initialize BIP32 master key
bip32_mst_ctx = Bip32.FromSeedAndNetVersions(seed_bytes, net_ver)
# Derive a key using a custom BIP32 path (example: m/0'/1)
derived_ctx = bip32_mst_ctx.DerivePath(Bip32Path("m/0'/1"))
# Get the public key and convert to address
pub_key = derived_ctx.PublicKey().ToAddress()
print(f"Generated Address: {pub_key}")
# Example of generating multiple addresses
for i in range(5):
    derived_ctx = bip32_mst_ctx.DerivePath(Bip32Path(f"m/0'/{i}"))
    print(f"Address {i}: {derived_ctx.PublicKey().ToAddress()}")
