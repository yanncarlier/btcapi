from mnemonic import Mnemonic
from bip32utils import BIP32Key

# Step 2: Generate or input the mnemonic
mnemo = Mnemonic("english")
# mnemonic_phrase = mnemo.generate(strength=128)  # Or use an existing phrase
mnemonic = "caution blush hill vintage park empower coin mystery earth unaware control fault"

print("Mnemonic Phrase:", mnemonic)

# Step 3: Convert mnemonic to seed
seed = mnemo.to_seed(mnemonic, passphrase="")
print("Seed (hex):", seed.hex())

# Step 4: Generate BIP32 root key
root_key = BIP32Key.fromEntropy(seed)

num_addresses = 5  # Number of addresses to generate
for i in range(num_addresses):
    # Step 5: Derive the first Bitcoin address (m/44'/0'/0'/0)
    BIP32_HARDEN = 0x80000000
    address_key = root_key.ChildKey(44 + BIP32_HARDEN) \
                         .ChildKey(0 + BIP32_HARDEN) \
                         .ChildKey(0 + BIP32_HARDEN) \
                         .ChildKey(0) \
                         .ChildKey(0)
    address = address_key.Address()
    private_key = address_key.WalletImportFormat()

    print("++++++++++++++++++++++++++++++++++++++++++++")
    print(f"derivation_path: m/44'/0'/0'/0/{i}")
    print(f"address:", address)
    print(f"public_key:", address_key.PublicKey().hex())
    print(f"private_key:", private_key)