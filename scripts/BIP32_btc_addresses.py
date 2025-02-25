from mnemonic import Mnemonic
from bip32utils import BIP32Key

# Step 2: Generate or input the mnemonic
mnemo = Mnemonic("english")
mnemonic_phrase = mnemo.generate(strength=128)  # Or use an existing phrase
print("Mnemonic Phrase:", mnemonic_phrase)

# Step 3: Convert mnemonic to seed
seed = mnemo.to_seed(mnemonic_phrase, passphrase="")
print("Seed (hex):", seed.hex())

# Step 4: Generate BIP32 root key
root_key = BIP32Key.fromEntropy(seed)

# Step 5: Derive the first Bitcoin address (m/32'/0'/0'/0)
BIP32_HARDEN = 0x80000000
address_key = root_key.ChildKey(32 + BIP32_HARDEN) \
                     .ChildKey(0 + BIP32_HARDEN) \
                     .ChildKey(0 + BIP32_HARDEN) \
                     .ChildKey(0) \
                     .ChildKey(0)
address = address_key.Address()
private_key = address_key.WalletImportFormat()

print("Path: m/32'/0'/0'/0")
print("Public Key (Hex):", address_key.PublicKey().hex())
print("Bitcoin Address:", address)
print("Private Key (WIF):", private_key)