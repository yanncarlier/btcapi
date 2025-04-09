# https://github.com/trezor/python-mnemonic
from mnemonic import Mnemonic
import bip32utils  # Ensure you have this library installed

mnemonic = Mnemonic("english")
print('++++++++++++++++++++++++++++++++++++++++++++++')
# Generate word list given the strength (128 - 256):
words = mnemonic.generate(strength=128)
print('BIP39 Mnemonic: %s' % words)
print('++++++++++++++++++++++++++++++++++++++++++++++')
# Given the word list generate seed:
seed = mnemonic.to_seed(words)
print('BIP39 Seed: %s' % seed.hex())
print('++++++++++++++++++++++++++++++++++++++++++++++')
# Generate BIP32 Root Key:
bip32_root_key = bip32utils.BIP32Key.fromEntropy(seed)
print('BIP32 Root Key: %s' % bip32_root_key.ExtendedKey())
print('++++++++++++++++++++++++++++++++++++++++++++++')
