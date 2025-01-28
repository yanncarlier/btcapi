#https://github.com/trezor/python-mnemonic
from mnemonic import Mnemonic
mnemonic = Mnemonic("english")
# print('++++++++++++++++++++++++++++++++++++++++++++++')
# print(mnemonic.generate(128))
print('++++++++++++++++++++++++++++++++++++++++++++++')
#Generate word list given the strength (128 - 256):
words = mnemonic.generate(strength=128)
print('BIP39 Mnemonic: %s' % words)
print('++++++++++++++++++++++++++++++++++++++++++++++')
#Given the word list generate seed:
seed = mnemonic.to_seed(words)
print('BIP39 Seed: %s' % seed.hex())
print('++++++++++++++++++++++++++++++++++++++++++++++')
