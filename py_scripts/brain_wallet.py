'''
Here's a Python script that generates a Bitcoin brain wallet. Please note that using brain wallets is risky because they depend entirely on the security of the passphrase. If someone else guesses or knows your passphrase, they can access your funds. 
This version of the script that ensures the private key is generated in the WIF (Wallet Import Format) which is more commonly used:
'''
'''
Important Security Notes:
Do not use this method for storing significant amounts of Bitcoin. Brain wallets are not considered secure for current standards.
Passphrase Strength: The security of your wallet depends entirely on the secrecy and complexity of your passphrase. Use long, unique phrases with numbers, special characters, and mixed case.
Backup: Write down the passphrase securely, since losing it means losing access to your funds.
Security Practices: Never share your passphrase or the generated private key with anyone or store it online where it could be compromised.
This code is for educational purposes to illustrate how such systems work. For actual use, consider safer alternatives like hardware wallets or software wallets with robust security features.
'''
'''
WIF Format: The WIF (Wallet Import Format) is now used for the private key, which includes a checksum for error detection. This format starts with '5' or 'K' or 'L' for uncompressed keys or 'c' or 'C' for compressed keys on Bitcoin mainnet. Here, we use the uncompressed format for simplicity.
Security: As before, remember the security caveats. Brain wallets are not recommended for actual use due to their susceptibility to brute-force attacks, especially with weak passphrases.
Testing: Always test the generated keys in a test environment or with very small amounts before using them in production scenarios.
This script should now provide you with a valid WIF private key along with the Bitcoin address. Remember, for actual use, secure your passphrase meticulously, and consider using established wallet software or hardware for better security.
'''
import hashlib
import ecdsa
import base58
def brain_wallet(passphrase):
    # Generate a private key from the passphrase
    private_key = hashlib.sha256(passphrase.encode('utf-8')).digest()
    # Compress the private key by removing leading zeros and adding '80' prefix for WIF
    wif_private_key = b'\x80' + private_key
    # Double SHA256 hash for checksum
    sha = hashlib.sha256()
    sha.update(wif_private_key)
    hash1 = sha.digest()
    sha = hashlib.sha256()
    sha.update(hash1)
    checksum = sha.digest()[:4]
    # Combine private key and checksum
    wif_private_key_with_checksum = wif_private_key + checksum
    # Convert to Base58 for WIF
    wif = base58.b58encode(wif_private_key_with_checksum).decode('utf-8')
    # Create public key
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    public_key = b'\x04' + vk.to_string()
    # Hash for address creation
    sha = hashlib.sha256()
    sha.update(public_key)
    hash1 = sha.digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hash1)
    hash2 = ripemd160.digest()
    # Add network byte for Bitcoin Mainnet
    hash2 = b'\x00' + hash2
    # Double SHA256 hash for checksum of address
    sha = hashlib.sha256()
    sha.update(hash2)
    hash3 = sha.digest()
    sha = hashlib.sha256()
    sha.update(hash3)
    checksum = sha.digest()[:4]
    # Combine hash2 and checksum for the address
    bin_addr = hash2 + checksum
    # Convert to Base58 for the Bitcoin address
    address = base58.b58encode(bin_addr).decode('utf-8')
    return wif, address
# Example usage
passphrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"  # Never use such simple passphrases in real life!
wif, bitcoin_address = brain_wallet(passphrase)
print(f"WIF Private Key: {wif}")
print(f"Bitcoin Address: {bitcoin_address}")