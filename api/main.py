# Standard Library Imports
from typing import Optional
import hashlib

# Third-Party Imports
from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
import ecdsa
import base58
from bip_utils import (
    Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes,
    Bip49, Bip49Coins, Bip84, Bip84Coins, Bip86, Bip86Coins,
    Bip39MnemonicValidator
)
from bip32utils import BIP32Key, BIP32_HARDEN
from mnemonic import Mnemonic

# Constants
MAX_ADDRESSES = 42  # Maximum number of addresses that can be generated per request

# FastAPI Application Setup
app = FastAPI(
    title="Bitcoin Address Generation API",
    version="1.0.0",
    description="API for generating Bitcoin mnemonic seeds and various address types (BIP32, BIP44, BIP49, BIP84, BIP86, BIP85) including BIP141-compatible addresses.",
    servers=[
        {"url": "http://127.0.0.1:8000", "description": "Development server"},
        {"url": "https://btc-tx-gw.vercel.app", "description": "Production environment"},
    ]
)

# Pydantic Models for Request and Response Validation
class MnemonicResponse(BaseModel):
    BIP39Mnemonic: str
    BIP39Seed: str

class AddressRequest(BaseModel):
    mnemonic: str
    passphrase: Optional[str] = ""  # Optional passphrase, defaults to empty string
    num_addresses: Optional[int] = 1  # Default to 1 address
    include_private_keys: bool = True  # New field to control private key inclusion

class AddressDetails(BaseModel):
    derivation_path: str
    address: str
    public_key: str
    private_key: Optional[str] = None  # Changed to optional

class AddressListResponse(BaseModel):
    addresses: list[AddressDetails]

class BrainWalletRequest(BaseModel):
    passphrase: str
    include_private_keys: bool = True  # New field to control private key inclusion

class BrainWalletResponse(BaseModel):
    bitcoin_address: str
    public_key: str
    wif_private_key: Optional[str] = None  # Changed to optional

class BIP85Request(BaseModel):
    mnemonic: str
    passphrase: Optional[str] = ""
    app_index: int = 39  # Default to BIP39 mnemonics
    word_count: int = 12  # Default to 12 words
    index: int = 0       # Default to first child

class BIP85Response(BaseModel):
    derivation_path: str
    child_mnemonic: str

# Helper Functions
def generate_brain_wallet(passphrase: str) -> tuple[str, str, str]:
    """Generate a brain wallet from a passphrase."""
    private_key = hashlib.sha256(passphrase.encode('utf-8')).digest()
    wif_private_key = b'\x80' + private_key
    sha = hashlib.sha256(wif_private_key).digest()
    checksum = hashlib.sha256(sha).digest()[:4]
    wif = base58.b58encode(wif_private_key + checksum).decode('utf-8')
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    public_key = b'\x04' + vk.to_string()
    sha_pub = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160', sha_pub).digest()
    bin_addr = b'\x00' + ripemd160
    checksum_addr = hashlib.sha256(hashlib.sha256(bin_addr).digest()).digest()[:4]
    address = base58.b58encode(bin_addr + checksum_addr).decode('utf-8')
    return wif, address, public_key.hex()

async def _generate_bip32_addresses(request: AddressRequest) -> dict:
    """Generate BIP32 addresses using bip32utils."""
    try:
        if not Bip39MnemonicValidator().IsValid(request.mnemonic):
            raise ValueError("Invalid mnemonic phrase.")
        if request.num_addresses < 1 or request.num_addresses > MAX_ADDRESSES:
            raise ValueError(f"Number of addresses must be between 1 and {MAX_ADDRESSES}")
        seed_bytes = Bip39SeedGenerator(request.mnemonic).Generate(passphrase=request.passphrase)
        root_key = BIP32Key.fromEntropy(seed_bytes)
        addresses = []
        for i in range(request.num_addresses):
            address_key = (root_key
                           .ChildKey(32 + BIP32_HARDEN)
                           .ChildKey(0 + BIP32_HARDEN)
                           .ChildKey(0 + BIP32_HARDEN)
                           .ChildKey(0)
                           .ChildKey(i))
            derivation_path = f"m/32'/0'/0'/0/{i}"
            address = address_key.Address()
            public_key = address_key.PublicKey().hex()
            private_key = address_key.WalletImportFormat() if request.include_private_keys else None
            addresses.append({
                "derivation_path": derivation_path,
                "address": address,
                "public_key": public_key,
                "private_key": private_key
            })
        return {"addresses": addresses}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

async def _generate_bip_addresses(request: AddressRequest, bip_class, coin_type, purpose: int) -> dict:
    """Generic helper to generate BIP addresses (BIP44, BIP49, BIP84, BIP86)."""
    try:
        if not Bip39MnemonicValidator().IsValid(request.mnemonic):
            raise ValueError("Invalid mnemonic phrase.")
        if request.num_addresses < 1 or request.num_addresses > MAX_ADDRESSES:
            raise ValueError(f"Number of addresses must be between 1 and {MAX_ADDRESSES}")
        seed_bytes = Bip39SeedGenerator(request.mnemonic).Generate(passphrase=request.passphrase)
        bip_ctx = bip_class.FromSeed(seed_bytes, coin_type).Purpose().Coin().Account(0)
        change_ctx = bip_ctx.Change(Bip44Changes.CHAIN_EXT)
        addresses = []
        for i in range(request.num_addresses):
            addr_ctx = change_ctx.AddressIndex(i)
            public_key_bytes = addr_ctx.PublicKey().RawCompressed().ToBytes()
            derivation_path = f"m/{purpose}'/0'/0'/0/{i}"
            private_key = addr_ctx.PrivateKey().ToWif() if request.include_private_keys else None
            addresses.append({
                "address": str(addr_ctx.PublicKey().ToAddress()),
                "private_key": private_key,
                "public_key": public_key_bytes.hex(),
                "derivation_path": derivation_path
            })
        return {"addresses": addresses}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# API Endpoints
@app.get("/")
async def read_root():
    """Root endpoint returning a simple greeting."""
    return {"Hello": "World"}

@app.get("/generate-mnemonic", response_model=MnemonicResponse)
async def generate_mnemonic():
    """Generate a new BIP39 mnemonic and seed."""
    mnemo = Mnemonic("english")
    words = mnemo.generate(128)  # 128 bits of entropy for 12 words
    seed = mnemo.to_seed(words)
    return {"BIP39Mnemonic": words, "BIP39Seed": seed.hex()}

@app.post("/generate-brain-wallet", response_model=BrainWalletResponse)
async def generate_brain_wallet_endpoint(request: BrainWalletRequest = Body(...)):
    """Generate a brain wallet from a passphrase."""
    try:
        wif, addr, pub_key = generate_brain_wallet(request.passphrase)
        return {
            "bitcoin_address": addr,
            "public_key": pub_key,
            "wif_private_key": wif if request.include_private_keys else None
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/generate-bip32-addresses", response_model=AddressListResponse)
async def generate_bip32_addresses(request: AddressRequest = Body(...)):
    """Generate BIP32 addresses from a mnemonic."""
    return await _generate_bip32_addresses(request)

@app.post("/generate-bip44-addresses", response_model=AddressListResponse)
async def generate_addresses(request: AddressRequest = Body(...)):
    """Generate BIP44 addresses from a mnemonic."""
    return await _generate_bip_addresses(request, Bip44, Bip44Coins.BITCOIN, 44)

@app.post("/generate-bip49-addresses", response_model=AddressListResponse)
async def generate_bip49_addresses(request: AddressRequest = Body(...)):
    """Generate BIP49 (Wrapped SegWit P2SH-P2WPKH) addresses from a mnemonic."""
    return await _generate_bip_addresses(request, Bip49, Bip49Coins.BITCOIN, 49)

@app.post("/generate-bip84-addresses", response_model=AddressListResponse)
async def generate_bip84_addresses(request: AddressRequest = Body(...)):
    """Generate BIP84 (Native SegWit P2WPKH) addresses from a mnemonic."""
    return await _generate_bip_addresses(request, Bip84, Bip84Coins.BITCOIN, 84)

@app.post("/generate-bip86-addresses", response_model=AddressListResponse)
async def generate_bip86_addresses(request: AddressRequest = Body(...)):
    """Generate BIP86 (Taproot) addresses from a mnemonic."""
    return await _generate_bip_addresses(request, Bip86, Bip86Coins.BITCOIN, 86)

@app.post("/generate-bip141-wrapped-segwit-via-bip49", response_model=AddressListResponse)
async def generate_bip141_wrapped_segwit_via_bip49(request: AddressRequest = Body(...)):
    """Generate BIP141-compatible Wrapped SegWit (P2SH-P2WPKH) addresses using BIP49."""
    return await _generate_bip_addresses(request, Bip49, Bip49Coins.BITCOIN, 49)

@app.post("/generate-bip141-native-segwit-via-bip84", response_model=AddressListResponse)
async def generate_bip141_native_segwit_via_bip84(request: AddressRequest = Body(...)):
    """Generate BIP141-compatible Native SegWit (P2WPKH) addresses using BIP84."""
    return await _generate_bip_addresses(request, Bip84, Bip84Coins.BITCOIN, 84)

@app.post("/generate-bip85-child-mnemonic", response_model=BIP85Response)
async def generate_bip85_child_mnemonic(request: BIP85Request = Body(...)):
    """Generate a BIP85 child mnemonic from a master mnemonic."""
    try:
        if not Bip39MnemonicValidator().IsValid(request.mnemonic):
            raise ValueError("Invalid mnemonic phrase.")
        
        mnemo = Mnemonic("english")
        valid_word_counts = [12, 15, 18, 21, 24]
        if request.word_count not in valid_word_counts:
            raise ValueError("Word count must be 12, 15, 18, 21, or 24.")

        word_count_to_entropy_len = {12: 16, 15: 20, 18: 24, 21: 28, 24: 32}
        entropy_len = word_count_to_entropy_len[request.word_count]

        seed = mnemo.to_seed(request.mnemonic, passphrase=request.passphrase)
        master_key = BIP32Key.fromEntropy(seed)

        child_key = (master_key
                     .ChildKey(83696968 + BIP32_HARDEN)  # BIP85 root
                     .ChildKey(request.app_index + BIP32_HARDEN)
                     .ChildKey(request.index + BIP32_HARDEN))

        child_entropy = child_key.PrivateKey()[:entropy_len]
        child_mnemonic = mnemo.to_mnemonic(child_entropy)

        derivation_path = f"m/83696968'/{request.app_index}'/{request.index}'"
        return {
            "derivation_path": derivation_path,
            "child_mnemonic": child_mnemonic
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="An unexpected error occurred.")

# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)