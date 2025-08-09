# Standard Library Imports
from typing import Optional
import hashlib
import threading
from datetime import datetime, timedelta

# Third-Party Imports
from fastapi import FastAPI, HTTPException, Body, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import base58
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from bip_utils import (
    Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes,
    Bip49, Bip49Coins, Bip84, Bip84Coins, Bip39MnemonicValidator,
    Bip86, Bip86Coins
)
from bip32utils import BIP32Key, BIP32_HARDEN
from mnemonic import Mnemonic

# Constants
MAX_ADDRESSES = 10
RATE_LIMIT = 60
TIME_FRAME = timedelta(hours=1)

# In-memory storage for rate limiting
request_timestamps = {}
rate_limit_lock = threading.Lock()

# FastAPI Application Setup
app = FastAPI(
    title="Bitcoin Address Generation API",
    version="1.0.0",
    description="API for generating Bitcoin mnemonic seeds and various address types (BIP32, BIP44, BIP49, BIP84, BIP86).",
    servers=[
       # {"url": "http://127.0.0.1:8000/", "description": "Development server"},
        {"url": "https://btcapi.bitcoin-tx.com", "description": "Production environment"}
    ]
)

origins = [
    "https://btcapi.bitcoin-tx.com",
    "https://www.bitcoin-tx.com",
    "https://bitcoin-tx.com",
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_x_content_type_options_header(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host
    if not client_ip:
        raise HTTPException(status_code=400, detail="Client IP not found")
    
    current_time = datetime.now()
    window_start = current_time - TIME_FRAME
    
    with rate_limit_lock:
        if client_ip in request_timestamps:
            request_timestamps[client_ip] = [ts for ts in request_timestamps[client_ip] if ts > window_start]
            if not request_timestamps[client_ip]:
                del request_timestamps[client_ip]
        
        if len(request_timestamps.get(client_ip, [])) >= RATE_LIMIT:
            response = JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded"}
            )
            response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT)
            response.headers["X-RateLimit-Remaining"] = "0"
            if request_timestamps.get(client_ip):
                oldest_ts = request_timestamps[client_ip][0]
                retry_after = (oldest_ts + TIME_FRAME - current_time).total_seconds()
                response.headers["Retry-After"] = str(int(retry_after))
            return response
        
        remaining = max(0, RATE_LIMIT - (len(request_timestamps.get(client_ip, [])) + 1))
    
    response = await call_next(request)
    
    with rate_limit_lock:
        if client_ip not in request_timestamps:
            request_timestamps[client_ip] = []
        request_timestamps[client_ip].append(current_time)
    
    response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    return response

# Pydantic Models
class MnemonicResponse(BaseModel):
    BIP39Mnemonic: str
    BIP39Seed: str
    BIP32RootKey: str

class AddressRequest(BaseModel):
    mnemonic: str
    passphrase: Optional[str] = ""
    num_addresses: Optional[int] = 1
    include_private_keys: bool = False
    derivation_path: Optional[str] = "m/0/{index}"

class AddressDetails(BaseModel):
    derivation_path: str
    address: str
    public_key: str
    private_key: Optional[str] = None
    wif: Optional[str] = None

class Bip32AddressDetails(BaseModel):
    derivation_path: str
    address: str
    public_key: str
    private_key: Optional[str] = None
    wif: Optional[str] = None

class Bip32AddressListResponse(BaseModel):
    account_xpub: str
    bip32_xpub: str
    addresses: list[Bip32AddressDetails]

class BrainWalletRequest(BaseModel):
    passphrase: str
    include_private_keys: bool = False

class BrainWalletResponse(BaseModel):
    bitcoin_address: str
    public_key: str
    wif_private_key: Optional[str] = None

# Helper Functions
def generate_brain_wallet(passphrase: str) -> tuple[str, str, str]:
    # Generate a private key from the passphrase
    private_key_bytes = hashlib.sha256(passphrase.encode('utf-8')).digest()
    
    # Load the private key into cryptography's ECDSA
    private_key = ec.derive_private_key(
        int.from_bytes(private_key_bytes, 'big'),
        ec.SECP256K1()
    )
    
    # Get WIF private key
    wif_private_key = b'\x80' + private_key_bytes
    sha = hashlib.sha256()
    sha.update(wif_private_key)
    hash1 = sha.digest()
    sha = hashlib.sha256()
    sha.update(hash1)
    checksum = sha.digest()[:4]
    wif = base58.b58encode(wif_private_key + checksum).decode('utf-8')
    
    # Create public key
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    # Hash for address creation
    sha = hashlib.sha256()
    sha.update(public_key)
    hash1 = sha.digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hash1)
    hash2 = ripemd160.digest()
    
    # Add network byte for Bitcoin Mainnet
    bin_addr = b'\x00' + hash2
    checksum_addr = hashlib.sha256(hashlib.sha256(bin_addr).digest()).digest()[:4]
    address = base58.b58encode(bin_addr + checksum_addr).decode('utf-8')
    
    return wif, address, public_key.hex()

async def _generate_bip32_addresses(request: AddressRequest) -> dict:
    try:
        if not Bip39MnemonicValidator().IsValid(request.mnemonic):
            raise ValueError("Invalid mnemonic phrase.")
        if request.num_addresses < 1 or request.num_addresses > MAX_ADDRESSES:
            raise ValueError(f"Number of addresses must be between 1 and {MAX_ADDRESSES}")

        seed_bytes = Bip39SeedGenerator(request.mnemonic).Generate(passphrase=request.passphrase)
        root_key = BIP32Key.fromEntropy(seed_bytes)

        parts = request.derivation_path.split('/')
        if parts[-1] != '{index}':
            raise ValueError("Derivation path must end with '/{index}'")
        base_parts = parts[:-1]  # e.g., ['m', '0\'', '0']
        account_parts = parts[:-2]  # e.g., ['m', '0\'']
        base_path = '/'.join(base_parts)
        account_path = '/'.join(account_parts) if len(account_parts) > 1 else "m"

        # Derive account_xpub (one level above base_key)
        account_key = root_key
        for part in account_parts[1:]:
            if "'" in part:
                index = int(part[:-1]) + BIP32_HARDEN
            else:
                index = int(part)
            account_key = account_key.ChildKey(index)
        account_xpub = account_key.ExtendedKey(private=False)

        # Derive bip32_xpub (base_key level)
        base_key = root_key
        for part in base_parts[1:]:
            if "'" in part:
                index = int(part[:-1]) + BIP32_HARDEN
            else:
                index = int(part)
            base_key = base_key.ChildKey(index)
        bip32_xpub = base_key.ExtendedKey(private=False)

        addresses = []
        for i in range(request.num_addresses):
            derivation_path = request.derivation_path.replace("{index}", str(i))
            path_parts = derivation_path.split("/")
            key = root_key
            for part in path_parts[1:]:
                if "'" in part:
                    key = key.ChildKey(int(part[:-1]) + BIP32_HARDEN)
                else:
                    key = key.ChildKey(int(part))
            address = key.Address()
            public_key = key.PublicKey().hex()
            if request.include_private_keys:
                private_key = key.PrivateKey().hex()
                wif = key.WalletImportFormat()
            else:
                private_key = None
                wif = None
            addresses.append({
                "derivation_path": derivation_path,
                "address": address,
                "public_key": public_key,
                "private_key": private_key,
                "wif": wif
            })

        return {
            "account_xpub": account_xpub,
            "bip32_xpub": bip32_xpub,
            "addresses": addresses
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

async def _generate_bip_addresses(request: AddressRequest, bip_class, coin_type, purpose: int) -> dict:
    try:
        if not Bip39MnemonicValidator().IsValid(request.mnemonic):
            raise ValueError("Invalid mnemonic phrase.")
        if request.num_addresses < 1 or request.num_addresses > MAX_ADDRESSES:
            raise ValueError(f"Number of addresses must be between 1 and {MAX_ADDRESSES}")
        
        seed_bytes = Bip39SeedGenerator(request.mnemonic).Generate(passphrase=request.passphrase)
        bip_ctx = bip_class.FromSeed(seed_bytes, coin_type).Purpose().Coin().Account(0)
        change_ctx = bip_ctx.Change(Bip44Changes.CHAIN_EXT)
        
        # Compute account_xpub at the account level (e.g., m/44'/0'/0')
        account_xpub = bip_ctx.PublicKey().ToExtended()
        # Compute bip32_xpub at the change level (e.g., m/44'/0'/0'/0)
        bip32_xpub = change_ctx.PublicKey().ToExtended()
        
        addresses = []
        for i in range(request.num_addresses):
            addr_ctx = change_ctx.AddressIndex(i)
            public_key_bytes = addr_ctx.PublicKey().RawCompressed().ToBytes()
            derivation_path = f"m/{purpose}'/0'/0'/0/{i}"
            if request.include_private_keys:
                private_key = addr_ctx.PrivateKey().Raw().ToHex()
                wif = addr_ctx.PrivateKey().ToWif()
            else:
                private_key = None
                wif = None
            addresses.append({
                "derivation_path": derivation_path,
                "address": str(addr_ctx.PublicKey().ToAddress()),
                "public_key": public_key_bytes.hex(),
                "private_key": private_key,
                "wif": wif
            })
        return {
            "account_xpub": account_xpub,
            "bip32_xpub": bip32_xpub,
            "addresses": addresses
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# API Endpoints
@app.get(
    "/",
    summary="Root Endpoint",
    description="Returns a simple greeting message."
)
async def read_root():
    return {"Hello": "World"}

@app.get(
    "/generate-mnemonic",
    response_model=MnemonicResponse,
    summary="Generate BIP39 Mnemonic",
    description="Generates a new BIP39 mnemonic phrase and its corresponding seed."
)
async def generate_mnemonic():
    mnemo = Mnemonic("english")
    words = mnemo.generate(128)
    seed = mnemo.to_seed(words)
    bip32_root_key = BIP32Key.fromEntropy(seed).ExtendedKey()
    return {
        "BIP39Mnemonic": words,
        "BIP39Seed": seed.hex(),
        "BIP32RootKey": bip32_root_key
    }

@app.post(
    "/generate-brain-wallet",
    response_model=BrainWalletResponse,
    summary="Generate Brain Wallet",
    description="Generates a Bitcoin address and keys from a passphrase."
)
async def generate_brain_wallet_endpoint(request: BrainWalletRequest = Body(...)):
    try:
        wif, addr, pub_key = generate_brain_wallet(request.passphrase)
        return {
            "bitcoin_address": addr,
            "public_key": pub_key,
            "wif_private_key": wif if request.include_private_keys else None
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post(
    "/generate-bip32-addresses",
    response_model=Bip32AddressListResponse,
    summary="Generate BIP32 Addresses (custom derivation paths)",
    description="Generates BIP32 legacy Bitcoin addresses from a mnemonic phrase with custom derivation paths."
)
async def generate_bip32_addresses(request: AddressRequest = Body(
    ...,
    example={
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "passphrase": "",
        "num_addresses": 1,
        "include_private_keys": False,
        "derivation_path": "m/0'/0/{index}"
    }
)):
    result = await _generate_bip32_addresses(request)
    return Bip32AddressListResponse(
        account_xpub=result["account_xpub"],
        bip32_xpub=result["bip32_xpub"],
        addresses=[Bip32AddressDetails(**addr) for addr in result["addresses"]]
    )

@app.post(
    "/generate-bip44-addresses",
    response_model=Bip32AddressListResponse,
    summary="Generate BIP44 Addresses",
    description="Generates BIP44 legacy Bitcoin addresses (P2PKH) from a mnemonic phrase."
)
async def generate_bip44_addresses(
    request: AddressRequest = Body(
        ...,
        example={
            "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "passphrase": "",
            "num_addresses": 1,
            "include_private_keys": False
        }
    )
):
    result = await _generate_bip_addresses(request, Bip44, Bip44Coins.BITCOIN, 44)
    return Bip32AddressListResponse(
        account_xpub=result["account_xpub"],
        bip32_xpub=result["bip32_xpub"],
        addresses=[Bip32AddressDetails(**addr) for addr in result["addresses"]]
    )

@app.post(
    "/generate-bip49-addresses",
    response_model=Bip32AddressListResponse,
    summary="Generate BIP49 Addresses",
    description="Generates BIP49 Wrapped SegWit (P2SH-P2WPKH) Bitcoin addresses from a mnemonic phrase."
)
async def generate_bip49_addresses(
    request: AddressRequest = Body(
        ...,
        example={
            "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "passphrase": "",
            "num_addresses": 1,
            "include_private_keys": False
        }
    )
):
    result = await _generate_bip_addresses(request, Bip49, Bip49Coins.BITCOIN, 49)
    return Bip32AddressListResponse(
        account_xpub=result["account_xpub"],
        bip32_xpub=result["bip32_xpub"],
        addresses=[Bip32AddressDetails(**addr) for addr in result["addresses"]]
    )

@app.post(
    "/generate-bip84-addresses",
    response_model=Bip32AddressListResponse,
    summary="Generate BIP84 Addresses",
    description="Generates BIP84 Native SegWit (P2WPKH) Bitcoin addresses from a mnemonic phrase."
)
async def generate_bip84_addresses(
    request: AddressRequest = Body(
        ...,
        example={
            "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "passphrase": "",
            "num_addresses": 1,
            "include_private_keys": False
        }
    )
):
    result = await _generate_bip_addresses(request, Bip84, Bip84Coins.BITCOIN, 84)
    return Bip32AddressListResponse(
        account_xpub=result["account_xpub"],
        bip32_xpub=result["bip32_xpub"],
        addresses=[Bip32AddressDetails(**addr) for addr in result["addresses"]]
    )

@app.post(
    "/generate-bip86-addresses",
    response_model=Bip32AddressListResponse,
    summary="Generate BIP86 Addresses",
    description="Generates BIP86 Taproot (P2TR) Bitcoin addresses from a mnemonic phrase."
)
async def generate_bip86_addresses(
    request: AddressRequest = Body(
        ...,
        example={
            "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "passphrase": "",
            "num_addresses": 1,
            "include_private_keys": False
        }
    )
):
    result = await _generate_bip_addresses(request, Bip86, Bip86Coins.BITCOIN, 86)
    return Bip32AddressListResponse(
        account_xpub=result["account_xpub"],
        bip32_xpub=result["bip32_xpub"],
        addresses=[Bip32AddressDetails(**addr) for addr in result["addresses"]]
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)