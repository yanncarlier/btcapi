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
MAX_ADDRESSES = 10  # Maximum number of addresses that can be generated per request
RATE_LIMIT = 60    # Maximum requests per IP
TIME_FRAME = timedelta(hours=1)  # Time window for rate limiting

# In-memory storage for rate limiting
request_timestamps = {}
rate_limit_lock = threading.Lock()

# FastAPI Application Setup
app = FastAPI(
    title="Bitcoin Address Generation API",
    version="1.0.0",
    description="API for generating Bitcoin mnemonic seeds and various address types (BIP32, BIP44, BIP49, BIP84, BIP86, BIP85) including BIP141-compatible addresses.",
    servers=[
        {"url": "http://127.0.0.1:8000", "description": "Development server"},
        {"url": "https://btc-tx-gw.vercel.app", "description": "Production environment"},
        {"url": "https://btc-tx-gw.bitcoin-tx.com", "description": "Production environment"}
    ]
)

# Replace with your frontend's origin
origins = [
    "http://127.0.0.1:8000",
    "https://7bitcoin-txcom.vercel.app",
    "https://btc-tx-gw.bitcoin-tx.com"
]

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware to add X-Content-Type-Options header
@app.middleware("http")
async def add_x_content_type_options_header(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

# Rate Limiting Middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host
    if not client_ip:
        raise HTTPException(status_code=400, detail="Client IP not found")
    
    current_time = datetime.now()
    window_start = current_time - TIME_FRAME
    
    with rate_limit_lock:
        # Clean up old timestamps
        if client_ip in request_timestamps:
            request_timestamps[client_ip] = [ts for ts in request_timestamps[client_ip] if ts > window_start]
            if not request_timestamps[client_ip]:
                del request_timestamps[client_ip]
        
        # Check rate limit
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
        
        # Calculate remaining requests after this one
        remaining = max(0, RATE_LIMIT - (len(request_timestamps.get(client_ip, [])) + 1))
    
    # Process the request
    response = await call_next(request)
    
    with rate_limit_lock:
        if client_ip not in request_timestamps:
            request_timestamps[client_ip] = []
        request_timestamps[client_ip].append(current_time)
    
    # Set rate limit headers
    response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    return response

# Pydantic Models for Request and Response Validation
class MnemonicResponse(BaseModel):
    BIP39Mnemonic: str
    BIP39Seed: str
    BIP32RootKey: str

class AddressRequest(BaseModel):
    mnemonic: str
    passphrase: Optional[str] = ""
    num_addresses: Optional[int] = 1
    include_private_keys: bool = False
    derivation_path: Optional[str] = "m/0/{index}"  # Default path with placeholder for index

class AddressDetails(BaseModel):
    derivation_path: str
    address: str
    public_key: str
    private_key: Optional[str] = None

class AddressListResponse(BaseModel):
    addresses: list[AddressDetails]

class BrainWalletRequest(BaseModel):
    passphrase: str
    include_private_keys: bool = False

class BrainWalletResponse(BaseModel):
    bitcoin_address: str
    public_key: str
    wif_private_key: Optional[str] = None

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
            # Parse the custom derivation path or use the default
            derivation_path = request.derivation_path.replace("{index}", str(i))
            path_parts = derivation_path.split("/")
            key = root_key
            for part in path_parts[1:]:
                if "'" in part:  # Hardened key
                    key = key.ChildKey(int(part[:-1]) + BIP32_HARDEN)
                else:
                    key = key.ChildKey(int(part))
            address = key.Address()
            public_key = key.PublicKey().hex()
            private_key = key.WalletImportFormat() if request.include_private_keys else None
            addresses.append({
                "derivation_path": derivation_path,
                "address": address,
                "public_key": public_key,
                "private_key": private_key
            })

            # Generate hardened address for the same index
            hardened_derivation_path = derivation_path[:-len(path_parts[-1])] + f"{path_parts[-1]}'"
            hardened_key = root_key
            for part in hardened_derivation_path.split("/")[1:]:
                if "'" in part:  # Hardened key
                    hardened_key = hardened_key.ChildKey(int(part[:-1]) + BIP32_HARDEN)
                else:
                    hardened_key = hardened_key.ChildKey(int(part))
            hardened_address = hardened_key.Address()
            hardened_public_key = hardened_key.PublicKey().hex()
            hardened_private_key = hardened_key.WalletImportFormat() if request.include_private_keys else None
            addresses.append({
                "derivation_path": hardened_derivation_path,
                "address": hardened_address,
                "public_key": hardened_public_key,
                "private_key": hardened_private_key
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
@app.get(
    "/",
    summary="Root Endpoint",
    description="Returns a simple greeting message."
)
async def read_root():
    """Root endpoint returning a simple greeting."""
    return {"Hello": "World"}

@app.get(
    "/generate-mnemonic",
    response_model=MnemonicResponse,
    summary="Generate BIP39 Mnemonic",
    description="Generates a new BIP39 mnemonic phrase and its corresponding seed."
)
async def generate_mnemonic():
    """Generate a new BIP39 mnemonic, seed, and BIP32 Root Key."""
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
    description="Generates a Bitcoin address and keys from a user-provided passphrase using a brain wallet approach."
)
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

@app.post(
    "/generate-bip32-addresses",
    response_model=AddressListResponse,
    summary="Generate BIP32 Addresses",
    description="Generates BIP32 legacy Bitcoin addresses from a mnemonic phrase."
)
async def generate_bip32_addresses(request: AddressRequest = Body(
        ...,
        example={
            "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "passphrase": "",
            "num_addresses": 1,
            "include_private_keys": False,
            "derivation_path": "m/0/{index}"
            }
        )
):
    """Generate BIP32 addresses from a mnemonic."""
    return await _generate_bip32_addresses(request)
    


@app.post(
    "/generate-bip44-addresses",
    response_model=AddressListResponse,
    summary="Generate BIP44 Addresses",
    description="Generates BIP44 legacy Bitcoin addresses (P2PKH) from a mnemonic phrase."
)
async def generate_addresses(
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
    """Generate BIP44 addresses from a mnemonic."""
    if not request.derivation_path:
        request.derivation_path = "m/44'/0'/0'/0/{index}"
    return await _generate_bip_addresses(request, Bip44, Bip44Coins.BITCOIN, 44)

@app.post(
    "/generate-bip49-addresses",
    response_model=AddressListResponse,
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
    """Generate BIP49 (Wrapped SegWit P2SH-P2WPKH) addresses from a mnemonic."""
    # Set default derivation path if not provided
    if not request.derivation_path:
        request.derivation_path = "m/49'/0'/0'/0/{index}"
    return await _generate_bip_addresses(request, Bip49, Bip49Coins.BITCOIN, 49)

@app.post(
    "/generate-bip84-addresses",
    response_model=AddressListResponse,
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
    """Generate BIP84 (Native SegWit P2WPKH) addresses from a mnemonic."""
    # Set default derivation path if not provided
    if not request.derivation_path:
        request.derivation_path = "m/84'/0'/0'/0/{index}"
    return await _generate_bip_addresses(request, Bip84, Bip84Coins.BITCOIN, 84)

# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)