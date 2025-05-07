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
        # {"url": "http://127.0.0.1:8000", "description": "Development server"},
        # {"url": "https://btcapi.vercel.app", "description": "Production environment"},
        {"url": "https://btcapi.bitcoin-tx.com", "description": "Production environment"}
    ]
)

origins = [
    # "http://127.0.0.1:3000",
    # "https://bitcointx.vercel.app",
    "https://*.bitcoin-tx.com"
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
    try:
        if not Bip39MnemonicValidator().IsValid(request.mnemonic):
            raise ValueError("Invalid mnemonic phrase.")
        if request.num_addresses < 1 or request.num_addresses > MAX_ADDRESSES:
            raise ValueError(f"Number of addresses must be between 1 and {MAX_ADDRESSES}")
        seed_bytes = Bip39SeedGenerator(request.mnemonic).Generate(passphrase=request.passphrase)
        root_key = BIP32Key.fromEntropy(seed_bytes)
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
        return {"addresses": addresses}
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
    response_model=AddressListResponse,
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
    return await _generate_bip32_addresses(request)

@app.post(
    "/generate-bip44-addresses",
    response_model=AddressListResponse,
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
    return await _generate_bip_addresses(request, Bip84, Bip84Coins.BITCOIN, 84)

@app.post(
    "/generate-bip86-addresses",
    response_model=AddressListResponse,
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
    return await _generate_bip_addresses(request, Bip86, Bip86Coins.BITCOIN, 86)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)