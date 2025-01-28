from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
from typing import Optional
import hashlib
import ecdsa
import base58
from bip_utils import (
    Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes,
    Bip49, Bip49Coins, Bip84, Bip84Coins, Bip86, Bip86Coins
)
app = FastAPI(
    title="Bitcoin Address Generation API",
    version="1.0.0",
    description="An API to generate mnemonic seeds and various types of Bitcoin addresses.",
    servers=[
        {"url": "http://127.0.0.1:8000", "description": "Development server"}
    ]
)
# Pydantic Models
class MnemonicResponse(BaseModel):
    BIP39Mnemonic: str
    BIP39Seed: str
class AddressRequest(BaseModel):
    mnemonic: str
    num_addresses: Optional[int] = 5
class AddressDetails(BaseModel):
    address: str
    private_key: str
    public_key: str
    derivation_path: str
    hardened: bool  # New field to indicate hardening
class AddressListResponse(BaseModel):
    addresses: list[AddressDetails]
class BrainWalletRequest(BaseModel):
    passphrase: str
class BrainWalletResponse(BaseModel):
    wif_private_key: str
    bitcoin_address: str
    public_key: str
# Helper function for brain wallet (unchanged)
def generate_brain_wallet(passphrase):
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
# Endpoints
@app.get("/")
def read_root():
    return {"Hello": "World"}
@app.get("/generate-mnemonic", response_model=MnemonicResponse)
async def generate_mnemonic():
    from mnemonic import Mnemonic
    mnemo = Mnemonic("english")
    words = mnemo.generate(128)
    seed = mnemo.to_seed(words)
    return {"BIP39Mnemonic": words, "BIP39Seed": seed.hex()}
@app.post("/generate-addresses", response_model=AddressListResponse)
async def generate_addresses(request: AddressRequest = Body(...)):
    return await _generate_bip_addresses(request, Bip44, Bip44Coins.BITCOIN, 44)
@app.post("/generate-bip49-addresses", response_model=AddressListResponse)
async def generate_bip49_addresses(request: AddressRequest = Body(...)):
    return await _generate_bip_addresses(request, Bip49, Bip49Coins.BITCOIN, 49)
@app.post("/generate-bip84-addresses", response_model=AddressListResponse)
async def generate_bip84_addresses(request: AddressRequest = Body(...)):
    return await _generate_bip_addresses(request, Bip84, Bip84Coins.BITCOIN, 84)
@app.post("/generate-bip86-addresses", response_model=AddressListResponse)
async def generate_bip86_addresses(request: AddressRequest = Body(...)):
    return await _generate_bip_addresses(request, Bip86, Bip86Coins.BITCOIN, 86)
@app.post("/generate-bip141-addresses", response_model=AddressListResponse)
async def generate_bip141_addresses(request: AddressRequest = Body(...)):
    return await _generate_bip_addresses(request, Bip49, Bip49Coins.BITCOIN, 49)
async def _generate_bip_addresses(request: AddressRequest, bip_class, coin_type, purpose: int):
    try:
        seed_bytes = Bip39SeedGenerator(request.mnemonic).Generate()
        bip_ctx = bip_class.FromSeed(seed_bytes, coin_type).Purpose().Coin().Account(0)
        # Standard change (external chain, non-hardened)
        change_ctx_std = bip_ctx.Change(Bip44Changes.CHAIN_EXT)
        # Hardened change (external chain, hardened)
        change_ctx_hard = bip_ctx.Change(Bip44Changes.CHAIN_EXT + 0x80000000)
        addresses = []
        for i in range(request.num_addresses):
            # Standard addresses
            addr_ctx_std = change_ctx_std.AddressIndex(i)
            public_key_std = addr_ctx_std.PublicKey().RawCompressed().ToBytes()
            addresses.append({
                "address": str(addr_ctx_std.PublicKey().ToAddress()),
                "private_key": addr_ctx_std.PrivateKey().ToWif(),
                "public_key": public_key_std.hex(),
                "derivation_path": f"m/{purpose}'/0'/0'/0/{i}",
                "hardened": False
            })
            # Hardened addresses (change and index hardened)
            addr_ctx_hard = change_ctx_hard.AddressIndex(i + 0x80000000)
            public_key_hard = addr_ctx_hard.PublicKey().RawCompressed().ToBytes()
            addresses.append({
                "address": str(addr_ctx_hard.PublicKey().ToAddress()),
                "private_key": addr_ctx_hard.PrivateKey().ToWif(),
                "public_key": public_key_hard.hex(),
                "derivation_path": f"m/{purpose}'/0'/0'/0'/{i}'",
                "hardened": True
            })
        return {"addresses": addresses}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
@app.post("/generate-brain-wallet", response_model=BrainWalletResponse)
async def generate_brain_wallet_endpoint(request: BrainWalletRequest = Body(...)):
    try:
        wif, addr, pub_key = generate_brain_wallet(request.passphrase)
        return {
            "wif_private_key": wif,
            "bitcoin_address": addr,
            "public_key": pub_key
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)