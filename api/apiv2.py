from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
from typing import Optional
from bip_utils import (
    Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes,
    Bip49, Bip49Coins, Bip84, Bip84Coins, Bip86, Bip86Coins
)
import hashlib
import ecdsa
import base58
app = FastAPI(
    title="Bitcoin Address Generation API",
    version="1.0.0",
    description="An API to generate mnemonic seeds and various types of Bitcoin addresses.",
    servers=[
        {"url": "http://127.0.0.1:8000", "description": "Development server"}
    ]
)
# Existing models and endpoints
class MnemonicResponse(BaseModel):
    BIP39Mnemonic: str
    BIP39Seed: str
class AddressRequest(BaseModel):
    mnemonic: str
    num_addresses: Optional[int] = 5
class AddressResponse(BaseModel):
    bip44_addresses: list[str]
# New response models
class BIP49AddressResponse(BaseModel):
    bip49_addresses: list[str]
class BIP84AddressResponse(BaseModel):
    bip84_addresses: list[str]
class BIP86AddressResponse(BaseModel):
    bip86_addresses: list[str]
class BrainWalletResponse(BaseModel):
    wif: str
    address: str
@app.get("/")
def read_root():
    return {"Hello": "World"}
@app.get("/generate-mnemonic", response_model=MnemonicResponse)
async def generate_mnemonic():
    from mnemonic import Mnemonic
    mnemonic = Mnemonic("english")
    words = mnemonic.generate(strength=128)
    seed = mnemonic.to_seed(words)
    return {
        "BIP39Mnemonic": words,
        "BIP39Seed": seed.hex()
    }
@app.post("/generate-addresses", response_model=AddressResponse)
async def generate_addresses(request: AddressRequest = Body(...)):
    try:
        seed_bytes = Bip39SeedGenerator(request.mnemonic).Generate()
        bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
        bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
        addresses = []
        for i in range(request.num_addresses):
            bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
            bip44_addr_ctx = bip44_chg_ctx.AddressIndex(i)
            addr = bip44_addr_ctx.PublicKey().ToAddress()
            addresses.append(str(addr))
        return {"bip44_addresses": addresses}
    except Exception as e:
        print(f"Error generating addresses: {e}")
        raise HTTPException(status_code=400, detail="Error generating addresses.")
# New endpoints
@app.post("/generate-bip49-addresses", response_model=BIP49AddressResponse)
async def generate_bip49_addresses(request: AddressRequest = Body(...)):
    try:
        seed_bytes = Bip39SeedGenerator(request.mnemonic).Generate()
        bip49_mst_ctx = Bip49.FromSeed(seed_bytes, Bip49Coins.BITCOIN)
        bip49_acc_ctx = bip49_mst_ctx.Purpose().Coin().Account(0)
        addresses = []
        for i in range(request.num_addresses):
            bip49_chg_ctx = bip49_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
            bip49_addr_ctx = bip49_chg_ctx.AddressIndex(i)
            addr = bip49_addr_ctx.PublicKey().ToAddress()
            addresses.append(str(addr))
        return {"bip49_addresses": addresses}
    except Exception as e:
        print(f"Error generating BIP49 addresses: {e}")
        raise HTTPException(status_code=400, detail="Error generating BIP49 addresses.")
@app.post("/generate-bip84-addresses", response_model=BIP84AddressResponse)
async def generate_bip84_addresses(request: AddressRequest = Body(...)):
    try:
        seed_bytes = Bip39SeedGenerator(request.mnemonic).Generate()
        bip84_mst_ctx = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)
        bip84_acc_ctx = bip84_mst_ctx.Purpose().Coin().Account(0)
        addresses = []
        for i in range(request.num_addresses):
            bip84_chg_ctx = bip84_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
            bip84_addr_ctx = bip84_chg_ctx.AddressIndex(i)
            addr = bip84_addr_ctx.PublicKey().ToAddress()
            addresses.append(str(addr))
        return {"bip84_addresses": addresses}
    except Exception as e:
        print(f"Error generating BIP84 addresses: {e}")
        raise HTTPException(status_code=400, detail="Error generating BIP84 addresses.")
@app.post("/generate-bip86-addresses", response_model=BIP86AddressResponse)
async def generate_bip86_addresses(request: AddressRequest = Body(...)):
    try:
        seed_bytes = Bip39SeedGenerator(request.mnemonic).Generate()
        bip86_mst_ctx = Bip86.FromSeed(seed_bytes, Bip86Coins.BITCOIN)
        bip86_acc_ctx = bip86_mst_ctx.Purpose().Coin().Account(0)
        bip86_chg_ctx = bip86_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
        addresses = []
        for i in range(request.num_addresses):
            bip86_addr_ctx = bip86_chg_ctx.AddressIndex(i)
            addr = bip86_addr_ctx.PublicKey().ToAddress()
            addresses.append(str(addr))
        return {"bip86_addresses": addresses}
    except Exception as e:
        print(f"Error generating BIP86 addresses: {e}")
        raise HTTPException(status_code=400, detail="Error generating BIP86 addresses.")
@app.post("/generate-brain-wallet", response_model=BrainWalletResponse)
async def generate_brain_wallet(request: dict = Body(...)):
    try:
        passphrase = request.get("passphrase")
        if not passphrase:
            raise ValueError("Passphrase is required.")
        private_key = hashlib.sha256(passphrase.encode('utf-8')).digest()
        wif_private_key = b'\x80' + private_key
        sha = hashlib.sha256(wif_private_key).digest()
        checksum = hashlib.sha256(sha).digest()[:4]
        wif_private_key_with_checksum = wif_private_key + checksum
        wif = base58.b58encode(wif_private_key_with_checksum).decode('utf-8')
        sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        public_key = b'\x04' + vk.to_string()
        hash1 = hashlib.sha256(public_key).digest()
        ripemd160 = hashlib.new('ripemd160', hash1).digest()
        hash2 = b'\x00' + ripemd160
        hash3 = hashlib.sha256(hash2).digest()
        checksum = hashlib.sha256(hash3).digest()[:4]
        bin_addr = hash2 + checksum
        address = base58.b58encode(bin_addr).decode('utf-8')
        return {"wif": wif, "address": address}
    except Exception as e:
        print(f"Error generating brain wallet: {e}")
        raise HTTPException(status_code=400, detail=str(e))
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)