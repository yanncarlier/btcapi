from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
from typing import Optional
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
app = FastAPI(
    title="Bitcoin Address Generation API",
    version="1.0.0",
    description="An API to generate mnemonic seeds and various types of Bitcoin addresses.",
    servers=[
        {"url": "http://127.0.0.1:8000", "description": "Development server"}
    ]
)
##############################################################
@app.get("/")
def read_root():
    return {"Hello": "World"}
##############################################################
# Endpoint for generating mnemonic# Endpoint for generating mnemonic
class MnemonicResponse(BaseModel):
    BIP39Mnemonic: str
    BIP39Seed: str
@app.get("/generate-mnemonic", response_model=MnemonicResponse)
async def generate_mnemonic():
    from mnemonic import Mnemonic
    mnemonic = Mnemonic("english")
    #Generate word list given the strength (128 - 256):
    words = mnemonic.generate(strength=128)
    # Given the word list generate seed:
    seed = mnemonic.to_seed(words)
    return {
        "BIP39Mnemonic": mnemonic.generate(128),
        "BIP39Seed": seed.hex()
        }
##############################################################
# Endpoint for generating addresses
from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
from typing import Optional
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
class AddressRequest(BaseModel):
    mnemonic: str
    num_addresses: Optional[int] = 5  # Default to 5 addresses
class AddressResponse(BaseModel):
    bip44_addresses: list[str]  # This will hold our generated addresses
@app.post("/generate-addresses", response_model=AddressResponse)
async def generate_addresses(request: AddressRequest = Body(...)):
    try:
        # Generate seed from mnemonic
        seed_bytes = Bip39SeedGenerator(request.mnemonic).Generate()
        # Initialize BIP44 with BTC main net and derive the default account
        bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
        bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
        # Generate addresses
        addresses = []
        for i in range(request.num_addresses):
            bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
            bip44_addr_ctx = bip44_chg_ctx.AddressIndex(i)
            addr = bip44_addr_ctx.PublicKey().ToAddress()
            addresses.append(str(addr))  # Convert to string to ensure JSON serializability
        return {"bip44_addresses": addresses}
    except Exception as e:
        # Log the error for debugging (in production, you'd want to log this more securely)
        print(f"Error generating address: {e}")
        raise HTTPException(status_code=400, detail="Error generating addresses.")
##############################################################
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)