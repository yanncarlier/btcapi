from typing import Union
from pydantic import BaseModel
from fastapi import FastAPI, Body
from fastapi import FastAPI, HTTPException, Depends, Body
from typing import Optional
# from pydantic import BaseModel
app = FastAPI()
############################
class MnemonicRequest(BaseModel):
    numWords: Optional[int] = 24
class MnemonicResponse(BaseModel):
    BIP39Mnemonic: str
    BIP39Seed: str
@app.get("/")
def read_root():
    return {"Hello": "World"}
####################################################
# @app.get("/items/{item_id}")
# def read_item(item_id: int, q: Union[str, None] = None):
#     return {"item_id": item_id, "q": q}
# @app.put("/items/{item_id}")
# def update_item(item_id: int, item: Item):
#     return {"item_name": item.name, "item_id": item_id}
####################################################
# Endpoint for generating mnemonic
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