from typing import Union
from fastapi import FastAPI
# from pydantic import BaseModel
app = FastAPI()
####################################################
# class Item(BaseModel):
#     name: str
#     price: float
#     is_offer: Union[bool, None] = None
####################################################
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
@app.get("/mnemonic/")
def function_name():
    from mnemonic import Mnemonic
    mnemonic = Mnemonic("english")
    #Generate word list given the strength (128 - 256):
    words = mnemonic.generate(strength=128)
    # Given the word list generate seed:
    seed = mnemonic.to_seed(words)
    return {
        "BIP39 Mnemonic": mnemonic.generate(128),
        "BIP39 Seed": seed.hex()
        }
################################