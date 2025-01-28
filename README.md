# btc_tx_gw

### bitcoin transaction gateway

```
python -m venv .venv
source .venv/bin/activate
pip freeze > requirements.txt
pip install -r requirements.txt
fastapi dev api.py
```



1. **Endpoints**:
   - `/generate-bip49-addresses`: Generates BIP49 (wrapped SegWit) addresses.
   - `/generate-bip84-addresses`: Generates BIP84 (native SegWit) addresses.
   - `/generate-bip86-addresses`: Generates BIP86 (Taproot) addresses.
   - `/generate-bip141-addresses` uses BIP49 internally but explicitly labels it as BIP141 for clarity.
   - Generates **P2SH-P2WPKH addresses** (wrapped SegWit starting with `3...`). Still uses `m/49'/0'/0'/0/i`
   - `/generate-brain-wallet`: Generates a WIF and Bitcoin address from a passphrase.



**Usage**:

- Use POST requests with a valid BIP39 mnemonic for BIP endpoints.
- Use a POST request with a passphrase for the brain wallet endpoint.

**Example Requests**:
```
# BIP49
curl -X POST "http://127.0.0.1:8000/generate-bip49-addresses" -H "Content-Type: application/json" -d '{"mnemonic":"your mnemonic here", "num_addresses":5}'
```
```
# Brain Wallet
curl -X POST "http://127.0.0.1:8000/generate-brain-wallet" -H "Content-Type: application/json" -d '{"passphrase":"your secret passphrase"}'
```
