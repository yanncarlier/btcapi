# Bitcoin Address Generation API

A FastAPI-based RESTful API for generating Bitcoin mnemonic seeds and various types of Bitcoin addresses (BIP32, BIP44, BIP49, BIP84) along with brain wallet functionality.

## Features

- Generate BIP39 mnemonic phrases and seeds
- Generate BIP32 legacy addresses with custom derivation paths
- Generate BIP44 legacy (P2PKH) addresses
- Generate BIP49 Wrapped SegWit (P2SH-P2WPKH) addresses
- Generate BIP84 Native SegWit (P2WPKH) addresses
- Create brain wallets from passphrases
- Rate limiting and CORS support
- Optional private key inclusion
- Detailed API documentation via OpenAPI

## Prerequisites

- Python 3.8+
- Required packages (listed in requirements.txt)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/username/bitcoin-address-api.git
cd bitcoin-address-api
```

1. Create a virtual environment:

bash

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

1. Install dependencies:

bash

```bash
pip install -r requirements.txt
```

Requirements.txt

```text
fastapi>=0.95.0
uvicorn>=0.20.0
pydantic>=1.10.0
ecdsa>=0.18.0
base58>=2.1.1
bip-utils>=2.7.0
bip32utils>=0.3.post4
mnemonic>=0.20
```

Usage

Run the API server:

bash

```bash
python main.py
# or
uvicorn main:app --host 0.0.0.0 --port 8000
```

The API will be available at:

- Development: http://127.0.0.1:8000
- Production: https://btc-tx-gw.vercel.app or https://btc-tx-gw.bitcoin-tx.com

Access the interactive API documentation at /docs endpoint (e.g., http://127.0.0.1:8000/docs)

API Endpoints

1. Root
   - GET /
   - Returns a simple greeting message
2. Generate Mnemonic
   - GET /generate-mnemonic
   - Returns a new BIP39 mnemonic, seed, and BIP32 root key
3. Generate Brain Wallet
   - POST /generate-brain-wallet
   - Creates a Bitcoin address from a passphrase
4. Generate BIP32 Addresses
   - POST /generate-bip32-addresses
   - Generates legacy addresses with custom derivation paths
5. Generate BIP44 Addresses
   - POST /generate-bip44-addresses
   - Generates legacy P2PKH addresses
6. Generate BIP49 Addresses
   - POST /generate-bip49-addresses
   - Generates Wrapped SegWit P2SH-P2WPKH addresses
7. Generate BIP84 Addresses
   - POST /generate-bip84-addresses
   - Generates Native SegWit P2WPKH addresses

Configuration

- MAX_ADDRESSES: Maximum number of addresses per request (default: 10)
- RATE_LIMIT: Maximum requests per IP (default: 60)
- TIME_FRAME: Rate limiting window (default: 1 hour)
- origins: List of allowed CORS origins

Security Features

- Rate limiting per IP address
- CORS middleware
- X-Content-Type-Options header
- Input validation
- Error handling

Example Request

bash

```bash
curl -X POST "http://127.0.0.1:8000/generate-bip44-addresses" \
-H "Content-Type: application/json" \
-d '{
    "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "passphrase": "",
    "num_addresses": 1,
    "include_private_keys": false
}'
```

Response Format

json

```json
{
    "addresses": [
        {
            "derivation_path": "m/44'/0'/0'/0/0",
            "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "public_key": "02...",
            "private_key": null
        }
    ]
}
```

Rate Limiting

- Limit: 60 requests per IP per hour
- Headers included in responses:
  - X-RateLimit-Limit
  - X-RateLimit-Remaining
  - Retry-After (when limit exceeded)

Contributing

1. Fork the repository
2. Create your feature branch (git checkout -b feature/amazing-feature)
3. Commit your changes (git commit -m 'Add some amazing feature')
4. Push to the branch (git push origin feature/amazing-feature)
5. Open a Pull Request

License

MIT License - see LICENSE file for details

Disclaimer

This is for educational purposes only. Use at your own risk, especially when generating private keys in a production environment. Always follow security best practices when handling cryptocurrency keys.

```text
You can save this content as `README.md` in your project directory. This single file contains all the sections from the previous response, properly formatted with Markdown syntax. To use it:

1. Create a new file named `README.md`
2. Copy and paste this entire content
3. Save the file
4. Modify any project-specific details (repository URL, username, etc.) as needed

The file will be properly rendered when viewed on GitHub or other Markdown-supporting platforms.
```