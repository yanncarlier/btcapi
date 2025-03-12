------

# Bitcoin Address Generation API Gateway

This is a FastAPI-based RESTful API for generating Bitcoin mnemonic seeds and various address types, including BIP32, BIP44, BIP49, BIP84, BIP86, BIP85, and BIP141-compatible addresses. It also supports generating brain wallets from passphrases. The API is designed for developers and enthusiasts who need to generate Bitcoin addresses programmatically.

## Features

- Generate BIP39 mnemonic phrases and seeds.
- Generate Bitcoin addresses for multiple BIP standards:
  - **BIP32**: Legacy HD wallet addresses.
  - **BIP44**: Legacy P2PKH addresses.
  - **BIP49**: Wrapped SegWit (P2SH-P2WPKH) addresses.
  - **BIP84**: Native SegWit (P2WPKH) addresses.
  - **BIP86**: Taproot (P2TR) addresses.
  - **BIP141**: Wrapped and Native SegWit addresses via BIP49 and BIP84.
- Generate BIP85 child mnemonics for deterministic derivation.
- Generate brain wallets from user-provided passphrases.
- Option to include or exclude private keys in responses (defaults to false for security).
- Interactive API documentation via Swagger UI (/docs) and ReDoc (/redoc).

## Prerequisites

- Python 3.8+
- A Unix-like environment (Linux, macOS) or Windows with compatible tools.

## Installation

1. **Clone the Repository**:

   bash

   ```bash
   git clone https://github.com/yanncarlier/btc_tx_gw.git
   cd btc_tx_gw
   ```

2. **Create a Virtual Environment** (optional but recommended):

   bash

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**: Install the required Python packages using pip:

   bash

   ```bash
   pip install fastapi uvicorn ecdsa base58 bip-utils bip32utils mnemonic
   ```

4. **Run the Application**: Start the FastAPI server locally:

   bash

   ```bash
   python main.py
   ```

   The API will be available at: http://127.0.0.1:8000  

   

## Usage

## Running the API

- **Local Development**: Use the command above to run on http://127.0.0.1:8000
- **Production**: Deploy to a server (e.g., Vercel) using the provided configuration https://maroon-raven-main-3cc16aa.d2.zuplo.dev/docs 

## Accessing Documentation

- **Swagger UI**: Visit http://127.0.0.1:8000/docs for an interactive API explorer.
- **ReDoc**: Visit http://127.0.0.1:8000/redoc for a detailed API reference.

## Example Requests

1. Generate a BIP39 Mnemonic

bash

```bash
curl -X GET "http://127.0.0.1:8000/generate-mnemonic"
```

**Response**:

json

```json
{
  "BIP39Mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  "BIP39Seed": "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
}
```

2. Generate BIP44 Addresses

bash

```bash
curl -X POST "http://127.0.0.1:8000/generate-bip44-addresses" \
-H "Content-Type: application/json" \
-d '{
  "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  "passphrase": "",
  "num_addresses": 1,
  "include_private_keys": true
}'
```

**Response**:

json

```json
{
  "addresses": [
    {
      "derivation_path": "m/44'/0'/0'/0/0",
      "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
      "public_key": "02...",
      "private_key": "L1..."
    }
  ]
}
```

3. Generate All BIP Addresses

bash

```bash
curl -X POST "http://127.0.0.1:8000/generate-all-bip-addresses" \
-H "Content-Type: application/json" \
-d '{
  "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  "num_addresses": 1
}'
```

**Response**:

json

```json
{
  "BIP32": [{"derivation_path": "m/32'/0'/0'/0/0", "address": "1...", "public_key": "02...", "private_key": null}],
  "BIP44": [{"derivation_path": "m/44'/0'/0'/0/0", "address": "1...", "public_key": "02...", "private_key": null}],
  "BIP49": [{"derivation_path": "m/49'/0'/0'/0/0", "address": "3...", "public_key": "03...", "private_key": null}],
  "BIP84": [{"derivation_path": "m/84'/0'/0'/0/0", "address": "bc1...", "public_key": "02...", "private_key": null}],
  "BIP86": [{"derivation_path": "m/86'/0'/0'/0/0", "address": "bc1p...", "public_key": "03...", "private_key": null}],
  "BIP141_Wrapped_SegWit_via_BIP49": [{"derivation_path": "m/49'/0'/0'/0/0", "address": "3...", "public_key": "03...", "private_key": null}],
  "BIP141_Native_SegWit_via_BIP84": [{"derivation_path": "m/84'/0'/0'/0/0", "address": "bc1...", "public_key": "02...", "private_key": null}]
}
```

## Endpoints

| Endpoint                                  | Method | Summary                        | Description                                                  |
| ----------------------------------------- | ------ | ------------------------------ | ------------------------------------------------------------ |
| /                                         | GET    | Root Endpoint                  | Returns a simple greeting message.                           |
| /generate-mnemonic                        | GET    | Generate BIP39 Mnemonic        | Generates a new BIP39 mnemonic phrase and seed.              |
| /generate-brain-wallet                    | POST   | Generate Brain Wallet          | Generates a Bitcoin address and keys from a passphrase.      |
| /generate-bip32-addresses                 | POST   | Generate BIP32 Addresses       | Generates BIP32 legacy addresses.                            |
| /generate-bip44-addresses                 | POST   | Generate BIP44 Addresses       | Generates BIP44 legacy P2PKH addresses.                      |
| /generate-bip49-addresses                 | POST   | Generate BIP49 Addresses       | Generates BIP49 Wrapped SegWit (P2SH-P2WPKH) addresses.      |
| /generate-bip84-addresses                 | POST   | Generate BIP84 Addresses       | Generates BIP84 Native SegWit (P2WPKH) addresses.            |
| /generate-bip86-addresses                 | POST   | Generate BIP86 Addresses       | Generates BIP86 Taproot (P2TR) addresses.                    |
| /generate-bip141-wrapped-segwit-via-bip49 | POST   | Generate BIP141 Wrapped SegWit | Generates BIP141-compatible Wrapped SegWit addresses using BIP49. |
| /generate-bip141-native-segwit-via-bip84  | POST   | Generate BIP141 Native SegWit  | Generates BIP141-compatible Native SegWit addresses using BIP84. |
| /generate-bip85-child-mnemonic            | POST   | Generate BIP85 Child Mnemonic  | Generates a BIP85 child mnemonic from a master mnemonic.     |
| /generate-all-bip-addresses               | POST   | Generate All BIP Addresses     | Generates addresses for all supported BIP types (BIP32, BIP44, BIP49, BIP84, BIP86, BIP141). |

## Request Parameters

- **AddressRequest** (used by most POST endpoints):
  - mnemonic (str, required): BIP39 mnemonic phrase.
  - passphrase (str, optional): Passphrase for seed derivation (defaults to "").
  - num_addresses (int, optional): Number of addresses to generate (1 to 42, defaults to 1).
  - include_private_keys (bool, optional): Include private keys in the response (defaults to false).
- **BrainWalletRequest**:
  - passphrase (str, required): Passphrase for brain wallet generation.
  - include_private_keys (bool, optional): Include private key in the response (defaults to false).
- **BIP85Request**:
  - mnemonic (str, required): Master mnemonic.
  - passphrase (str, optional): Passphrase (defaults to "").
  - app_index (int, optional): Application index (defaults to 39).
  - word_count (int, optional): Number of words in child mnemonic (12, 15, 18, 21, 24; defaults to 12).
  - index (int, optional): Child index (defaults to 0).

## Security Notes

- **Private Keys**: By default, private keys are not returned (include_private_keys=false) to enhance security. Set to true only when necessary and handle responses securely.
- **Mnemonic Safety**: Store mnemonics and seeds securely; exposure compromises all derived addresses.
- **Production Use**: Use HTTPS in production to encrypt requests and responses.

## Dependencies

- **FastAPI**: Web framework for building the API.
- **Uvicorn**: ASGI server to run the application.
- **Pydantic**: Data validation and serialization.
- **ecdsa**: Elliptic Curve Digital Signature Algorithm for key generation.
- **base58**: Base58 encoding for Bitcoin addresses and keys.
- **bip-utils**: BIP39, BIP44, BIP49, BIP84, BIP86 implementations.
- **bip32utils**: BIP32 HD wallet support.
- **mnemonic**: BIP39 mnemonic generation.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue on GitHub.

1. Fork the repository.
2. Create a feature branch (git checkout -b feature/your-feature).
3. Commit changes (git commit -am 'Add your feature').
4. Push to the branch (git push origin feature/your-feature).
5. Open a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

------

## Notes on the README

- **Structure**: Follows a standard README format with sections for overview, setup, usage, endpoints, and additional info.
- **Examples**: Includes practical curl commands to demonstrate API usage.
- **Endpoint Table**: Summarizes all endpoints with their methods, summaries, and descriptions, reflecting the code’s documentation.
- **Security**: Highlights the default exclusion of private keys and best practices.
- **Assumptions**: Assumes the file is named main.py and the repository is hosted on GitHub (adjust the URL as needed).

Feel free to customize this further based on your specific deployment details or additional features! Let me know if you need adjustments.
