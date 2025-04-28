# Bitcoin Transaction API

This API allows users to create unsigned Bitcoin transactions by providing inputs and outputs in a JSON format. The API is built using the Actix-web framework in Rust and utilizes the Bitcoin crate for transaction creation.

## Overview

The API exposes a single endpoint, /create_tx, which accepts POST requests containing the necessary inputs and outputs for a Bitcoin transaction. It constructs an unsigned transaction and returns it as a hex-encoded string. Note that the transaction must be signed separately before it can be broadcast to the Bitcoin network.

## Setup

To run the API locally, follow these steps:

1. **Clone the repository**:

   bash

   ```bash
   git clone <repository-url>
   ```

2. **Navigate to the project directory**:

   bash

   ```bash
   cd bitcoin_tx_server
   ```

3. **Build the project**:

   bash

   ```bash
   cargo build
   ```

4. **Run the server**:

   bash

   ```bash
   cargo run
   ```

The server will start and listen on http://127.0.0.1:8080.

## API Endpoint

**POST /create_tx**

- **Description**: Creates an unsigned Bitcoin transaction based on the provided inputs and outputs.
- **Content-Type**: application/json

**Request Body**

The request body should be a JSON object with the following structure:

- inputs: An array of input objects, each containing:
  - txid: A string representing the previous transaction ID (64-character hexadecimal).
  - vout: An integer representing the output index in the previous transaction.
- outputs: An array of output objects, each containing:
  - address: A string representing the Bitcoin address.
  - amount: An integer representing the amount in satoshis.

**Example**:

json

```json
{
    "inputs": [
        {
            "txid": "abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abc",
            "vout": 0
        }
    ],
    "outputs": [
        {
            "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "amount": 10000
        }
    ]
}
```

**Response**

- **Success**: Returns a JSON object with the hex-encoded unsigned transaction.

  json

  ```json
  {
      "tx_hex": "01000000..."
  }
  ```

- **Error**: If there are issues with the request (e.g., invalid txid, invalid address, or network mismatch), the API returns a 400 Bad Request with an error message.

  ```text
  Invalid txid
  ```

## Dependencies

The project relies on the following Rust crates:

- actix-web: ^4.0 – Web framework for handling HTTP requests.
- bitcoin: ^0.29 – For Bitcoin transaction creation and utilities.
- serde: ^1.0 with derive feature – For JSON serialization and deserialization.
- hex: ^0.4 – For encoding the transaction into a hexadecimal string.

## Testing the API

You can test the API using tools like curl or Postman. Below is an example using curl:

bash

```bash
curl -X POST http://127.0.0.1:8080/create_tx \
     -H "Content-Type: application/json" \
     -d '{"inputs":[{"txid":"abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abc","vout":0}],"outputs":[{"address":"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa","amount":10000}]}'
```

## Additional Notes

- **Network**: The API is currently configured to use the Bitcoin mainnet. To use it with testnet or another network, modify the network field in the AppState struct in main.rs.
- **Unsigned Transactions**: The transaction returned by the API is unsigned and must be signed using a separate tool or library before it can be broadcast to the Bitcoin network.
- **Error Handling**: The API performs basic validation on inputs and outputs, such as checking for valid txid formats and ensuring addresses match the network. Invalid requests will result in a 400 Bad Request response with a descriptive message.