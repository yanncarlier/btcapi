# Agent Instructions for btcapi

This document provides instructions for AI coding agents working on the btcapi project, a FastAPI-based Bitcoin address generation API.

## Build and Development Commands

### Running the Application
```bash
# Development server (from api/ directory)
cd api && python main.py

# Alternative with uvicorn
cd api && uvicorn main:app --host 0.0.0.0 --port 8000

# Production server
uvicorn main:app --host 0.0.0.0 --port 8000
```

### Dependencies
```bash
# Install dependencies (from api/ directory)
cd api && pip install -r requirements.txt

# Update dependencies
pip-compile --upgrade requirements.in
pip install -r requirements.txt

# Security audit
pip-audit -r requirements.txt
```

### Testing
```bash
# No formal test framework is currently configured
# Run individual test scripts from scripts/ directory:
cd scripts && python generate_mnemonic.py
cd scripts && python BIP44_addresses.py
cd scripts && python BIP84_addressess.py

# For single test execution (example):
cd scripts && python -m pytest BIP44_addresses.py::test_function_name  # if pytest were configured
```

## Code Style Guidelines

### Import Organization
```python
# 1. Standard Library Imports
from typing import Optional
import hashlib

# 2. Third-Party Imports
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# 3. Local Imports (if any)
# from . import local_module
```

### Naming Conventions
- **Functions**: `snake_case` (e.g., `generate_mnemonic`, `_bip32_derive`)
- **Classes**: `PascalCase` (e.g., `AddressRequest`, `BrainWalletResponse`)
- **Constants**: `UPPER_CASE` (e.g., `MAX_ADDRESSES`, `RATE_LIMIT`)
- **Variables**: `snake_case` (e.g., `client_ip`, `current_time`)
- **Private functions**: Prefix with underscore (e.g., `_generate_address`)

### Type Hints
```python
# Always use type hints for function parameters and return values
def generate_brain_wallet(passphrase: str) -> tuple[str, str, str]:
    # Function body

# Use Optional for nullable types
class AddressRequest(BaseModel):
    mnemonic: str
    passphrase: Optional[str] = ""
    num_addresses: Optional[int] = 1
```

### Error Handling
```python
# Use try/except blocks for expected errors
try:
    if not mnemo.check(request.mnemonic):
        raise ValueError("Invalid mnemonic phrase.")
except Exception as e:
    raise HTTPException(status_code=400, detail=str(e))

# For validation errors, raise ValueError with descriptive messages
if request.num_addresses < 1 or request.num_addresses > MAX_ADDRESSES:
    raise ValueError(f"Number of addresses must be between 1 and {MAX_ADDRESSES}")
```

### Code Structure
- **Constants**: Define at module level after imports
- **Pydantic Models**: Group together after constants
- **Helper Functions**: Place before API endpoints
- **API Endpoints**: Group at the end of the file
- **Main Block**: At the very end for script execution

### Documentation
```python
# Use descriptive docstrings for complex functions
def _bip32_derive(seed: bytes, path: str) -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Derive a BIP32 private key and chain code from a seed and derivation path."""

# API endpoints should have summary and description
@app.get(
    "/generate-mnemonic",
    summary="Generate BIP39 Mnemonic",
    description="Generates a new BIP39 mnemonic phrase and its corresponding seed."
)
```

### Security Best Practices
- **Input Validation**: Always validate user inputs through Pydantic models
- **Rate Limiting**: Respect the existing rate limiting middleware
- **Private Keys**: Never expose private keys unless explicitly requested and validated
- **HTTPS**: Always use HTTPS in production environments
- **CORS**: Only allow necessary origins in CORS configuration

### Formatting
- **Line Length**: Keep lines under 120 characters when possible
- **Indentation**: Use 4 spaces for Python
- **Blank Lines**: Use blank lines to separate logical sections
- **String Quotes**: Use double quotes for consistency (`"string"`)

### Performance Considerations
- **Async Functions**: Use `async`/`await` for I/O operations
- **Threading**: Use thread locks for shared state (like rate limiting)
- **Memory**: Be mindful of memory usage with large address generation requests

### Bitcoin-Specific Guidelines
- **Address Types**: Support BIP32, BIP44, BIP49, BIP84, BIP86 standards
- **Derivation Paths**: Follow standard BIP derivation path conventions
- **Key Security**: Handle private keys securely, never log them
- **Checksums**: Always include proper checksums for addresses and keys

## Development Workflow

1. **Code Changes**: Make changes following the style guidelines above
2. **Testing**: Test changes with existing scripts or create new test scripts
3. **Security Review**: Review changes for security implications, especially around key handling
4. **Documentation**: Update docstrings and API documentation for any new endpoints

## File Structure
```
btcapi/
├── api/
│   ├── main.py              # Main FastAPI application
│   ├── requirements.txt     # Pinned dependencies
│   └── requirements.in      # Abstract dependencies
├── scripts/                 # Utility and test scripts
├── .vscode/                 # VS Code configuration
├── .github/                 # GitHub workflows
└── README.md               # Project documentation
```

## Important Notes
- This API handles sensitive cryptographic operations
- Always prioritize security and correctness over convenience
- Rate limiting is enforced - respect these limits in automated testing
- The application uses in-memory storage for rate limiting (not suitable for multi-instance deployments)</content>
<parameter name="filePath">/home/y/MY_PROJECTS/btcapi/AGENTS.md