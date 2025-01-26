# btc_tx_gw

### bitcoin transaction gateway

```
python -m venv .venv
source .venv/bin/activate
pip freeze > requirements.txt
pip install -r requirements.txt
fastapi dev api.py
```

### to test

```
curl -X POST -H "Content-Type: application/json" -d '{"mnemonic":"dutch relax ten exercise brick country afraid behave during polar segment baby"}' http://localhost:8000/generate-addresses |jq
```
