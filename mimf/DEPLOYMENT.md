# MIMF Deployment Notes

## Run the API

```bash
export MIMF_API_KEYS="devkey:alice:export:document.basic,export:document.identifying,export:document.tooling,runtime:read,runtime:write"
export MIMF_DB_PATH=./mimf_runtime.db
python -m mimf serve --host 127.0.0.1 --port 8080
```

OpenAPI docs:
- `http://127.0.0.1:8080/docs`

## Docker

```bash
docker compose up --build
```
