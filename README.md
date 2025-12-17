# rigctl-http-proxy
A tiny HTTP→rigctl proxy for Hamlib. Exposes a simple HTTP API that forwards frequency and mode changes to a TCP rigctl server. CORS headers are added automatically, so the API can be called from a browser.


## Requirements
- Python 3.10+ (standard library only)

## Usage
Start the proxy:

```
python rigctl-http-proxy.py
```

Options:
- `-r, --rigctl HOST:PORT`  rigctl endpoint to connect to (default: `localhost:4532`)
- `-s, --server HOST:PORT`  HTTP server bind address (default: `localhost:5566`)
- `--debug` enable verbose IN/OUT logs
- `--no-check` skip allowed-action validation (accept any action strings)
- `--reconnect-time-sec n` Wait time in seconds before reconnecting to rigctl (default: 1)
- `-h, --help`  show help


## Connection behavior
- Auto-connect and reconnect: the proxy continuously attempts to connect to the rigctl endpoint and will automatically reconnect if the TCP connection drops or the server becomes available later.
- Default rigctl port: the default `-r localhost:4532` matches the common rigctl port used by SDR++, so you can point this proxy directly at SDR++ without extra configuration.
- Debug logging: `IN:` and `OUT:` lines are only printed when `--debug` is enabled.


## HTTP endpoints
Base path: `/rigctl-http-proxy/`

- `GET /status` → `{ "rigctl_connected": true|false }`
- `POST /action` → body: `{ "version": 1, "actions": ["F 14074000", "M USB"] }`; returns the same status object

Notes:
- By default, only `F` and `M` commands are accepted in `actions`. Pass `--no-check` to allow arbitrary rigctl lines.
- The action endpoint does not return the result of the rigctl call.

## Supported rigctl commands
This proxy currently forwards a minimal subset:
- `F <hz>` — set frequency (Hz)
- `M <mode>` — set mode (string passed through to rigctl)

Responses from rigctl are not surfaced; the HTTP API returns a simple JSON status.
