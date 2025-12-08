# rigctl-http-proxy
A tiny HTTP→rigctl proxy for Hamlib. Exposes a simple HTTP API that forwards frequency and mode changes to a TCP rigctl server.

## Requirements
- Python 3.10+ (standard library only)

## Usage
Start the proxy:

```
python rigctl-http-proxy.py
```

Options:
- `-r, --rigctl HOST:PORT`  rigctl endpoint to connect to (default: `localhost:4532`)
- `-s, --server HOST:PORT`  HTTP server bind address (default: `127.0.0.1:5566`)
- `--debug` enable verbose IN/OUT logs
- `-h, --help`  show help


## Connection behavior
- Auto-connect and reconnect: the proxy continuously attempts to connect to the rigctl endpoint and will automatically reconnect if the TCP connection drops or the server becomes available later.
- Default rigctl port: the default `-r localhost:4532` matches the common rigctl port used by SDR++, so you can point this proxy directly at SDR++ without extra configuration.
- Debug logging: `IN:` and `OUT:` lines are only printed when `--debug` is enabled.


## HTTP endpoints
Base path: `/rigctl-http-proxy/`

- `GET /status` → `{ "rigctl_connected": true|false }`
- `GET /action?F=<hz>&M=<mode>` → applies the requested changes and returns status
  - `F` (integer, Hz) — send `F <hz>`
  - `M` (string) — send `M <mode>` (e.g. `USB`, `LSB`, `AM`, `FM`, `CW`, etc.)

Notes:
- Both `F` and `M` are optional and can be sent together.
- CORS headers are added automatically, so the API can be called from a browser.


## Supported rigctl commands
This proxy currently forwards a minimal subset:
- `F <hz>` — set frequency (Hz)
- `M <mode>` — set mode (string passed through to rigctl)

Responses from rigctl are not surfaced; the HTTP API returns a simple JSON status.
