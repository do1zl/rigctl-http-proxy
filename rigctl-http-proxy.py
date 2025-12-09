import json
import logging
import queue
import signal
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from queue import Empty
from typing import Optional
import argparse
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("rigctl-http-proxy")

rig = None
shutdown_evt = threading.Event()

URL_PREFIX = '/rigctl-http-proxy/'

RECONNECT_TIME_SEC = 1.0

DEFAULT_RIGCTL = 'localhost:4532'
DEFAULT_SERVER = 'localhost:5566'


class RigctlService:
    def __init__(self, ip: str, port: int, debug: bool = False) -> None:
        self.ip = ip
        self.port = port
        self.debug = debug
        self.blocking_queue: "queue.Queue[str]" = queue.Queue()
        self.is_connected: bool = False
        self.stop_requested: bool = False

    # --- Lifecycle ---
    def start(self) -> None:
        def _run() -> None:
            self.start_client()

        threading.Thread(target=_run, name="RigctlService", daemon=True).start()

    def request_stop(self):
        self.stop_requested = True

    def start_client(self) -> None:
        # Loop forever, reconnecting to ip
        logger.info("rigctl endpoint = " + self.ip + ":" + str(self.port))
        while True and not self.stop_requested:
            self.connect_and_process(self.ip, self.port)
            if self.stop_requested:
                return
            time.sleep(RECONNECT_TIME_SEC)

    # --- Connection processing ---
    def connect_and_process(self, ip: str, port: int) -> None:
        self.is_connected = False
        try:
            with socket.create_connection((ip, port)) as sock:
                inp = sock.makefile("r", encoding="utf-8", newline="\n")
                out = sock.makefile("w", encoding="utf-8", newline="\n")
                self.is_connected = True

                reader_thread = threading.Thread(
                    target=self.process_reader,
                    args=(inp,),
                    name="RigctlReaderService",
                    daemon=True,
                )
                writer_thread = threading.Thread(
                    target=self.process_writer,
                    args=(out,),
                    name="RigctlWriterService",
                    daemon=True,
                )
                reader_thread.start()
                writer_thread.start()
                logger.info("rigctl connected")

                # Main loop until stop requested
                while self.is_connected:
                    time.sleep(0.5)
                logger.info("rigctl disconnected")
        except Exception:
            pass
        finally:
            self.is_connected = False

    # --- I/O processing ---
    def process_reader(self, inp) -> None:
        input_line: Optional[str] = None
        try:
            while self.is_connected and (not self.stop_requested):
                input_line = inp.readline()
                if input_line == "" or input_line is None:
                    break
                input_line = input_line.rstrip("\r\n")
                if self.debug:
                    logger.info("IN: '%s'", input_line)
                if input_line == "RPRT 0":
                    continue

        except Exception:
            pass
        logger.warning("reader thread end")
        self.is_connected = False

    def process_writer(self, out) -> None:
        try:
            while self.is_connected and (not self.stop_requested):
                try:
                    c = self.blocking_queue.get(timeout=0.2)
                except Empty:
                    continue
                if self.debug:
                    logger.info("OUT: '%s'", c)
                out.write(c + "\n")
                out.flush()
        except Exception:
            pass
        logger.warning("writer thread end")
        self.is_connected = False

    # --- Commands ---
    def send_freq(self, f: int) -> None:
        # logging.info("send freq")
        self.send(f"F {f}")

    def send_mode(self, mode_string: str) -> None:
        cmd = f"M {mode_string}"
        self.send(cmd)

    def send(self, t: str) -> None:
        t1 = t.strip()
        if self.is_connected:
            self.blocking_queue.put(t1)


class RigctlHttpHandler(BaseHTTPRequestHandler):

    def log_request(self, code: int | str = "-", size: int | str = "-"):
        pass

    # Apply CORS headers to every response automatically
    def end_headers(self):
        origin = self.headers.get('Origin')
        if origin:
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Vary', 'Origin')
        else:
            self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

    # Compact JSON response helper
    def _json(self, status_code: int, payload: dict):
        body = json.dumps(payload).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _status(self):
        connected = bool(getattr(rig, 'is_connected', False)) if rig else False
        self._json(200, {"rigctl_connected": connected})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')
        if path == URL_PREFIX + 'action':
            qs = parse_qs(parsed.query)
            freq = qs.get('F', [None])[0]
            mode = qs.get('M', [None])[0]
            if rig and rig.is_connected:
                if freq is not None:
                    rig.send_freq(int(freq))
                    time.sleep(0.1)
                if mode is not None:
                    rig.send_mode(mode)
            else:
                logger.info("could not send: rigctl not connected")
            self._status()
            return

        if path == URL_PREFIX + 'status':
            self._status()
            return

        self._json(404, {"status": "error", "error": "not_found"})

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        req_headers = self.headers.get('Access-Control-Request-Headers')
        if req_headers:
            self.send_header('Access-Control-Allow-Headers', req_headers)
        self.send_header('Content-Length', '0')
        self.end_headers()



def endpoint_arg(value: str) -> tuple[str, int]:
    if ':' not in value:
        raise argparse.ArgumentTypeError("expected HOST:PORT")
    host, port_str = value.rsplit(':', 1)
    if not host:
        raise argparse.ArgumentTypeError("host part is empty")
    try:
        port = int(port_str)
    except ValueError:
        raise argparse.ArgumentTypeError("port must be an integer")
    if not (0 < port < 65536):
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return host, port

def parse_args():
    parser = argparse.ArgumentParser(
        description='HTTP proxy that translates simple /action GETs into rigctl commands.',
    )
    parser.add_argument(
        '-r', '--rigctl',
        type=endpoint_arg,
        default=endpoint_arg(DEFAULT_RIGCTL),
        metavar='HOST:PORT',
        help=f'rigctl endpoint to connect to (default: {DEFAULT_RIGCTL})',
    )
    parser.add_argument(
        '-s', '--server',
        type=endpoint_arg,
        default=endpoint_arg(DEFAULT_SERVER),
        metavar='HOST:PORT',
        help=f'HTTP server bind address (default: {DEFAULT_SERVER})',
    )
    parser.add_argument(
        '--debug', action='store_true',
        help='enable verbose IN/OUT logs',
    )
    return parser.parse_args()


def main():
    global rig

    args = parse_args()

    rigctl_host, rigctl_port = args.rigctl
    rig = RigctlService(rigctl_host, rigctl_port, debug=args.debug)
    rig.start()

    server_host, server_port = args.server
    httpd = HTTPServer((server_host, server_port), RigctlHttpHandler)
    logger.info(f'Proxy serving on http://{server_host}:{server_port}{URL_PREFIX}')

    def on_shutdown(signum, frame):
        logger.info("Shutting down...")
        shutdown_evt.set()
        if rig:
            rig.request_stop()
        # shutdown() must be called from another thread
        threading.Thread(target=httpd.shutdown, name="httpd-shutdown", daemon=True).start()

    signal.signal(signal.SIGINT, on_shutdown)
    signal.signal(signal.SIGTERM, on_shutdown)

    try:
        httpd.serve_forever(poll_interval=0.1)
    finally:
        httpd.server_close()


def setup_logging():
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)


if __name__ == '__main__':
    setup_logging()
    main()
