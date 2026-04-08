# sentinel_protocol.py
# ---------------------
# Shared message protocol for Sentinel Guard.
#
# This module defines how the agent and controller send and receive messages
# over a TCP socket:
#
#   - Messages are Python dictionaries.
#   - They are converted to JSON text, then to bytes.
#   - Each message is sent as:
#         [4-byte length][JSON bytes...]
#
#   The 4-byte length tells the receiver exactly how many bytes belong to
#   the next message, so we never accidentally mix or cut messages.

import json
import socket
import struct
from typing import Any, Dict, Optional

# We always send a 4-byte header that tells us how long the JSON message is.
HEADER_SIZE = 4

# To avoid someone sending a huge message and exhausting memory,
# we can set a reasonable max size (e.g. 10 MB).
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MB

def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    """
    Receive exactly n bytes from the socket, or return None if the connection
    is closed or an error occurs.

    We call this twice in recv_message():
        - once to get the 4-byte length header
        - once to get the full JSON payload
    """
    chunks: list[bytes] = []
    bytes_remaining = n

    while bytes_remaining > 0:
        try:
            chunk = sock.recv(bytes_remaining)
        except OSError:
            # Socket error (e.g connection reset)
            return None

        if not chunk:
            # Empty chunk means the other side closed the connection
            return None

        chunks.append(chunk)
        bytes_remaining -= len(chunk)

    return b''.join(chunks)

def send_message(sock: socket.socket, message: Dict[str, Any]) -> None:
    """
    Send a single JSON message over the given socket.

    Steps:
        1. Convert the Python dict to a JSON string.
        2. Encode it to UTF-8 bytes.
        3. Prefix it with a 4-byte length header (big-endian unsigned int).
        4. Use sendall() so the whole thing is sent.
    """
    # Convert dict -> JSON text -> bytes
    try:
        json_text=json.dumps(message, separators=(',', ':'))
    except (TypeError, ValueError) as e:
        raise ValueError(f'Message is not JSON-serializable: {e}') from e

    payload = json_text.encode('utf-8')
    length = len(payload)

    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f'Message too large to send ({length} bytes)')

    # Pack the length into 4 bytes, network byte order ('!I').
    header = struct.pack('>I', length)

    # Send header + payload. sendall() keeps sending until all bytes are sent.
    try:
        sock.sendall(header+payload)
    except OSError as e:
        # Let caller handle connection issues
        raise ConnectionError(f'Failed to send message: {e}') from e

def recv_message(sock: socket.socket, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """
    Receive a single JSON message from the given socket.

        - If timeout is provided (in seconds), the socket will only wait that long
    for data before raising a timeout (which we treat as "no message").
        - Returns:
            - a Python dict for a full message, or
            - None if the connection is closed or no message is received in time.
    """
    # Save the original timeout so we can restore it later.
    original_timeout = sock.gettimeout()
    try:
        if timeout is not None:
            sock.settimeout(timeout)

        # First, read the 4-byte header that tells us the message length
        header = _recv_exact(sock, HEADER_SIZE)
        if header is None:
            # Connection closed or error
            return None

        # Unpack the length (big-endian unsigned int).
        (length, ) = struct.unpack('!I', header)

        if length <= 0 or length > MAX_MESSAGE_SIZE:
            # Length is invalid or suspiciously large.
            return None

        # Now read exactly 'length' bytes for the json payload.
        payload = _recv_exact(sock, length)
        if payload is None:
            # Connection closed or error while reading payload
            return None

        # Decode JSON bytes -> text -> Python dict.
        try:
            json_text=payload.decode('utf-8')
            message = json.loads(json_text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            # Bad data; treat as no valid message
            return None

        if not isinstance(message, dict):
            # We expect the top-level message to be a JSON object.
            return None

        return message

    except socket.timeout:
        # If a timeout was set and no data arrived in time, return None.
        return None

    finally:
        # Restore original timeout.
        sock.settimeout(original_timeout)

# if __name__ == "__main__":
#     # Simple local test using socket.socketpair() (works on Unix-like systems, incl. macOS).
#     parent_sock, child_sock = socket.socketpair()
#
#     try:
#         test_message = {
#             "type": "test",
#             "text": "hello from sentinel_protocol",
#             "value": 123,
#         }
#
#         # Send from "parent" to "child"
#         send_message(parent_sock, test_message)
#
#         # Receive on "child"
#         received = recv_message(child_sock, timeout=1.0)
#
#         print("Sent message   :", test_message)
#         print("Received message:", received)
#     finally:
#         parent_sock.close()
#         child_sock.close()

