#!/usr/bin/env python3
"""Canary stdio MCP server for watchdeck tests (M6.7). Fake data only.

Newline-delimited JSON-RPC 2.0 on stdin/stdout, as the MCP stdio transport
specifies. Every response is written with sorted keys and compact
separators, so a test can compare the bytes it reads through
`watchdeck run --subject mcp:<name> --` with a direct run.

Tools:
  echo  {text}            -> the text back
  env   {}                -> the sorted names of the environment variables
  net   {host, port}      -> "connected" or "denied: <errno name>"
  write {path}            -> "wrote" or "denied: <errno name>"
  read  {path}            -> "read <n> bytes" or "denied: <errno name>"
"""
import errno
import json
import os
import socket
import sys

TOOLS = [
    {"name": "echo", "description": "Echo text back.", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}},
    {"name": "env", "description": "List environment variable names.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "net", "description": "Try a TCP connect.", "inputSchema": {"type": "object", "properties": {"host": {"type": "string"}, "port": {"type": "integer"}}}},
    {"name": "write", "description": "Try to write a file.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    {"name": "read", "description": "Try to read a file.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
]


def errname(e):
    return "denied: " + errno.errorcode.get(e.errno or 0, str(e.errno))


def call(name, args):
    if name == "echo":
        return args.get("text", "")
    if name == "env":
        return " ".join(sorted(os.environ.keys()))
    if name == "net":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            s.connect((args["host"], int(args["port"])))
            return "connected"
        except OSError as e:
            return errname(e)
        finally:
            s.close()
    if name == "write":
        try:
            with open(args["path"], "w") as f:
                f.write("canary\n")
            return "wrote"
        except OSError as e:
            return errname(e)
    if name == "read":
        try:
            with open(args["path"], "rb") as f:
                return "read %d bytes" % len(f.read())
        except OSError as e:
            return errname(e)
    raise KeyError(name)


def reply(msg):
    sys.stdout.write(json.dumps(msg, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main():
    sys.stderr.write("canary mcp server started\n")
    sys.stderr.flush()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        mid = req.get("id")
        method = req.get("method")
        if mid is None:  # a notification
            continue
        if method == "initialize":
            reply({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "watchdeck-canary", "version": "0.0.1"}}})
        elif method == "tools/list":
            reply({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            p = req.get("params", {})
            try:
                text = call(p.get("name"), p.get("arguments", {}))
                reply({"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": text}]}})
            except KeyError:
                reply({"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool"}})
        else:
            reply({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}})


if __name__ == "__main__":
    main()
