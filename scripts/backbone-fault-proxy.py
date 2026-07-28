#!/usr/bin/env python3
"""Small TCP impairment proxy for live BackboneInterface tests."""

import argparse
import asyncio
import random
import signal


async def relay(reader, writer, latency, jitter, bytes_per_second):
    try:
        while data := await reader.read(64 * 1024):
            delay = latency
            if jitter:
                delay += random.uniform(0, jitter)
            if bytes_per_second:
                delay += len(data) / bytes_per_second
            if delay:
                await asyncio.sleep(delay)
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--upstream-host", required=True)
    parser.add_argument("--upstream-port", type=int, required=True)
    parser.add_argument("--latency-ms", type=float, default=0)
    parser.add_argument("--jitter-ms", type=float, default=0)
    parser.add_argument("--rate-kbps", type=float, default=0)
    args = parser.parse_args()

    if min(args.latency_ms, args.jitter_ms, args.rate_kbps) < 0:
        parser.error("impairment values cannot be negative")

    latency = args.latency_ms / 1000
    jitter = args.jitter_ms / 1000
    bytes_per_second = args.rate_kbps * 1000 / 8 if args.rate_kbps else 0
    sessions = set()
    session_number = 0

    async def handle(client_reader, client_writer):
        nonlocal session_number
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                args.upstream_host, args.upstream_port
            )
        except Exception as error:
            print(f"upstream connection failed: {error}", flush=True)
            client_writer.close()
            await client_writer.wait_closed()
            return

        session = (client_writer, upstream_writer)
        sessions.add(session)
        session_number += 1
        current_session = session_number
        print(f"session {current_session} connected", flush=True)
        try:
            await asyncio.gather(
                relay(client_reader, upstream_writer, latency, jitter, bytes_per_second),
                relay(upstream_reader, client_writer, latency, jitter, bytes_per_second),
            )
        finally:
            print(f"session {current_session} closed", flush=True)
            sessions.discard(session)
            for writer in session:
                writer.close()
            await asyncio.gather(
                *(writer.wait_closed() for writer in session), return_exceptions=True
            )

    server = await asyncio.start_server(handle, "127.0.0.1", args.listen_port)
    print(
        f"listening on 127.0.0.1:{args.listen_port}, upstream "
        f"{args.upstream_host}:{args.upstream_port}, latency={args.latency_ms}ms, "
        f"jitter={args.jitter_ms}ms, rate={args.rate_kbps}kbps",
        flush=True,
    )

    loop = asyncio.get_running_loop()

    def disconnect_sessions():
        print(f"disconnecting {len(sessions)} active session(s)", flush=True)
        for client_writer, upstream_writer in list(sessions):
            client_writer.close()
            upstream_writer.close()

    if hasattr(signal, "SIGUSR1"):
        loop.add_signal_handler(signal.SIGUSR1, disconnect_sessions)

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
