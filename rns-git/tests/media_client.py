"""Opt-in live Python client for the Rust Nomad Network media endpoint.

Run the Rust page E2E with RNS_MEDIA_INTEROP=1 and PYTHONPATH pointing at the
exact audited Reticulum checkout. No system Reticulum configuration is used.
"""
import sys
import time
import os
import tempfile

import RNS

from RNS.Utilities.rngit.media import convert_file_to_webp, _webp_info

# Compare resize behavior, not backend-dependent compressed bytes.
with tempfile.NamedTemporaryFile() as source:
    source.write(b"P6\n4 2\n255\n" + b"\xff\0\0" * 8)
    source.flush()
    for limit, expected in [(2, (2, 1)), (8, (4, 2))]:
        converted = convert_file_to_webp(source.name, max_dimension=limit)
        assert converted
        try:
            with open(converted, "rb") as image:
                assert _webp_info(image.read()) == expected
        finally:
            os.unlink(converted)


def wait_for(predicate):
    deadline = time.monotonic() + 20
    while not predicate():
        assert time.monotonic() < deadline, "Python media interop timed out"
        time.sleep(0.02)


reticulum = RNS.Reticulum(configdir=sys.argv[1], loglevel=RNS.LOG_ERROR)
destination_hash = bytes.fromhex(sys.argv[2])
wait_for(lambda: RNS.Transport.has_path(destination_hash))
identity = RNS.Identity.recall(destination_hash)
assert identity is not None
destination = RNS.Destination(identity, RNS.Destination.OUT,
                              RNS.Destination.SINGLE, "nomadnetwork", "node")
link = RNS.Link(destination)
wait_for(lambda: link.status == RNS.Link.ACTIVE)
time.sleep(0.25)
responses = []


def received(receipt):
    # The Resource owns the stream and closes it after this callback returns.
    value = receipt.response.read() if hasattr(receipt.response, "read") else receipt.response
    responses.append((value, receipt.metadata))


link.request("/media", data={"key": b"python-key", "path": "/media/group/repo/HEAD/README.md"},
             response_callback=received, timeout=15)
wait_for(lambda: len(responses) == 1)
value, metadata = responses.pop()
assert metadata == {"name": b"README.md"}, metadata
assert value == b"hello over rns\n"
link.request("/media", data={"key": b"image-key", "path": "/media/group/repo/HEAD/pixel.png"},
             response_callback=received, timeout=15)
wait_for(lambda: len(responses) == 1)
value, metadata = responses.pop()
assert metadata == {"name": b"pixel.webp"}, metadata
assert _webp_info(value) == (2, 1)
link.request("/media", data={"path": "/media/group/repo/HEAD/README.md"},
             response_callback=received, timeout=15)
wait_for(lambda: len(responses) == 1)
assert responses[0][0] is False
link.teardown()
print(f"Python {RNS.__version__}: media bytes, PNG-to-WebP conversion, filename metadata and rejection passed", flush=True)
