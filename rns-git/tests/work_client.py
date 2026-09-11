"""Live audited Python client exercising the Rust work lifecycle endpoint."""
import sys
import time
import os

import RNS
from RNS.vendor import umsgpack as mp


def wait_for(predicate):
    deadline = time.monotonic() + 20
    while not predicate():
        assert time.monotonic() < deadline, "Python work interop timed out"
        time.sleep(0.02)


reticulum = RNS.Reticulum(configdir=sys.argv[1], loglevel=RNS.LOG_ERROR)
destination_hash = bytes.fromhex(sys.argv[2])
wait_for(lambda: RNS.Transport.has_path(destination_hash))
destination = RNS.Destination(RNS.Identity.recall(destination_hash),
                              RNS.Destination.OUT, RNS.Destination.SINGLE,
                              "git", "repositories")
link = RNS.Link(destination)
wait_for(lambda: link.status == RNS.Link.ACTIVE)
identity = RNS.Identity()
link.identify(identity)
time.sleep(0.25)


def request(operation, path="/mgmt/work", repository="group/repo", expected=0, **fields):
    responses = []
    link.request(path, data={0: repository, "operation": operation, **fields},
                 response_callback=lambda receipt: responses.append(receipt.response), timeout=15)
    wait_for(lambda: responses)
    response = responses[0]
    assert response[0] == expected, response
    if expected != 0:
        return response[1:]
    return mp.unpackb(response[1:]) if len(response) > 1 else None


proposal = request("propose", title="Python proposal", content="Keep my content",
                   format="plain", signature=identity.sign(b"Keep my content"))
doc_id = proposal["id"]
assert proposal["scope"] == "proposed"
if os.environ.get("RNS_WORK_ADMIN_INTEROP"):
    link.teardown()
    link = RNS.Link(destination)
    wait_for(lambda: link.status == RNS.Link.ACTIVE)
    link.identify(RNS.Identity())
    time.sleep(0.25)
assert request("activate", doc_id=doc_id)["scope"] == "active"
document = request("view", doc_id=doc_id, scope="active")
assert document["content"] == "Keep my content"
assert document["meta"]["identity"] == identity.get_public_key()
assert identity.validate(document["meta"]["signature"], document["content"].encode())
assert request("complete", doc_id=doc_id)["scope"] == "completed"
assert request("activate", doc_id=doc_id)["scope"] == "active"
if os.environ.get("RNS_WORK_ADMIN_INTEROP"):
    request("rperms", path="/mgmt/perms", step="set", content="write = all\n")
    assert request("rperms", path="/mgmt/perms", step="get")["content"] == "write = all\n"
    if sys.platform != "win32":
        denial = request("rperms", path="/mgmt/perms", repository="group/dynamic",
                         step="set", content="read = none\n", expected=1)
        assert b"node-side" in denial
link.teardown()
print(f"Python {RNS.__version__}: propose/activate/view/complete/reactivate passed", flush=True)
