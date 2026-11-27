import json
import os
import shutil
import signal
import socket
import socketserver
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from pathlib import Path
from uuid import uuid4

import pytest

from haproxy_pilot import Conflict, Pilot, Policy, Runtime


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(1024):
            self.request.sendall(self.server.marker + data)


@contextmanager
def server(marker):
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo) as service:
        service.daemon_threads = True
        service.marker = marker
        thread = threading.Thread(target=service.serve_forever, kwargs={"poll_interval": 0.02})
        thread.start()
        try:
            yield service.server_address[1]
        finally:
            service.shutdown()
            thread.join()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def policy(listen, a, b):
    return {
        "listen_address": "127.0.0.1",
        "listen_port": listen,
        "targets": {
            key: {"address": "127.0.0.1", "port": port, "exit_node_id": i, "inbound_tag": "TEST TCP"}
            for i, (key, port) in enumerate([("a", a), ("b", b)], 1)
        },
    }


@pytest.mark.parametrize(
    "field,value", [("address", "127.0.0.1\nfrontend injection"), ("port", True), ("port", 65536)]
)
def test_invalid_policy_cannot_generate_config(field, value):
    values = policy(1234, 1235, 1236)
    values["targets"]["a"][field] = value
    with pytest.raises(ValueError):
        Policy.model_validate(values)


def intent(node, revision=0, target="a", enabled=True):
    return dict(
        operation_id=str(uuid4()),
        expected_revision=revision,
        target=target,
        enabled=enabled,
        expected_destination=node.policy.targets[target].model_dump(),
    )


def exchange(stream, expected):
    stream.sendall(b"?")
    assert stream.recv(2) == expected + b"?"


@pytest.fixture
def lab():
    if not shutil.which("haproxy"):
        pytest.skip("requires HAProxy in PATH")
    with ExitStack() as stack:
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="pilot-")))
        a, b = (stack.enter_context(server(mark)) for mark in (b"A", b"B"))
        listen = free_port()
        config = directory / "policy.json"
        config.write_text(json.dumps(policy(listen, a, b)))
        state = directory / "state"
        controller = Pilot(config, state)
        try:
            yield controller, (config, state), ("127.0.0.1", listen)
        finally:
            pidfile = state / "master.pid"
            if pidfile.exists():
                try:
                    os.kill(int(pidfile.read_text().strip()), signal.SIGTERM)
                except ProcessLookupError:
                    pass


def test_switch_preserves_stream_and_disable_drains(lab):
    node, files, addr = lab
    op = intent(node)
    assert node.status()["listener"] == "down"
    node.validate(op)
    assert node.result(op["operation_id"]) is None
    assert node.apply(op)["revision"] == 1
    with socket.create_connection(addr, timeout=1) as original:
        exchange(original, b"A")
        assert node.apply(intent(node, 1, "b"))["outcome"] == "applied"
        with socket.create_connection(addr, timeout=1) as changed:
            exchange(changed, b"B")
            exchange(original, b"A")
            assert node.apply(intent(node, 2, "b", False))["outcome"] == "applied"
            with pytest.raises(OSError):
                socket.create_connection(addr, timeout=1)
            exchange(changed, b"B")
        exchange(original, b"A")
    restarted = Pilot(*files)
    assert restarted.apply(op)["revision"] == 1
    assert restarted.status()["revision"] == 3
    with pytest.raises(Conflict):
        restarted.apply(dict(op, enabled=False))
    with pytest.raises(Conflict):
        restarted.apply(intent(node, 1))


def test_external_listener_is_observed_and_preserved(lab):
    node, _, addr = lab
    with socket.create_server(addr) as external:
        assert node.status()["listener"] == "external"
        cmd = intent(node)
        assert node.apply(cmd)["outcome"] == "rejected"
        assert node.result(cmd["operation_id"])["revision"] == 0
        with socket.create_connection(addr, timeout=1):
            external.settimeout(1)
            external.accept()[0].close()
    assert node.apply(intent(node))["outcome"] == "applied"


def test_unreachable_new_target_keeps_previous_revision(lab):
    node, (path, state), addr = lab
    assert node.apply(intent(node))["outcome"] == "applied"
    values = json.loads(path.read_text())
    values["targets"]["b"]["port"] = free_port()
    path.write_text(json.dumps(values))
    node = Pilot(path, state)
    result = node.apply(intent(node, 1, "b"))
    assert result["outcome"] == "rejected"
    assert node.status()["target"] == "a"
    with socket.create_connection(addr, timeout=1) as stream:
        exchange(stream, b"A")


def test_worker_loaded_before_crash_is_reconciled(lab, monkeypatch):
    node, files, addr = lab
    switch = Runtime.activate

    def interrupt(runtime, route):
        switch(runtime, route)
        raise KeyboardInterrupt

    monkeypatch.setattr(Runtime, "activate", interrupt)
    cmd = intent(node)
    with pytest.raises(KeyboardInterrupt):
        node.apply(cmd)
    monkeypatch.undo()
    recovered = Pilot(*files)
    assert recovered.result(cmd["operation_id"])["outcome"] == "applied"
    assert recovered.status()["revision"] == 1
    with socket.create_connection(addr, timeout=1) as stream:
        exchange(stream, b"A")


def test_failed_worker_switch_rolls_back(lab, monkeypatch):
    node, _, addr = lab
    assert node.apply(intent(node))["outcome"] == "applied"
    activate = Runtime.activate

    def lose_confirmation(runtime, route):
        activate(runtime, route)
        if route.revision == 2:
            raise RuntimeError("candidate could not be confirmed")

    monkeypatch.setattr(Runtime, "activate", lose_confirmation)
    result = node.apply(intent(node, 1, "b"))
    assert result["outcome"] == "rejected"
    assert result["revision"] == 1
    with socket.create_connection(addr, timeout=1) as stream:
        exchange(stream, b"A")


def test_concurrent_revision_has_single_winner(lab):
    node, _, _ = lab

    def apply(target):
        try:
            return node.apply(intent(node, 0, target))["outcome"]
        except Conflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(apply, ["a", "b"])) == ["applied", "conflict"]


def test_rest_session_loss_and_strict_command(lab, monkeypatch):
    node, _, _ = lab
    import xray

    monkeypatch.setattr(xray.XRayCore, "get_version", lambda self: "test")
    import rest_service
    from fastapi.testclient import TestClient

    service = rest_service.service
    monkeypatch.setattr(service, "pilot", node)
    active = uuid4()
    monkeypatch.setattr(service, "session_id", active)
    client = TestClient(rest_service.app)
    assert client.post("/").json()["capabilities"]["haproxy_pilot"] == 1
    for route in ("status", "apply", "validate", "result"):
        body = (
            {} if route == "status" else {"operation_id": str(uuid4())} if route == "result" else intent(node)
        )
        assert (
            client.post("/haproxy-pilot/" + route, json=dict(body, session_id=str(uuid4()))).status_code
            == 403
        )
    body = dict(intent(node), session_id=str(active))
    for change in [{"enabled": "yes"}, {"arbitrary": "config"}, {"expected_revision": True}]:
        assert client.post("/haproxy-pilot/apply", json=dict(body, **change)).status_code == 422
    assert (
        client.post(
            "/haproxy-pilot/result", json={"session_id": str(active), "operation_id": str(uuid4())}
        ).status_code
        == 404
    )
    assert client.post("/haproxy-pilot/apply", json=body).json()["outcome"] == "applied"


def test_unconfirmed_reload_cannot_ack_old_worker(lab, monkeypatch):
    node, _, addr = lab
    assert node.apply(intent(node))["outcome"] == "applied"
    cli = Runtime._cli

    def ignore_reload(runtime, command):
        if command == "reload":
            return ""
        return cli(runtime, command)

    monkeypatch.setattr(Runtime, "_cli", ignore_reload)
    result = node.apply(intent(node, 1, "b"))
    assert result["outcome"] == "rejected" and result["revision"] == 1
    with socket.create_connection(addr, timeout=1) as stream:
        exchange(stream, b"A")


def test_removed_destination_is_not_started_after_cold_boot(lab):
    node, (path, directory), addr = lab
    assert node.apply(intent(node))["outcome"] == "applied"
    proc = node.runtime.process
    proc.terminate()
    proc.wait(timeout=2)
    config = json.loads(path.read_text())
    del config["targets"]["a"]
    path.write_text(json.dumps(config))
    restored = Pilot(path, directory)
    assert restored.status()["confirmed_destination"]["port"] != config["targets"]["b"]["port"]
    assert restored.status()["listener"] == "down"
    with pytest.raises(OSError):
        socket.create_connection(addr, timeout=1)
    assert restored.apply(intent(node, 1, "b"))["outcome"] == "applied"


def test_inaccessible_master_with_live_worker_stays_pending(lab, monkeypatch):
    node, (_, directory), address = lab
    activate = Runtime.activate

    def lose_master_socket(runtime, route):
        activate(runtime, route)
        (directory / "master.sock").rename(directory / "saved.sock")
        raise RuntimeError("control socket lost")

    monkeypatch.setattr(Runtime, "activate", lose_master_socket)
    cmd = intent(node)
    try:
        assert node.apply(cmd)["outcome"] == "pending"
        assert node.status()["listener"] == "unknown"
        with socket.create_connection(address, timeout=1) as stream:
            exchange(stream, b"A")
    finally:
        (directory / "saved.sock").rename(directory / "master.sock")
    assert node.result(cmd["operation_id"])["outcome"] == "applied"


def test_confirmed_config_restarts_on_cold_boot(lab):
    node, files, addr = lab
    assert node.apply(intent(node))["outcome"] == "applied"
    node.runtime.process.terminate()
    node.runtime.process.wait(timeout=2)
    restored = Pilot(*files)
    assert restored.status()["listener"] == "up"
    with socket.create_connection(addr, timeout=1) as stream:
        exchange(stream, b"A")


def test_failed_rollback_preserves_both_revisions_in_result(lab, monkeypatch):
    node, _, _ = lab
    assert node.apply(intent(node))["outcome"] == "applied"

    def fail_activation(runtime, route):
        raise RuntimeError(f"Could not load revision {route.revision}")

    monkeypatch.setattr(Runtime, "activate", fail_activation)
    cmd = intent(node, 1, "b")
    result = node.apply(cmd)
    assert result["outcome"] == "rollback_failed"
    assert result["revision"] == 1
    assert "revision 1" in result["detail"] and "revision 2" in result["detail"]
    assert node.result(cmd["operation_id"]) == result


@pytest.mark.parametrize("ipv6_field", ["listen_address", "address"])
def test_pilot_requires_ipv4(ipv6_field):
    values = policy(10000, 10001, 10002)
    container = values if ipv6_field == "listen_address" else values["targets"]["a"]
    container[ipv6_field] = "::1"
    with pytest.raises(ValueError):
        Policy.model_validate(values)


def test_port_taken_after_validation_cannot_be_claimed(lab, monkeypatch):
    node, files, address = lab
    cmd = intent(node)
    node.validate(cmd)
    original_cli = Runtime._cli
    with socket.socket() as newcomer:

        def race(runtime, command):
            if command == "reload" and newcomer.getsockname()[1] == 0:
                newcomer.bind(address)
                newcomer.listen()
            return original_cli(runtime, command)

        monkeypatch.setattr(Runtime, "_cli", race)
        result = node.apply(cmd)
        assert result["outcome"] == "rejected"
        assert result["revision"] == 0
        assert node.status()["listener"] == "external"
        with socket.create_connection(address, timeout=1):
            newcomer.settimeout(1)
            newcomer.accept()[0].close()
    assert node.result(cmd["operation_id"]) == result


@pytest.mark.parametrize("mutation", ["changed", "removed"])
def test_policy_change_is_a_durable_rejection_before_backend_access(lab, monkeypatch, mutation):
    from haproxy_pilot import Rejected
    from haproxy_runtime import Route

    node, (path, directory), _ = lab
    command = intent(node, target="a")
    old = json.loads(path.read_text())
    new = json.loads(path.read_text())
    if mutation == "removed":
        del new["targets"]["a"]
    else:
        new["targets"]["a"]["port"] = new["targets"]["b"]["port"]
    path.write_text(json.dumps(new))
    updated = Pilot(path, directory)

    def unexpected_probe(self):
        pytest.fail("Mismatched policy performed a backend probe")

    monkeypatch.setattr(Route, "backend_health", unexpected_probe)
    with pytest.raises(Rejected):
        updated.validate(command)
    result = updated.apply(command)
    assert result["outcome"] == "rejected" and result["revision"] == 0
    assert updated.result(command["operation_id"]) == result
    path.write_text(json.dumps(old))
    restored = Pilot(path, directory)
    assert restored.apply(command) == result
    with pytest.raises(Conflict):
        restored.apply(dict(command, expected_destination=old["targets"]["b"]))


@pytest.mark.parametrize("mutation", ["changed", "removed"])
def test_disable_confirmed_destination_after_revocation(lab, mutation):
    node, (path, directory), address = lab
    assert node.apply(intent(node))["outcome"] == "applied"
    disable = intent(node, 1, "a", False)
    policy_after = json.loads(path.read_text())
    if mutation == "removed":
        del policy_after["targets"]["a"]
    else:
        policy_after["targets"]["a"]["port"] = free_port()
    path.write_text(json.dumps(policy_after))
    controller = Pilot(path, directory)
    assert controller.status()["confirmed_destination"] == disable["expected_destination"]
    forged = dict(disable, operation_id=str(uuid4()), expected_destination=policy_after["targets"]["b"])
    assert controller.apply(forged)["outcome"] == "rejected"
    assert controller.validate(disable)["valid"]
    assert controller.apply(disable)["outcome"] == "applied"
    with pytest.raises(OSError):
        socket.create_connection(address, timeout=1)
    assert controller.status()["revision"] == 2


def test_session_revoked_while_waiting_for_route_lock_cannot_reserve(lab, monkeypatch):
    node, _, _ = lab
    import xray

    monkeypatch.setattr(xray.XRayCore, "get_version", lambda self: "test")
    import rest_service
    from fastapi.testclient import TestClient

    service = rest_service.service
    monkeypatch.setattr(service, "pilot", node)
    active = uuid4()
    monkeypatch.setattr(service, "session_id", active)
    client = TestClient(rest_service.app)
    entered = threading.Event()
    lookup = service._session_pilot

    def admitted(request):
        found = lookup(request)
        entered.set()
        return found

    monkeypatch.setattr(service, "_session_pilot", admitted)
    cmd = intent(node)
    with ThreadPoolExecutor(max_workers=1) as pool:
        with node._locked():
            future = pool.submit(client.post, "/haproxy-pilot/apply", json=dict(cmd, session_id=str(active)))
            assert entered.wait(2)
            assert client.post("/disconnect").status_code == 200
        assert future.result(timeout=5).status_code == 403
    assert node.result(cmd["operation_id"]) is None
    assert node.status()["revision"] == 0


def test_policy_listener_move_cannot_retarget_interrupted_operation(lab, monkeypatch):
    node, (path, directory), original = lab
    assert node.apply(intent(node))["outcome"] == "applied"
    cmd = intent(node, 1, "b")

    def interrupt(runtime, route):
        raise KeyboardInterrupt

    monkeypatch.setattr(Runtime, "activate", interrupt)
    with pytest.raises(KeyboardInterrupt):
        node.apply(cmd)
    monkeypatch.undo()
    previous = path.read_text()
    moved = json.loads(previous)
    moved["listen_port"] = free_port()
    path.write_text(json.dumps(moved))
    with pytest.raises(ValueError, match="different listener"):
        Pilot(path, directory)
    with socket.create_connection(original, timeout=1) as stream:
        exchange(stream, b"A")
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", moved["listen_port"]), timeout=1)
    path.write_text(previous)
    recovered = Pilot(path, directory)
    assert recovered.result(cmd["operation_id"])["outcome"] == "rejected"
    assert recovered.status()["revision"] == 1


def test_empty_policy_still_allows_observation_and_disable_of_last_route(lab):
    node, (path, directory), addr = lab
    config = json.loads(path.read_text())
    del config["targets"]["b"]
    path.write_text(json.dumps(config))
    original = Pilot(path, directory)
    assert original.apply(intent(original))["outcome"] == "applied"
    disable = intent(original, 1, "a", False)
    denied = intent(original, 1, "a", True)
    config["targets"].clear()
    path.write_text(json.dumps(config))
    with_no_targets = Pilot(path, directory)
    state = with_no_targets.status()
    assert state["targets"] == {}
    assert state["listener"] == "up"
    assert state["confirmed_destination"] == disable["expected_destination"]
    assert with_no_targets.apply(denied)["outcome"] == "rejected"
    assert with_no_targets.apply(disable)["outcome"] == "applied"
    with pytest.raises(OSError):
        socket.create_connection(addr, timeout=1)


@pytest.mark.parametrize("will_start", [True, False])
def test_slow_master_survives_wait_deadline_and_controller_restart(lab, monkeypatch, will_start):
    import subprocess
    import time

    node, (path, directory), addr = lab
    real = shutil.which("haproxy")
    wrapper = directory / "haproxy"
    release = directory / "release-test-master"
    wrapper.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "-W" ]; then\n'
        f'  while [ ! -f "{release}" ]; do sleep 0.05; done\n'
        + ("" if will_start else "  exit 1\n")
        + f'fi\nexec "{real}" "$@"\n'
    )
    popen = subprocess.Popen

    def delay_boot(args, **kwargs):
        if "-W" in args and "haproxy" in args:
            binary = args.index("haproxy")
            args = [*args[:binary], "/bin/sh", str(wrapper), *args[binary + 1 :]]
        return popen(args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", delay_boot)
    monkeypatch.setattr(Runtime, "START_WAIT", 0.15, raising=False)
    command = intent(node)
    try:
        assert node.apply(command)["outcome"] == "pending"
        restarted = Pilot(path, directory)
        assert restarted.result(command["operation_id"])["outcome"] == "pending"
        assert restarted.apply(command)["outcome"] == "pending"
        assert (directory / "active.cfg").exists()
    finally:
        release.touch()
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        result = restarted.result(command["operation_id"])
        if result["outcome"] != "pending":
            break
        time.sleep(0.05)
    if will_start:
        assert result["outcome"] == "applied" and result["revision"] == 1
        with socket.create_connection(addr, timeout=1) as stream:
            exchange(stream, b"A")
    else:
        assert result["outcome"] == "rejected" and result["revision"] == 0
        assert restarted.status()["listener"] == "down"


@pytest.mark.parametrize("transient_failure", [False, True])
def test_restart_drains_orphan_candidate_when_confirmed_revision_is_zero(lab, monkeypatch, transient_failure):
    from haproxy_runtime import Route

    node, files, addr = lab
    original = intent(node)
    orphan = Route(
        revision=1,
        target="a",
        enabled=True,
        destination=original["expected_destination"],
        listen_address=addr[0],
        listen_port=addr[1],
    )
    # A legacy node recorded rejection and lost the startup file, but the worker came up later.
    node.runtime.activate(orphan)
    (files[1] / "active.cfg").unlink()
    checks = []
    checked = Runtime._checked_config

    def validate_recovery(runtime, route):
        checks.append(route.revision)
        if transient_failure and len(checks) == 1:
            raise RuntimeError("HAProxy validation timed out")
        return checked(runtime, route)

    monkeypatch.setattr(Runtime, "_checked_config", validate_recovery)
    with socket.create_connection(addr, timeout=1) as stream:
        exchange(stream, b"A")
        restarted = Pilot(*files)
        assert checks == [0]
        if transient_failure:
            with socket.create_connection(addr, timeout=1) as before_retry:
                exchange(before_retry, b"A")
        assert restarted.status()["revision"] == 0
        assert restarted.status()["listener"] == "down"
        assert checks == ([0, 0] if transient_failure else [0])
        with pytest.raises(OSError):
            socket.create_connection(addr, timeout=1)
        exchange(stream, b"A")


def test_cold_validation_can_finish_after_client_stops_waiting(lab, monkeypatch):
    import subprocess

    node, _, addr = lab
    command = intent(node)
    run = subprocess.run
    checks = []
    entered = threading.Event()

    def slow_check(args, **kwargs):
        if "-c" in args:
            checks.append(1)
            entered.set()
            if len(checks) == 1:
                args = ["/bin/sh", "-c", 'sleep 4.2; exec "$@"', "slow-check", *args]
        return run(args, **kwargs)

    monkeypatch.setattr(subprocess, "run", slow_check)
    with ThreadPoolExecutor(1) as pool:
        original = pool.submit(node.apply, command)
        assert entered.wait(timeout=2)
        with pytest.raises(TimeoutError):
            original.result(timeout=0.05)
        by_id = node.result(command["operation_id"])
        assert by_id == original.result(timeout=2)
    assert by_id["outcome"] == "applied" and by_id["revision"] == 1
    assert checks == [1]
    with socket.create_connection(addr, timeout=1) as stream:
        exchange(stream, b"A")


def test_status_observes_external_owner_of_previously_confirmed_port(lab, monkeypatch):
    node, files, addr = lab
    assert node.apply(intent(node))["outcome"] == "applied"
    node.runtime.process.terminate()
    node.runtime.process.wait(timeout=2)

    def forbidden(*args):
        pytest.fail("Status attempted to reload an externally owned listener")

    monkeypatch.setattr(Runtime, "activate", forbidden)
    with socket.create_server(addr) as external:
        restarted = Pilot(*files)
        assert restarted.status()["listener"] == "external"
        with socket.create_connection(addr, timeout=1):
            external.settimeout(1)
            external.accept()[0].close()


def test_validation_timeout_during_rollback_keeps_original_operation_pending(lab, monkeypatch):
    from haproxy_runtime import ConfigCheckTimeout

    node, _, addr = lab
    assert node.apply(intent(node))["outcome"] == "applied"
    activate = Runtime.activate

    def fail(runtime, route):
        if route.revision == 1:
            raise ConfigCheckTimeout("HAProxy validation timed out")
        activate(runtime, route)
        raise RuntimeError("backend lost after candidate launch")

    monkeypatch.setattr(Runtime, "activate", fail)
    cmd = intent(node, 1, "b")
    assert node.apply(cmd)["outcome"] == "pending"
    monkeypatch.undo()
    assert node.status()["target"] == "a"
    assert node.result(cmd["operation_id"])["outcome"] == "rejected"
    with socket.create_connection(addr, timeout=1) as stream:
        exchange(stream, b"A")
