"""One isolated HAProxy master. Only its private Unix socket accepts commands."""

import csv
import errno
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from ipaddress import IPv4Address
from pathlib import Path
from typing import Annotated
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StrictBool, StringConstraints


def ip_literal(value):
    return str(IPv4Address(value))


IP = Annotated[str, AfterValidator(ip_literal)]
Port = Annotated[int, Field(strict=True, ge=1, le=65535)]
Revision = Annotated[int, Field(strict=True, ge=0, le=2**63 - 2)]
Key = Annotated[str, StringConstraints(min_length=1, max_length=128)]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Target(Model):
    address: IP
    port: Port
    exit_node_id: Annotated[int, Field(strict=True, gt=0)]
    inbound_tag: Annotated[str, StringConstraints(min_length=1, max_length=255)]


class Policy(Model):
    listen_address: IP
    listen_port: Port
    targets: dict[Key, Target]


class Command(Model):
    expected_destination: Target
    operation_id: UUID
    expected_revision: Revision
    target: Key
    enabled: StrictBool


class Route(Model):
    revision: Revision
    target: Key | None
    enabled: StrictBool
    listen_address: IP
    listen_port: Port
    destination: Target | None

    @property
    def marker(self):
        digest = hashlib.sha256(self.model_dump_json().encode()).hexdigest()[:16]
        return f"route_{self.revision}_{digest}"

    @staticmethod
    def endpoint(address, port):
        return f"{address}:{port}"

    def render(self):
        # Only validated IP literals, numeric ports and a generated marker enter HAProxy.
        lines = [
            "global",
            "  noreuseport",
            "  nbthread 1",
            "  stats socket unix@worker.sock mode 600 level user",
            "defaults",
            "  mode tcp",
            "  timeout connect 3s",
            "  timeout client 1h",
            "  timeout server 1h",
            f"backend {self.marker}",
        ]
        if self.enabled:
            lines += [
                "  server exit " + self.endpoint(self.destination.address, self.destination.port),
                "frontend pilot",
                "  bind " + self.endpoint(self.listen_address, self.listen_port),
                "  default_backend " + self.marker,
            ]
        return "\n".join(lines) + "\n"

    def backend_health(self):
        if not self.enabled:
            return "unknown"
        try:
            with socket.create_connection((self.destination.address, self.destination.port), timeout=0.6):
                return "up"
        except OSError:
            return "down"


# Wait for durable registration before exec. An EOF means the controller died
# before it authorized this child to claim the listener.
_START_MASTER = """
import os, sys
with os.fdopen(int(sys.argv[1]), "rb", buffering=0) as gate:
    authorized = gate.read(1) == b"1"
if authorized:
    os.execvp(sys.argv[2], sys.argv[2:])
"""


class ConfigCheckError(RuntimeError):
    """The candidate failed before installation or any worker change."""


class ConfigCheckTimeout(ConfigCheckError):
    pass


class StartupPending(RuntimeError):
    """The admitted master is still starting and may yet claim the listener."""


class Runtime:
    # The default panel read timeout is 5s. Slow starts continue under their
    # durable operation ID and are reconciled by result/status.
    START_WAIT = 2.5

    def __init__(self, directory: Path):
        self.directory = directory
        self.master = directory / "master.sock"
        self.process = None

    def _cli(self, command):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(6 if command == "reload" else 1)
            stream.connect(str(self.master))
            stream.sendall(command.encode("ascii") + b"\n")
            stream.shutdown(socket.SHUT_WR)
            data = bytearray()
            while chunk := stream.recv(8192):
                data.extend(chunk)
            return data.decode("utf-8", errors="replace")

    @staticmethod
    def _start_ticks(pid):
        try:
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        except (FileNotFoundError, ProcessLookupError):
            return None
        # stat(5): field 3 is state; field 22 is starttime across exec.
        return None if fields[0] in ("Z", "X") else int(fields[19])

    def _starting_or_live(self):
        if self.process is not None:
            if self.process.poll() is None:
                return True
            self.process = None
        try:
            identity = json.loads((self.directory / "master.identity").read_text())
        except FileNotFoundError:
            return False
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        return (
            boot_id == identity["boot_id"] and self._start_ticks(identity["pid"]) == identity["start_ticks"]
        )

    def _install(self, source, name):
        os.replace(source, self.directory / name)
        dirfd = os.open(self.directory, os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)

    def _start(self, active):
        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd, "rb") as child_gate, os.fdopen(write_fd, "wb", buffering=0) as authorize:
            self.process = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    _START_MASTER,
                    str(read_fd),
                    "haproxy",
                    "-W",
                    "-db",
                    "-S",
                    str(self.master),
                    "-p",
                    str(self.directory / "master.pid"),
                    "-f",
                    str(active),
                ],
                cwd=self.directory,
                start_new_session=True,
                umask=0o077,
                pass_fds=(child_gate.fileno(),),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
            )
            pid = self.process.pid
            ticks = self._start_ticks(pid)
            if ticks is None:
                raise RuntimeError("HAProxy launcher exited before registration")
            identity = dict(
                pid=pid,
                start_ticks=ticks,
                boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            )
            with tempfile.NamedTemporaryFile(dir=self.directory, mode="w", delete=False) as handle:
                json.dump(identity, handle)
                handle.flush()
                os.fsync(handle.fileno())
            self._install(handle.name, "master.identity")
            authorize.write(b"1")

    def _worker(self):
        try:
            stats = self._cli("@1 show stat")
        except (FileNotFoundError, ConnectionRefusedError):
            # A running worker can outlive loss of the master control socket.
            # It still owns the listener; starting another master would race it.
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as worker:
                worker.settimeout(1)
                try:
                    worker.connect(str(self.directory / "worker.sock"))
                except (FileNotFoundError, ConnectionRefusedError):
                    if self._starting_or_live():
                        raise RuntimeError("Registered HAProxy master has not exposed its worker yet")
                    return None, False
            raise RuntimeError("Live worker without an observable master")
        rows = csv.DictReader(stats.strip().removeprefix("# ").splitlines())
        name = None
        listening = False
        for row in rows:
            if row.get("svname") == "BACKEND" and row["pxname"].startswith("route_"):
                name = row["pxname"]
            if row.get("svname") == "FRONTEND" and row["pxname"] == "pilot":
                listening = row["status"] == "OPEN"
        if not name:
            raise RuntimeError("Current HAProxy worker could not be identified")
        return name, listening

    @staticmethod
    def _port(route):
        with socket.socket(socket.AF_INET) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((route.listen_address, route.listen_port))
            except OSError as e:
                return "external" if e.errno == errno.EADDRINUSE else "unknown"
        return "down"

    def observe(self, route):
        try:
            marker, listening = self._worker()
        except (OSError, RuntimeError):
            return None, "unknown"
        port = self._port(route)
        if listening:
            return marker, "up" if port == "external" else "unknown"
        return marker, port

    def matches(self, route):
        marker, listener = self.observe(route)
        return marker == route.marker and listener == ("up" if route.enabled else "down")

    def _checked_config(self, route):
        handle = tempfile.NamedTemporaryFile(dir=self.directory, mode="w", delete=False)
        path = Path(handle.name)
        try:
            with handle:
                handle.write(route.render())
                handle.flush()
                os.fsync(handle.fileno())
            completed = subprocess.run(
                ["haproxy", "-c", "-f", str(path)], cwd=self.directory, capture_output=True, timeout=30
            )
            if completed.returncode:
                raise ConfigCheckError(
                    "HAProxy rejected candidate syntax: " + completed.stderr.decode(errors="replace")[-500:]
                )
            return path
        except subprocess.TimeoutExpired as error:
            path.unlink(missing_ok=True)
            raise ConfigCheckTimeout("HAProxy validation timed out") from error
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    def validate(self, route):
        self._checked_config(route).unlink()

    def activate(self, route):
        try:
            path = self._checked_config(route)
        except OSError as error:
            raise ConfigCheckError(f"Could not validate HAProxy candidate: {error}") from error
        try:
            _, listener = self.observe(route)
            if listener in ("unknown", "external"):
                raise RuntimeError(f"Cannot take pilot listener ({listener})")
            active = self.directory / "active.cfg"
            self._install(path, "active.cfg")
            spawned = None
            wait = 5
            try:
                response = self._cli("reload")
                if response.startswith("Success=0"):
                    raise RuntimeError("HAProxy master rejected the reload: " + response[-500:])
            except (FileNotFoundError, ConnectionRefusedError):
                if self._starting_or_live():
                    raise RuntimeError("Registered HAProxy master is unavailable")
                self._start(active)
                spawned = self.process
                wait = self.START_WAIT
            deadline = time.monotonic() + wait
            while time.monotonic() < deadline:
                if self.matches(route):
                    return
                if spawned is not None and spawned.poll() is not None:
                    break
                time.sleep(0.05)
            if spawned is not None and self._starting_or_live():
                raise StartupPending("Waiting for the registered HAProxy master to expose its worker")
            raise RuntimeError(f"Worker did not confirm revision {route.revision} and its listener")
        finally:
            path.unlink(missing_ok=True)
