#!/usr/bin/env python3
"""Provision, test, diagnose, and destroy an AiFw Proxmox VM."""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import ipaddress
import json
import os
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.parse
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
import urllib3
from argon2 import PasswordHasher

RESOURCE_PREFIX = "aifw-e2e-"
FULL_WAN_CIDR = "198.18.0.1/24"
FULL_WAN_HELPER = "198.18.0.2"
FULL_LAN_CIDR = "198.19.0.1/24"
FULL_LAN_HELPER = "198.19.0.2"
HELPER_TEMPLATE = "local:vztmpl/debian-13-standard_13.6-1_amd64.tar.zst"


class HarnessError(RuntimeError):
    """A bounded, user-facing harness failure."""


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise HarnessError(f"required environment variable {name} is not set")
    return value


@dataclass(frozen=True)
class LabConfig:
    pve_url: str
    pve_node: str
    image_storage: str
    vm_storage: str
    bridge: str
    wan_bridge: str
    lan_bridge: str
    verify_tls: bool
    address_cidr: str
    gateway: str
    dns: str
    token_id: str
    token_secret: str
    admin_password: str

    @classmethod
    def from_env(cls) -> "LabConfig":
        return cls(
            pve_url=required_env("PVE_URL").rstrip("/"),
            pve_node=required_env("PVE_NODE"),
            image_storage=os.environ.get("PVE_IMAGE_STORAGE", "local"),
            vm_storage=os.environ.get("PVE_VM_STORAGE", "local-lvm"),
            bridge=os.environ.get("PVE_BRIDGE", "vmbr0"),
            wan_bridge=os.environ.get("PVE_E2E_WAN_BRIDGE", "vmbr998"),
            lan_bridge=os.environ.get("PVE_E2E_LAN_BRIDGE", "vmbr999"),
            verify_tls=os.environ.get("PVE_VERIFY_TLS", "true").lower()
            in ("1", "true", "yes"),
            address_cidr=required_env("AIFW_E2E_ADDRESS"),
            gateway=required_env("AIFW_E2E_GATEWAY"),
            dns=os.environ.get("AIFW_E2E_DNS", required_env("AIFW_E2E_GATEWAY")),
            token_id=required_env("PVE_TOKEN_ID"),
            token_secret=required_env("PVE_TOKEN_SECRET"),
            admin_password=required_env("AIFW_E2E_ADMIN_PASSWORD"),
        )

    @property
    def address(self) -> str:
        return self.address_cidr.split("/", 1)[0]


class Proxmox:
    def __init__(self, cfg: LabConfig):
        self.cfg = cfg
        self.base = f"{cfg.pve_url}/api2/json"
        self.session = requests.Session()
        self.session.headers["Authorization"] = (
            f"PVEAPIToken={cfg.token_id}={cfg.token_secret}"
        )
        self.session.verify = cfg.verify_tls
        if not cfg.verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        response = self.session.request(
            method, f"{self.base}{path}", timeout=120, **kwargs
        )
        if not response.ok:
            detail = response.text[:500]
            raise HarnessError(
                f"Proxmox {method} {path} failed: {response.status_code} {detail}"
            )
        return response.json().get("data")

    def wait_task(self, upid: str, timeout: int = 900) -> None:
        encoded = urllib.parse.quote(upid, safe="")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.request(
                "GET", f"/nodes/{self.cfg.pve_node}/tasks/{encoded}/status"
            )
            if status.get("status") == "stopped":
                exit_status = str(status.get("exitstatus", ""))
                if exit_status != "OK" and not exit_status.startswith("WARNINGS"):
                    raise HarnessError(
                        f"Proxmox task failed: {status.get('exitstatus')} ({upid})"
                    )
                return
            time.sleep(2)
        raise HarnessError(f"timed out waiting for Proxmox task {upid}")

    def next_vmid(self) -> int:
        return int(self.request("GET", "/cluster/nextid"))

    def require_bridges(self, bridges: list[str]) -> None:
        networks = self.request("GET", f"/nodes/{self.cfg.pve_node}/network")
        available = {
            network.get("iface")
            for network in networks
            if network.get("type") == "bridge" and network.get("active") == 1
        }
        missing = sorted(set(bridges) - available)
        if missing:
            raise HarnessError(
                "required active Proxmox bridges are missing: " + ", ".join(missing)
            )

    def create_vm(self, vmid: int, name: str, description: str) -> None:
        upid = self.request(
            "POST",
            f"/nodes/{self.cfg.pve_node}/qemu",
            data={
                "vmid": vmid,
                "name": name,
                "description": description,
                "tags": "aifw-e2e",
                "ostype": "other",
                "bios": "seabios",
                "cores": 4,
                "memory": 4096,
                "scsihw": "virtio-scsi-single",
                "serial0": "socket",
                "vga": "serial0",
                "net0": f"virtio,bridge={self.cfg.bridge},firewall=1",
                "onboot": 0,
                "protection": 0,
            },
        )
        if upid:
            self.wait_task(upid)

    def create_full_appliance_vm(self, vmid: int, name: str, description: str) -> None:
        upid = self.request(
            "POST",
            f"/nodes/{self.cfg.pve_node}/qemu",
            data={
                "vmid": vmid,
                "name": name,
                "description": description,
                "tags": "aifw-e2e",
                "ostype": "other",
                "bios": "seabios",
                "cores": 4,
                "memory": 4096,
                "scsihw": "virtio-scsi-single",
                "serial0": "socket",
                "vga": "serial0",
                "net0": f"virtio,bridge={self.cfg.wan_bridge},firewall=0",
                "net1": f"virtio,bridge={self.cfg.lan_bridge},firewall=0",
                "onboot": 0,
                "protection": 0,
            },
        )
        if upid:
            self.wait_task(upid)

    def create_helper_container(
        self,
        vmid: int,
        name: str,
        description: str,
        public_key: str,
        networks: list[str],
    ) -> None:
        config: dict[str, Any] = {
            "vmid": vmid,
            "hostname": name,
            "description": description,
            "tags": "aifw-e2e",
            "ostemplate": HELPER_TEMPLATE,
            "rootfs": f"{self.cfg.vm_storage}:2",
            "cores": 1,
            "memory": 512,
            "swap": 0,
            "unprivileged": 1,
            "start": 0,
            "onboot": 0,
            "protection": 0,
            "ssh-public-keys": public_key.strip(),
        }
        for index, network in enumerate(networks):
            config[f"net{index}"] = network
        upid = self.request(
            "POST", f"/nodes/{self.cfg.pve_node}/lxc", data=config
        )
        if upid:
            self.wait_task(upid)

    def start_container(self, vmid: int) -> None:
        upid = self.request(
            "POST", f"/nodes/{self.cfg.pve_node}/lxc/{vmid}/status/start"
        )
        self.wait_task(upid)

    def container_exists(self, vmid: int) -> bool:
        resources = self.request("GET", "/cluster/resources", params={"type": "vm"})
        return any(
            int(resource.get("vmid", -1)) == vmid
            and resource.get("type") == "lxc"
            for resource in resources
        )

    def container_config(self, vmid: int) -> dict[str, Any]:
        return self.request(
            "GET", f"/nodes/{self.cfg.pve_node}/lxc/{vmid}/config"
        )

    def destroy_container(self, vmid: int) -> None:
        with contextlib.suppress(Exception):
            upid = self.request(
                "POST", f"/nodes/{self.cfg.pve_node}/lxc/{vmid}/status/stop"
            )
            self.wait_task(upid, timeout=120)
        upid = self.request(
            "DELETE",
            f"/nodes/{self.cfg.pve_node}/lxc/{vmid}",
            params={"purge": 1, "destroy-unreferenced-disks": 1},
        )
        self.wait_task(upid, timeout=300)

    def create_builder_vm(self, vmid: int, name: str, description: str) -> None:
        upid = self.request(
            "POST",
            f"/nodes/{self.cfg.pve_node}/qemu",
            data={
                "vmid": vmid,
                "name": name,
                "description": description,
                "tags": "aifw-e2e",
                "ostype": "other",
                "bios": "seabios",
                "cpu": "host",
                "cores": 8,
                "memory": 12288,
                "scsihw": "virtio-scsi-single",
                "serial0": "socket",
                "vga": "serial0",
                "net0": f"virtio,bridge={self.cfg.bridge},firewall=1",
                "onboot": 0,
                "protection": 0,
            },
        )
        if upid:
            self.wait_task(upid)

    def upload(self, path: Path, content: str) -> str:
        checksum = sha256_file(path)
        with path.open("rb") as handle:
            upid = self.request(
                "POST",
                f"/nodes/{self.cfg.pve_node}/storage/{self.cfg.image_storage}/upload",
                data={
                    "content": content,
                    "checksum-algorithm": "sha256",
                    "checksum": checksum,
                },
                files={"filename": (path.name, handle, "application/octet-stream")},
            )
        self.wait_task(upid)
        prefix = "iso" if content == "iso" else "import"
        return f"{self.cfg.image_storage}:{prefix}/{path.name}"

    def attach_imported_disk(
        self, vmid: int, volume: str, seed_volume: str | None = None
    ) -> None:
        # Proxmox 9 imports a storage `import` volume while applying the VM
        # disk configuration. The source upload is removed during teardown.
        disk = f"{self.cfg.vm_storage}:0,import-from={volume},discard=on"
        config = {"virtio0": disk}
        if seed_volume is not None:
            config["ide2"] = f"{seed_volume},media=cdrom"
        upid = self.request(
            "PUT",
            f"/nodes/{self.cfg.pve_node}/qemu/{vmid}/config",
            data=config,
        )
        if upid:
            self.wait_task(upid)
        # The imported disk does not exist until the asynchronous task above
        # finishes. Setting boot order in the same request makes PVE silently
        # discard virtio0 from `boot` and fall back to PXE/CD-ROM.
        upid = self.request(
            "PUT",
            f"/nodes/{self.cfg.pve_node}/qemu/{vmid}/config",
            data={"boot": "order=virtio0"},
        )
        if upid:
            self.wait_task(upid)

    def resize_disk(self, vmid: int, disk: str, size: str) -> None:
        upid = self.request(
            "PUT",
            f"/nodes/{self.cfg.pve_node}/qemu/{vmid}/resize",
            data={"disk": disk, "size": size},
        )
        if upid:
            self.wait_task(upid)

    def start(self, vmid: int) -> None:
        upid = self.request(
            "POST", f"/nodes/{self.cfg.pve_node}/qemu/{vmid}/status/start"
        )
        self.wait_task(upid)

    def stop(self, vmid: int) -> None:
        status = self.request(
            "GET", f"/nodes/{self.cfg.pve_node}/qemu/{vmid}/status/current"
        )
        if status.get("status") == "stopped":
            return
        upid = self.request(
            "POST", f"/nodes/{self.cfg.pve_node}/qemu/{vmid}/status/stop"
        )
        self.wait_task(upid, timeout=120)

    def destroy(self, vmid: int) -> None:
        with contextlib.suppress(Exception):
            self.stop(vmid)
        upid = self.request(
            "DELETE",
            f"/nodes/{self.cfg.pve_node}/qemu/{vmid}",
            params={"purge": 1, "destroy-unreferenced-disks": 1},
        )
        self.wait_task(upid, timeout=300)

    def delete_volume(self, volume: str) -> None:
        encoded = urllib.parse.quote(volume, safe="")
        upid = self.request(
            "DELETE",
            f"/nodes/{self.cfg.pve_node}/storage/{self.cfg.image_storage}/content/{encoded}",
        )
        if upid:
            self.wait_task(upid, timeout=300)

    def vm_config(self, vmid: int) -> dict[str, Any]:
        return self.request(
            "GET", f"/nodes/{self.cfg.pve_node}/qemu/{vmid}/config"
        )

    def vm_exists(self, vmid: int) -> bool:
        resources = self.request("GET", "/cluster/resources", params={"type": "vm"})
        return any(int(resource.get("vmid", -1)) == vmid for resource in resources)

    def volume_exists(self, volume: str) -> bool:
        resources = self.request(
            "GET",
            f"/nodes/{self.cfg.pve_node}/storage/{self.cfg.image_storage}/content",
        )
        return any(resource.get("volid") == volume for resource in resources)

    def wait_resources_absent(
        self, vmid: int | None, volumes: list[str], timeout: int = 60
    ) -> None:
        """Prove that every resource owned by this run has disappeared."""
        deadline = time.monotonic() + timeout
        remaining: list[str] = []
        while time.monotonic() < deadline:
            remaining = []
            if vmid is not None and self.vm_exists(vmid):
                remaining.append(f"VM {vmid}")
            remaining.extend(volume for volume in volumes if self.volume_exists(volume))
            if not remaining:
                return
            time.sleep(2)
        raise HarnessError(f"run-owned Proxmox resources remain: {', '.join(remaining)}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_checked(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=True, text=True, **kwargs)


def prepare_image(artifact: Path, output_dir: Path, run_id: str) -> Path:
    if not artifact.is_file():
        raise HarnessError(f"artifact does not exist: {artifact}")
    suffixes = "".join(artifact.suffixes)
    # Proxmox's upload API accepts VM import media with `.raw`, not `.img`.
    image = output_dir / f"{RESOURCE_PREFIX}{run_id}.raw"
    if suffixes.endswith(".img.xz"):
        with image.open("wb") as out:
            subprocess.run(["xz", "-dc", str(artifact)], check=True, stdout=out)
    elif artifact.suffix == ".img":
        shutil.copyfile(artifact, image)
    else:
        raise HarnessError("artifact must be an .img or .img.xz file")
    return image


def prepare_builder_image(artifact: Path, output_dir: Path, run_id: str) -> Path:
    if not artifact.is_file():
        raise HarnessError(f"builder image does not exist: {artifact}")
    image = output_dir / f"{RESOURCE_PREFIX}{run_id}-builder.qcow2"
    if "".join(artifact.suffixes).endswith(".qcow2.xz"):
        with image.open("wb") as out:
            subprocess.run(["xz", "-dc", str(artifact)], check=True, stdout=out)
    elif artifact.suffix == ".qcow2":
        shutil.copyfile(artifact, image)
    else:
        raise HarnessError("builder image must be a .qcow2 or .qcow2.xz file")
    return image


def make_seed(
    cfg: LabConfig,
    output_dir: Path,
    run_id: str,
    public_key: str,
    full: bool = False,
) -> Path:
    password_hash = PasswordHasher().hash(cfg.admin_password)
    wan_ip = FULL_WAN_CIDR if full else cfg.address_cidr
    setup = {
        "hostname": f"aifw-e2e-{run_id}",
        "wan_interface": "vtnet0",
        "wan_mode": "static",
        "wan_ip": wan_ip,
        "wan_gateway": None if full else cfg.gateway,
        "lan_interface": "vtnet1" if full else None,
        "lan_ip": FULL_LAN_CIDR if full else None,
        "admin_username": "e2e-admin",
        "admin_password_hash": password_hash,
        "totp_secret": "",
        "totp_enabled": False,
        "recovery_codes": [],
        "api_listen": "0.0.0.0",
        "api_port": 8080,
        "ui_enabled": True,
        "dns_servers": [] if full else [cfg.dns],
        "dhcp_enabled": False,
        "default_policy": "standard" if full else "permissive",
        "nat_enabled": full,
        "ssh_auth_method": "key_only",
        "ssh_github_user": None,
        "ssh_authorized_keys": [public_key.strip()],
        "ram_mb": 4096,
        "db_path": "/var/db/aifw/aifw.db",
        "config_dir": "/usr/local/etc/aifw",
    }
    seed_dir = output_dir / "seed"
    seed_dir.mkdir(mode=0o700)
    (seed_dir / "setup.json").write_text(json.dumps(setup, indent=2) + "\n")
    seed = output_dir / f"{RESOURCE_PREFIX}{run_id}-seed.iso"
    tool = shutil.which("xorrisofs") or shutil.which("genisoimage")
    if not tool:
        raise HarnessError("xorrisofs or genisoimage is required to create seed media")
    run_checked(
        [tool, "-quiet", "-V", "AIFW_SEED", "-o", str(seed), str(seed_dir)]
    )
    return seed


HELPER_SERVER = """#!/usr/bin/env python3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (self.client_address[0] + "\\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return

ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), Handler).serve_forever()
"""


def start_helper_servers(
    private_key: Path,
    host: str,
    ports: list[int],
    jump: str | None = None,
) -> None:
    encoded = base64.b64encode(HELPER_SERVER.encode()).decode()
    port_list = " ".join(str(port) for port in ports)
    command = (
        f"printf %s {shlex.quote(encoded)} | base64 -d > /tmp/aifw-e2e-server.py && "
        "chmod 700 /tmp/aifw-e2e-server.py && "
        f"for port in {port_list}; do "
        "nohup python3 /tmp/aifw-e2e-server.py \"$port\" "
        ">/tmp/aifw-e2e-server-\"$port\".log 2>&1 </dev/null & done"
    )
    run_checked(
        ssh_command(private_key, host, command, user="root", jump=jump),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def configure_lan_helper_route(private_key: Path, host: str) -> None:
    run_checked(
        ssh_command(
            private_key,
            host,
            "ip route replace 198.18.0.0/24 via 198.19.0.1 dev eth1",
            user="root",
        ),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def make_ssh_key(output_dir: Path) -> tuple[Path, str]:
    private_key = output_dir / "id_ed25519"
    run_checked(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "aifw-e2e",
            "-f",
            str(private_key),
        ]
    )
    return private_key, private_key.with_suffix(".pub").read_text()


def make_builder_seed(
    cfg: LabConfig, output_dir: Path, run_id: str, public_key: str
) -> Path:
    seed_dir = output_dir / "builder-seed"
    seed_dir.mkdir(mode=0o700)
    user_data = f"""#cloud-config
hostname: aifw-builder-{run_id}
disable_root: true
ssh_pwauth: false
# FreeBSD nuageinit processes this top-level key before networking. Entries
# under `users` are delayed until the stock image's post-network firstboot
# work, so using the image's default `freebsd` account avoids that delay.
ssh_authorized_keys:
  - {public_key.strip()}
growpart:
  mode: auto
  devices: ['/']
resize_rootfs: true
"""
    interface = ipaddress.ip_interface(cfg.address_cidr)
    network_data = {
        # FreeBSD 15's native nuageinit NoCloud parser expects cloud-init
        # network-config v2 and iterates network.ethernets directly.
        "version": 2,
        "ethernets": {
            "vtnet0": {
                "addresses": [str(interface)],
                "gateway4": cfg.gateway,
                "nameservers": {"addresses": [cfg.dns]},
            }
        },
    }
    (seed_dir / "user-data").write_text(user_data)
    (seed_dir / "meta-data").write_text(
        json.dumps(
            {
                "instance-id": f"aifw-builder-{run_id}",
                "local-hostname": f"aifw-builder-{run_id}",
            },
            indent=2,
        )
        + "\n"
    )
    (seed_dir / "network-config").write_text(
        json.dumps(network_data, indent=2) + "\n"
    )
    seed = output_dir / f"{RESOURCE_PREFIX}{run_id}-builder-seed.iso"
    tool = shutil.which("xorrisofs") or shutil.which("genisoimage")
    if not tool:
        raise HarnessError("xorrisofs or genisoimage is required to create seed media")
    run_checked([tool, "-quiet", "-V", "cidata", "-o", str(seed), str(seed_dir)])
    return seed


def ssh_command(
    private_key: Path,
    host: str,
    command: str,
    user: str = "root",
    jump: str | None = None,
) -> list[str]:
    args = [
        "ssh",
        "-i",
        str(private_key),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
    ]
    if jump:
        proxy = " ".join(
            shlex.quote(value)
            for value in [
                "ssh",
                "-i",
                str(private_key),
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-W",
                "%h:%p",
                jump,
            ]
        )
        args.extend(["-o", f"ProxyCommand={proxy}"])
    args.extend([f"{user}@{host}", command])
    return args


@contextlib.contextmanager
def ssh_tunnel(
    private_key: Path,
    bastion: str,
    remote_host: str,
    remote_port: int,
):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        local_port = int(probe.getsockname()[1])
    process = subprocess.Popen(
        [
            "ssh",
            "-i",
            str(private_key),
            "-o",
            "BatchMode=yes",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-N",
            "-L",
            f"127.0.0.1:{local_port}:{remote_host}:{remote_port}",
            bastion if "@" in bastion else f"root@{bastion}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise HarnessError("SSH tunnel exited before becoming ready")
            with socket.socket() as check:
                check.settimeout(1)
                if check.connect_ex(("127.0.0.1", local_port)) == 0:
                    break
            time.sleep(0.5)
        else:
            raise HarnessError("SSH tunnel readiness timed out")
        yield local_port
    finally:
        process.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=5)
        if process.poll() is None:
            process.kill()


def wait_command(
    private_key: Path,
    host: str,
    command: str,
    user: str,
    timeout: int,
    jump: str | None = None,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(
            ssh_command(private_key, host, command, user=user, jump=jump),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            return
        time.sleep(5)
    raise HarnessError(f"SSH readiness timed out for {user}@{host}")


def wait_ssh(
    private_key: Path,
    host: str,
    timeout: int = 600,
    jump: str | None = None,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(
            ssh_command(
                private_key,
                host,
                "test -f /usr/local/etc/aifw/aifw.conf",
                jump=jump,
            ),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            return
        time.sleep(5)
    raise HarnessError(f"SSH/setup readiness timed out for {host}")


def copy_git_archive(
    private_key: Path, host: str, destination: str, user: str = "root"
) -> None:
    run_checked(
        ssh_command(
            private_key,
            host,
            f"mkdir -p {shlex.quote(destination)}",
            user=user,
        )
    )
    archive = subprocess.Popen(["git", "archive", "--format=tar", "HEAD"], stdout=subprocess.PIPE)
    assert archive.stdout is not None
    unpack = subprocess.run(
        ssh_command(
            private_key,
            host,
            f"tar -xf - -C {shlex.quote(destination)}",
            user=user,
        ),
        stdin=archive.stdout,
    )
    archive.stdout.close()
    archive_status = archive.wait()
    if archive_status != 0 or unpack.returncode != 0:
        raise HarnessError("failed to copy the checked-out commit to the builder VM")


def as_root(command: str) -> str:
    """Run a shell command as root on FreeBSD's passwordless wheel account."""
    return f"su root -c {shlex.quote(command)}"


def login_and_check(cfg: LabConfig, base: str | None = None) -> dict[str, Any]:
    base = base or f"https://{cfg.address}:8080"
    session = requests.Session()
    session.verify = False
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = session.post(
        f"{base}/api/v1/auth/login",
        json={"username": "e2e-admin", "password": cfg.admin_password},
        timeout=20,
    )
    response.raise_for_status()
    token = response.json()["tokens"]["access_token"]
    status = session.get(
        f"{base}/api/v1/status",
        headers={"Authorization": f"Bearer {token}"},
        timeout=20,
    )
    status.raise_for_status()
    data = status.json()
    if not data.get("pf_running"):
        raise HarnessError("authenticated status reports pf_running=false")
    ui = session.get(f"{base}/", timeout=20)
    ui.raise_for_status()
    if "AiFw" not in ui.text:
        raise HarnessError("served UI does not contain the AiFw marker")
    return data


def api_session(cfg: LabConfig, base: str) -> requests.Session:
    session = requests.Session()
    session.verify = False
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = session.post(
        f"{base}/api/v1/auth/login",
        json={"username": "e2e-admin", "password": cfg.admin_password},
        timeout=20,
    )
    response.raise_for_status()
    session.headers["Authorization"] = (
        f"Bearer {response.json()['tokens']['access_token']}"
    )
    return session


def test_http_flow(
    private_key: Path,
    source_host: str,
    destination: str,
    expected: str | None,
    jump: str | None = None,
    user: str = "root",
) -> str:
    command = f"wget -q -T 8 -O - {shlex.quote(destination)}"
    result = subprocess.run(
        ssh_command(private_key, source_host, command, user=user, jump=jump),
        capture_output=True,
        text=True,
        timeout=30,
    )
    observed = result.stdout.strip()
    if expected is None:
        if result.returncode == 0:
            raise HarnessError(f"flow unexpectedly succeeded: {destination}")
        return "blocked"
    if result.returncode != 0:
        raise HarnessError(f"flow failed unexpectedly: {destination}")
    if observed != expected:
        raise HarnessError(
            f"flow {destination} observed source {observed!r}, expected {expected!r}"
        )
    return observed


def clear_pf_states(private_key: Path, appliance_host: str, jump: str) -> None:
    run_checked(
        ssh_command(private_key, appliance_host, "pfctl -F states", jump=jump),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def create_rule(
    session: requests.Session,
    base: str,
    *,
    action: str,
    interface: str,
    source: str,
    destination: str,
    port: int,
    label: str,
    priority: int,
) -> str:
    response = session.post(
        f"{base}/api/v1/rules",
        json={
            "action": action,
            "direction": "in",
            "protocol": "tcp",
            "src_addr": source,
            "dst_addr": destination,
            "dst_port_start": port,
            "dst_port_end": port,
            "interface": interface,
            "ip_version": "inet",
            "priority": priority,
            "log": action == "block",
            "quick": True,
            "label": label,
            "state_tracking": "keep_state" if action == "pass" else "none",
            "status": "active",
        },
        timeout=20,
    )
    response.raise_for_status()
    rule_id = response.json()["data"]["id"]
    reload_response = session.post(f"{base}/api/v1/reload", timeout=60)
    reload_response.raise_for_status()
    if "Partial reload" in reload_response.json().get("message", ""):
        raise HarnessError(reload_response.json()["message"])
    return str(rule_id)


def delete_rule(session: requests.Session, base: str, rule_id: str) -> None:
    response = session.delete(f"{base}/api/v1/rules/{rule_id}", timeout=20)
    response.raise_for_status()
    reload_response = session.post(f"{base}/api/v1/reload", timeout=60)
    reload_response.raise_for_status()
    if "Partial reload" in reload_response.json().get("message", ""):
        raise HarnessError(reload_response.json()["message"])


def browser_checks(cfg: LabConfig, base: str, output_dir: Path) -> None:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as error:
        raise HarnessError("Playwright is required for full E2E browser checks") from error

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.goto(f"{base}/login", wait_until="networkidle")
        page.get_by_label("Username").fill("e2e-admin")
        page.get_by_label("Password").fill(cfg.admin_password)
        page.get_by_role("button", name="Sign In").click()
        page.wait_for_url(f"{base}/", timeout=30_000)
        page.locator("h1").first.wait_for(state="visible")
        page.goto(f"{base}/rules", wait_until="networkidle")
        page.get_by_role("heading", name="Firewall Rules").wait_for(state="visible")
        page.screenshot(path=str(output_dir / "rules-page.png"), full_page=True)
        browser.close()


def full_data_plane_checks(
    cfg: LabConfig,
    private_key: Path,
    output_dir: Path,
) -> tuple[dict[str, Any], str]:
    jump = f"root@{cfg.address}"
    appliance_host = FULL_LAN_CIDR.split("/", 1)[0]
    evidence: dict[str, Any] = {}

    evidence["lan_to_wan_nat_source"] = test_http_flow(
        private_key,
        cfg.address,
        f"http://{FULL_WAN_HELPER}:9001/",
        FULL_WAN_CIDR.split("/", 1)[0],
    )
    evidence["wan_to_lan_initial"] = test_http_flow(
        private_key,
        FULL_WAN_HELPER,
        f"http://{FULL_LAN_HELPER}:9101/",
        None,
        jump=jump,
    )

    with ssh_tunnel(private_key, cfg.address, appliance_host, 8080) as port:
        base = f"https://127.0.0.1:{port}"
        session = api_session(cfg, base)
        allow_id = create_rule(
            session,
            base,
            action="pass",
            interface="vtnet0",
            source=FULL_WAN_HELPER,
            destination=FULL_LAN_HELPER,
            port=9102,
            label="E2E allow WAN to LAN",
            priority=-100,
        )
        clear_pf_states(private_key, appliance_host, jump)
        evidence["wan_to_lan_after_allow"] = test_http_flow(
            private_key,
            FULL_WAN_HELPER,
            f"http://{FULL_LAN_HELPER}:9102/",
            FULL_WAN_HELPER,
            jump=jump,
        )

        block_id = create_rule(
            session,
            base,
            action="block",
            interface="vtnet1",
            source=FULL_LAN_HELPER,
            destination=FULL_WAN_HELPER,
            port=9003,
            label="E2E block LAN to WAN",
            priority=-200,
        )
        try:
            clear_pf_states(private_key, appliance_host, jump)
            evidence["lan_to_wan_after_block"] = test_http_flow(
                private_key,
                cfg.address,
                f"http://{FULL_WAN_HELPER}:9003/",
                None,
            )
        finally:
            delete_rule(session, base, block_id)
        clear_pf_states(private_key, appliance_host, jump)
        evidence["lan_to_wan_after_delete"] = test_http_flow(
            private_key,
            cfg.address,
            f"http://{FULL_WAN_HELPER}:9004/",
            FULL_WAN_CIDR.split("/", 1)[0],
        )
        browser_checks(cfg, base, output_dir)
        evidence["browser"] = "passed"
    return evidence, allow_id


def post_reboot_data_plane_checks(
    cfg: LabConfig,
    private_key: Path,
    allow_rule_id: str,
) -> dict[str, Any]:
    jump = f"root@{cfg.address}"
    appliance_host = FULL_LAN_CIDR.split("/", 1)[0]
    evidence = {
        "lan_to_wan_nat_source": test_http_flow(
            private_key,
            cfg.address,
            f"http://{FULL_WAN_HELPER}:9002/",
            FULL_WAN_CIDR.split("/", 1)[0],
        ),
        "persisted_wan_to_lan_allow": test_http_flow(
            private_key,
            FULL_WAN_HELPER,
            f"http://{FULL_LAN_HELPER}:9102/",
            FULL_WAN_HELPER,
            jump=jump,
        ),
    }
    with ssh_tunnel(private_key, cfg.address, appliance_host, 8080) as port:
        base = f"https://127.0.0.1:{port}"
        delete_rule(api_session(cfg, base), base, allow_rule_id)
    clear_pf_states(private_key, appliance_host, jump)
    evidence["wan_to_lan_after_allow_delete"] = test_http_flow(
        private_key,
        FULL_WAN_HELPER,
        f"http://{FULL_LAN_HELPER}:9102/",
        None,
        jump=jump,
    )
    return evidence


def appliance_checks(
    cfg: LabConfig,
    private_key: Path,
    host: str | None = None,
    jump: str | None = None,
) -> dict[str, Any]:
    host = host or cfg.address
    commands = [
        "service aifw_daemon onestatus",
        "service aifw_ids onestatus",
        "service aifw_api onestatus",
        "service aifw_watchdog onestatus",
        "pfctl -si",
        "test -s /usr/local/share/aifw/version",
    ]
    for command in commands:
        run_checked(
            ssh_command(private_key, host, command, jump=jump),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    if jump:
        with ssh_tunnel(private_key, jump, host, 8080) as port:
            return login_and_check(cfg, f"https://127.0.0.1:{port}")
    return login_and_check(cfg)


def wait_appliance_ready(
    cfg: LabConfig,
    private_key: Path,
    timeout: int = 600,
    host: str | None = None,
    jump: str | None = None,
) -> dict[str, Any]:
    """Wait for the complete service/API/pf contract, not merely SSH."""
    deadline = time.monotonic() + timeout
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            return appliance_checks(cfg, private_key, host=host, jump=jump)
        except (HarnessError, requests.RequestException, subprocess.SubprocessError) as error:
            last_error = error
            time.sleep(5)
    detail = f": {last_error}" if last_error is not None else ""
    raise HarnessError(f"complete appliance readiness timed out{detail}")


def collect_diagnostics(
    pve: Proxmox,
    cfg: LabConfig,
    private_key: Path,
    vmid: int,
    output_dir: Path,
    host: str | None = None,
    jump: str | None = None,
) -> None:
    with contextlib.suppress(Exception):
        safe_config = pve.vm_config(vmid)
        output_dir.joinpath("proxmox-vm.json").write_text(
            json.dumps(safe_config, indent=2, sort_keys=True) + "\n"
        )
    command = """set +e
echo '=== uname ==='; uname -a
echo '=== uptime ==='; uptime
echo '=== disks ==='; df -h
echo '=== interfaces ==='; ifconfig -a
echo '=== routes ==='; netstat -rn
echo '=== services ==='
for s in aifw_daemon aifw_ids aifw_api aifw_watchdog rdns rdhcpd trafficcop; do service "$s" onestatus; done
echo '=== processes ==='; ps auxww
echo '=== sockets ==='; sockstat -46l
echo '=== pf info ==='; pfctl -si
echo '=== pf rules ==='; pfctl -sr
echo '=== pf nat ==='; pfctl -sn
echo '=== recent logs ==='; tail -n 300 /var/log/aifw/*.log 2>/dev/null
echo '=== dmesg ==='; dmesg
"""
    with output_dir.joinpath("appliance-diagnostics.txt").open("w") as handle:
        subprocess.run(
            ssh_command(private_key, host or cfg.address, command, jump=jump),
            stdout=handle,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=90,
        )


def collect_helper_diagnostics(
    private_key: Path,
    host: str,
    output: Path,
    jump: str | None = None,
    user: str = "root",
) -> None:
    command = """set +e
echo '=== uname ==='; uname -a
echo '=== interfaces ==='; ip address
echo '=== routes ==='; ip route
echo '=== processes ==='; ps auxww
echo '=== sockets ==='; netstat -lntp
echo '=== cloud-init ==='; cloud-init status --long
echo '=== cloud-init output ==='; tail -n 300 /var/log/cloud-init-output.log
"""
    with output.open("w") as handle:
        subprocess.run(
            ssh_command(private_key, host, command, user=user, jump=jump),
            stdout=handle,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=60,
        )


def reboot_and_check(
    cfg: LabConfig,
    private_key: Path,
    host: str | None = None,
    jump: str | None = None,
) -> dict[str, Any]:
    host = host or cfg.address
    subprocess.run(
        ssh_command(private_key, host, "shutdown -r now", jump=jump),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(10)
    wait_ssh(private_key, host, timeout=600, jump=jump)
    return wait_appliance_ready(
        cfg, private_key, timeout=600, host=host, jump=jump
    )


class Lifecycle:
    def __init__(self, pve: Proxmox, keep_on_failure: bool):
        self.pve = pve
        self.keep_on_failure = keep_on_failure
        self.vmid: int | None = None
        self.additional_vmids: list[int] = []
        self.container_vmids: list[int] = []
        self.volumes: list[str] = []
        self.failed = False

    def cleanup(self) -> None:
        if self.keep_on_failure and self.failed:
            print(f"preserving failed VM {self.vmid} by explicit request", flush=True)
            return
        vmids = self.additional_vmids + ([self.vmid] if self.vmid is not None else [])
        for vmid in self.container_vmids:
            if not self.pve.container_exists(vmid):
                continue
            config = self.pve.container_config(vmid)
            name = config.get("hostname", "")
            if not name.startswith(RESOURCE_PREFIX):
                raise HarnessError(
                    f"refusing to destroy container {vmid} with unexpected name {name!r}"
                )
            self.pve.destroy_container(vmid)
        for vmid in vmids:
            if not self.pve.vm_exists(vmid):
                continue
            config = self.pve.vm_config(vmid)
            name = config.get("name", "")
            if not name.startswith(RESOURCE_PREFIX):
                raise HarnessError(
                    f"refusing to destroy VM {vmid} with unexpected name {name!r}"
                )
            self.pve.destroy(vmid)
        for volume in self.volumes:
            if RESOURCE_PREFIX not in volume:
                raise HarnessError(f"refusing to delete unexpected volume {volume!r}")
            if self.pve.volume_exists(volume):
                self.pve.delete_volume(volume)
        for vmid in vmids:
            self.pve.wait_resources_absent(vmid, self.volumes if vmid == self.vmid else [])
        for vmid in self.container_vmids:
            if self.pve.container_exists(vmid):
                raise HarnessError(f"run-owned Proxmox container remains: {vmid}")
        print("teardown verified: zero run-owned Proxmox resources", flush=True)


def build_image(args: argparse.Namespace) -> int:
    cfg = LabConfig.from_env()
    run_id = args.run_id or uuid.uuid4().hex[:10]
    if not all(c in "0123456789abcdef-" for c in run_id.lower()):
        raise HarnessError("run ID may contain only hexadecimal characters and hyphens")
    work_root = Path(args.work_dir)
    work_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    work_dir = work_root / f"{RESOURCE_PREFIX}{run_id}-builder"
    work_dir.mkdir(mode=0o700)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    pve = Proxmox(cfg)
    lifecycle = Lifecycle(pve, keep_on_failure=False)

    def handle_signal(signum: int, _frame: Any) -> None:
        lifecycle.failed = True
        raise KeyboardInterrupt(f"received signal {signum}")

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    try:
        private_key, public_key = make_ssh_key(work_dir)
        image = prepare_builder_image(Path(args.builder_image), work_dir, run_id)
        seed = make_builder_seed(cfg, work_dir, run_id, public_key)
        image_volume = pve.upload(image, "import")
        seed_volume = pve.upload(seed, "iso")
        lifecycle.volumes.extend([image_volume, seed_volume])
        vmid = pve.next_vmid()
        lifecycle.vmid = vmid
        name = f"{RESOURCE_PREFIX}builder-{run_id}"
        pve.create_builder_vm(
            vmid,
            name,
            f"AiFw image builder {run_id}; expires {int(time.time()) + 4 * 3600}",
        )
        # Proxmox-generated NoCloud metadata names the interface `eth0` and
        # uses a schema FreeBSD 15's native nuageinit cannot apply. Attach our
        # explicit v2/vtnet0 cidata seed instead.
        pve.attach_imported_disk(vmid, image_volume, seed_volume)
        pve.resize_disk(vmid, "virtio0", args.builder_disk_size)
        pve.start(vmid)

        wait_command(
            private_key,
            cfg.address,
            (
                "test -s /var/cache/nuageinit/user_data && "
                f"ifconfig vtnet0 inet | grep -F {shlex.quote(cfg.address)} && "
                "netstat -rn -f inet | "
                f"awk '$1 == \"default\" && $2 == {json.dumps(cfg.gateway)} "
                "{found=1} END {exit !found}' && "
                f"{as_root('id -u')} | grep -qx 0"
            ),
            user="freebsd",
            timeout=args.boot_timeout,
        )
        copy_git_archive(
            private_key, cfg.address, "/home/freebsd/AiFw", user="freebsd"
        )
        commit_sha = run_checked(
            ["git", "rev-parse", "HEAD"], capture_output=True
        ).stdout.strip()
        run_checked(
            ssh_command(
                private_key,
                cfg.address,
                (
                    "printf '%s\\n' "
                    f"{shlex.quote(commit_sha)} > /home/freebsd/AiFw/.aifw-build-commit"
                ),
                user="freebsd",
            )
        )
        version = run_checked(
            [
                "sh",
                "-c",
                "sed -n 's/^version = \"\\([^\"]*\\)\"/\\1/p' Cargo.toml | head -n 1",
            ],
            cwd=Path.cwd(),
            capture_output=True,
        ).stdout.strip()
        if not version:
            raise HarnessError("could not determine workspace version from Cargo.toml")
        remote_artifact = f"/usr/obj/aifw-iso/output/aifw-{version}-amd64.img.xz"
        build_command = as_root(
            "cd /home/freebsd/AiFw && "
            f"sh freebsd/build-local.sh {shlex.quote(version)} && "
            f"test -s {shlex.quote(remote_artifact)}"
        )
        run_checked(
            ssh_command(
                private_key,
                cfg.address,
                build_command,
                user="freebsd",
            )
        )
        with output.open("wb") as handle:
            result = subprocess.run(
                ssh_command(
                    private_key,
                    cfg.address,
                    as_root(f"cat {shlex.quote(remote_artifact)}"),
                    user="freebsd",
                ),
                stdout=handle,
            )
        if result.returncode != 0 or not output.is_file() or output.stat().st_size == 0:
            raise HarnessError("failed to copy the built IMG from the builder VM")
        output.with_suffix(output.suffix + ".sha256").write_text(
            f"{sha256_file(output)}  {output.name}\n"
        )
        print(f"built {output} ({output.stat().st_size} bytes)", flush=True)
        return 0
    except BaseException:
        lifecycle.failed = True
        raise
    finally:
        try:
            lifecycle.cleanup()
        finally:
            if work_dir.parent == work_root and work_dir.name.startswith(RESOURCE_PREFIX):
                shutil.rmtree(work_dir, ignore_errors=True)


def run(args: argparse.Namespace) -> int:
    cfg = LabConfig.from_env()
    run_id = args.run_id or uuid.uuid4().hex[:10]
    if not all(c in "0123456789abcdef-" for c in run_id.lower()):
        raise HarnessError("run ID may contain only hexadecimal characters and hyphens")
    output_dir = Path(args.artifacts) / run_id
    output_dir.mkdir(parents=True, mode=0o700)
    work_root = Path(args.work_dir)
    work_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    work_dir = work_root / f"{RESOURCE_PREFIX}{run_id}"
    work_dir.mkdir(mode=0o700)
    pve = Proxmox(cfg)
    lifecycle = Lifecycle(pve, args.keep_on_failure)
    private_key: Path | None = None

    def handle_signal(signum: int, _frame: Any) -> None:
        lifecycle.failed = True
        raise KeyboardInterrupt(f"received signal {signum}")

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    manifest: dict[str, Any] = {
        "run_id": run_id,
        "artifact": Path(args.artifact).name,
        "artifact_sha256": sha256_file(Path(args.artifact)),
        "started_at": int(time.time()),
        "network_scope": "single-nic-smoke",
    }
    try:
        private_key, public_key = make_ssh_key(work_dir)
        seed = make_seed(cfg, work_dir, run_id, public_key)
        image = prepare_image(Path(args.artifact), work_dir, run_id)

        image_volume = pve.upload(image, "import")
        seed_volume = pve.upload(seed, "iso")
        lifecycle.volumes.extend([image_volume, seed_volume])
        vmid = pve.next_vmid()
        lifecycle.vmid = vmid
        name = f"{RESOURCE_PREFIX}{run_id}"
        pve.create_vm(
            vmid,
            name,
            f"AiFw E2E run {run_id}; expires {int(time.time()) + 4 * 3600}",
        )
        pve.attach_imported_disk(vmid, image_volume, seed_volume)
        pve.start(vmid)
        manifest["vmid"] = vmid

        wait_ssh(private_key, cfg.address, timeout=args.boot_timeout)
        manifest["initial_status"] = wait_appliance_ready(
            cfg, private_key, timeout=args.boot_timeout
        )
        manifest["post_reboot_status"] = reboot_and_check(cfg, private_key)
        manifest["result"] = "passed"
        return 0
    except BaseException:
        lifecycle.failed = True
        manifest["result"] = "failed"
        raise
    finally:
        if lifecycle.vmid is not None and private_key is not None:
            with contextlib.suppress(Exception):
                collect_diagnostics(pve, cfg, private_key, lifecycle.vmid, output_dir)
        try:
            lifecycle.cleanup()
            manifest["teardown_verified"] = True
        except BaseException:
            manifest["result"] = "failed"
            raise
        finally:
            manifest.setdefault("teardown_verified", False)
            manifest["finished_at"] = int(time.time())
            output_dir.joinpath("manifest.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n"
            )
            # Only remove the exact, prefix-validated per-run directory. This
            # contains the private key, seed config, and decompressed source IMG.
            if work_dir.parent == work_root and work_dir.name.startswith(
                RESOURCE_PREFIX
            ):
                shutil.rmtree(work_dir)


def run_full(args: argparse.Namespace) -> int:
    cfg = LabConfig.from_env()
    run_id = args.run_id or uuid.uuid4().hex[:10]
    if not all(c in "0123456789abcdef-" for c in run_id.lower()):
        raise HarnessError("run ID may contain only hexadecimal characters and hyphens")
    output_dir = Path(args.artifacts) / run_id
    output_dir.mkdir(parents=True, mode=0o700)
    work_root = Path(args.work_dir)
    work_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    work_dir = work_root / f"{RESOURCE_PREFIX}{run_id}-full"
    work_dir.mkdir(mode=0o700)
    pve = Proxmox(cfg)
    lifecycle = Lifecycle(pve, args.keep_on_failure)
    private_key: Path | None = None
    appliance_vmid: int | None = None
    helper_vmids: dict[str, int] = {}

    def handle_signal(signum: int, _frame: Any) -> None:
        lifecycle.failed = True
        raise KeyboardInterrupt(f"received signal {signum}")

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    manifest: dict[str, Any] = {
        "run_id": run_id,
        "artifact": Path(args.artifact).name,
        "artifact_sha256": sha256_file(Path(args.artifact)),
        "helper_template": HELPER_TEMPLATE,
        "started_at": int(time.time()),
        "network_scope": "isolated-wan-lan-full",
        "topology": {
            "management": f"{cfg.bridge}:{cfg.address_cidr}",
            "wan": f"{cfg.wan_bridge}:198.18.0.0/24",
            "lan": f"{cfg.lan_bridge}:198.19.0.0/24",
        },
    }
    try:
        pve.require_bridges([cfg.bridge, cfg.wan_bridge, cfg.lan_bridge])
        private_key, public_key = make_ssh_key(work_dir)
        appliance_seed = make_seed(cfg, work_dir, run_id, public_key, full=True)
        appliance_image = prepare_image(Path(args.artifact), work_dir, run_id)
        appliance_image_volume = pve.upload(appliance_image, "import")
        appliance_seed_volume = pve.upload(appliance_seed, "iso")
        lifecycle.volumes.extend(
            [
                appliance_image_volume,
                appliance_seed_volume,
            ]
        )

        lan_vmid = pve.next_vmid()
        pve.create_helper_container(
            lan_vmid,
            f"{RESOURCE_PREFIX}lan-{run_id}",
            f"AiFw E2E LAN helper {run_id}; expires {int(time.time()) + 4 * 3600}",
            public_key,
            [
                f"name=eth0,bridge={cfg.bridge},firewall=0,ip={cfg.address_cidr},gw={cfg.gateway},type=veth",
                f"name=eth1,bridge={cfg.lan_bridge},firewall=0,ip={FULL_LAN_HELPER}/24,type=veth",
            ],
        )
        lifecycle.container_vmids.append(lan_vmid)
        helper_vmids["lan"] = lan_vmid

        wan_vmid = pve.next_vmid()
        pve.create_helper_container(
            wan_vmid,
            f"{RESOURCE_PREFIX}wan-{run_id}",
            f"AiFw E2E WAN helper {run_id}; expires {int(time.time()) + 4 * 3600}",
            public_key,
            [f"name=eth0,bridge={cfg.wan_bridge},firewall=0,ip={FULL_WAN_HELPER}/24,gw={FULL_WAN_CIDR.split('/', 1)[0]},type=veth"],
        )
        lifecycle.container_vmids.append(wan_vmid)
        helper_vmids["wan"] = wan_vmid

        appliance_vmid = pve.next_vmid()
        lifecycle.vmid = appliance_vmid
        pve.create_full_appliance_vm(
            appliance_vmid,
            f"{RESOURCE_PREFIX}{run_id}",
            f"AiFw full E2E run {run_id}; expires {int(time.time()) + 4 * 3600}",
        )
        pve.attach_imported_disk(
            appliance_vmid, appliance_image_volume, appliance_seed_volume
        )
        manifest["vmids"] = {
            "appliance": appliance_vmid,
            "lan_helper": lan_vmid,
            "wan_helper": wan_vmid,
        }

        pve.start_container(lan_vmid)
        wait_command(
            private_key,
            cfg.address,
            "test -x /usr/bin/python3",
            user="root",
            timeout=args.boot_timeout,
        )
        configure_lan_helper_route(private_key, cfg.address)
        start_helper_servers(private_key, cfg.address, [9101, 9102, 9103, 9104])
        pve.start_container(wan_vmid)
        pve.start(appliance_vmid)
        jump = f"root@{cfg.address}"
        appliance_host = FULL_LAN_CIDR.split("/", 1)[0]
        wait_ssh(
            private_key,
            appliance_host,
            timeout=args.boot_timeout,
            jump=jump,
        )
        wait_command(
            private_key,
            FULL_WAN_HELPER,
            "test -x /usr/bin/python3",
            user="root",
            timeout=args.boot_timeout,
            jump=jump,
        )
        start_helper_servers(
            private_key,
            FULL_WAN_HELPER,
            [9001, 9002, 9003, 9004],
            jump=jump,
        )
        manifest["initial_status"] = wait_appliance_ready(
            cfg,
            private_key,
            timeout=args.boot_timeout,
            host=appliance_host,
            jump=jump,
        )
        data_plane, allow_rule_id = full_data_plane_checks(
            cfg, private_key, output_dir
        )
        manifest["initial_data_plane"] = data_plane
        manifest["post_reboot_status"] = reboot_and_check(
            cfg, private_key, host=appliance_host, jump=jump
        )
        manifest["post_reboot_data_plane"] = post_reboot_data_plane_checks(
            cfg, private_key, allow_rule_id
        )
        manifest["result"] = "passed"
        return 0
    except BaseException:
        lifecycle.failed = True
        manifest["result"] = "failed"
        raise
    finally:
        if appliance_vmid is not None and private_key is not None:
            with contextlib.suppress(Exception):
                collect_diagnostics(
                    pve,
                    cfg,
                    private_key,
                    appliance_vmid,
                    output_dir,
                    host=FULL_LAN_CIDR.split("/", 1)[0],
                    jump=f"root@{cfg.address}",
                )
            with contextlib.suppress(Exception):
                collect_helper_diagnostics(
                    private_key,
                    cfg.address,
                    output_dir / "lan-helper-diagnostics.txt",
                    user="root",
                )
            with contextlib.suppress(Exception):
                collect_helper_diagnostics(
                    private_key,
                    FULL_WAN_HELPER,
                    output_dir / "wan-helper-diagnostics.txt",
                    jump=f"root@{cfg.address}",
                    user="root",
                )
        try:
            lifecycle.cleanup()
            manifest["teardown_verified"] = True
        except BaseException:
            manifest["result"] = "failed"
            raise
        finally:
            manifest.setdefault("teardown_verified", False)
            manifest["finished_at"] = int(time.time())
            output_dir.joinpath("manifest.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n"
            )
            if work_dir.parent == work_root and work_dir.name.startswith(
                RESOURCE_PREFIX
            ):
                shutil.rmtree(work_dir)


def check_helper(args: argparse.Namespace) -> int:
    """Focused, disposable validation of the Linux helper substrate."""
    cfg = LabConfig.from_env()
    run_id = args.run_id or uuid.uuid4().hex[:10]
    if not all(c in "0123456789abcdef-" for c in run_id.lower()):
        raise HarnessError("run ID may contain only hexadecimal characters and hyphens")
    work_root = Path(args.work_dir)
    work_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    work_dir = work_root / f"{RESOURCE_PREFIX}{run_id}-helper-check"
    work_dir.mkdir(mode=0o700)
    pve = Proxmox(cfg)
    lifecycle = Lifecycle(pve, keep_on_failure=False)
    try:
        pve.require_bridges([cfg.bridge, cfg.lan_bridge])
        private_key, public_key = make_ssh_key(work_dir)
        vmid = pve.next_vmid()
        pve.create_helper_container(
            vmid,
            f"{RESOURCE_PREFIX}helper-{run_id}",
            f"AiFw focused helper check {run_id}; expires {int(time.time()) + 3600}",
            public_key,
            [
                f"name=eth0,bridge={cfg.bridge},firewall=0,ip={cfg.address_cidr},gw={cfg.gateway},type=veth",
                f"name=eth1,bridge={cfg.lan_bridge},firewall=0,ip={FULL_LAN_HELPER}/24,type=veth",
            ],
        )
        lifecycle.container_vmids.append(vmid)
        pve.start_container(vmid)
        wait_command(
            private_key,
            cfg.address,
            (
                f"ip -4 addr show eth0 | grep -F {shlex.quote(cfg.address_cidr)} && "
                "ip -4 addr show eth1 | grep -F 198.19.0.2/24 && "
                f"ip route | grep -F 'default via {cfg.gateway} dev eth0'"
            ),
            user="root",
            timeout=args.boot_timeout,
        )
        configure_lan_helper_route(private_key, cfg.address)
        start_helper_servers(private_key, cfg.address, [9101])
        test_http_flow(
            private_key,
            cfg.address,
            "http://127.0.0.1:9101/",
            "127.0.0.1",
        )
        print("focused helper boot/network/SSH/server check passed", flush=True)
        return 0
    except BaseException:
        lifecycle.failed = True
        raise
    finally:
        try:
            lifecycle.cleanup()
        finally:
            if work_dir.parent == work_root and work_dir.name.startswith(
                RESOURCE_PREFIX
            ):
                shutil.rmtree(work_dir)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)
    run_parser = sub.add_parser("run", help="run the Proxmox appliance lifecycle")
    run_parser.add_argument("--artifact", required=True)
    run_parser.add_argument("--artifacts", default="e2e/artifacts")
    run_parser.add_argument("--work-dir", default="e2e/.run")
    run_parser.add_argument("--run-id")
    run_parser.add_argument("--boot-timeout", type=int, default=900)
    run_parser.add_argument("--keep-on-failure", action="store_true")
    full_parser = sub.add_parser(
        "full", help="run the isolated WAN/LAN Proxmox lifecycle"
    )
    full_parser.add_argument("--artifact", required=True)
    full_parser.add_argument("--artifacts", default="e2e/artifacts")
    full_parser.add_argument("--work-dir", default="e2e/.run")
    full_parser.add_argument("--run-id")
    full_parser.add_argument("--boot-timeout", type=int, default=900)
    full_parser.add_argument("--keep-on-failure", action="store_true")
    helper_parser = sub.add_parser(
        "check-helper", help="run a focused disposable Linux helper check"
    )
    helper_parser.add_argument("--work-dir", default="e2e/.run")
    helper_parser.add_argument("--run-id")
    helper_parser.add_argument("--boot-timeout", type=int, default=300)
    build_parser = sub.add_parser(
        "build", help="build an AiFw IMG in an ephemeral Proxmox FreeBSD VM"
    )
    build_parser.add_argument("--builder-image", required=True)
    build_parser.add_argument("--output", required=True)
    build_parser.add_argument("--work-dir", default="e2e/.run")
    build_parser.add_argument("--run-id")
    build_parser.add_argument("--boot-timeout", type=int, default=900)
    build_parser.add_argument("--builder-disk-size", default="+40G")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "run":
            return run(args)
        if args.command == "full":
            return run_full(args)
        if args.command == "check-helper":
            return check_helper(args)
        if args.command == "build":
            return build_image(args)
    except HarnessError as error:
        print(f"E2E ERROR: {error}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
