#!/usr/bin/env python3
"""Provision, test, diagnose, and destroy an AiFw Proxmox VM."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import shutil
import signal
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
                if status.get("exitstatus") != "OK":
                    raise HarnessError(
                        f"Proxmox task failed: {status.get('exitstatus')} ({upid})"
                    )
                return
            time.sleep(2)
        raise HarnessError(f"timed out waiting for Proxmox task {upid}")

    def next_vmid(self) -> int:
        return int(self.request("GET", "/cluster/nextid"))

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
        config = {
            "virtio0": disk,
            "boot": "order=virtio0",
        }
        if seed_volume is not None:
            config["ide2"] = f"{seed_volume},media=cdrom"
        upid = self.request(
            "PUT",
            f"/nodes/{self.cfg.pve_node}/qemu/{vmid}/config",
            data=config,
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
        with contextlib.suppress(Exception):
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


def make_seed(
    cfg: LabConfig, output_dir: Path, run_id: str, public_key: str
) -> Path:
    password_hash = PasswordHasher().hash(cfg.admin_password)
    setup = {
        "hostname": f"aifw-e2e-{run_id}",
        "wan_interface": "vtnet0",
        "wan_mode": "static",
        "wan_ip": cfg.address_cidr,
        "wan_gateway": cfg.gateway,
        "lan_interface": None,
        "lan_ip": None,
        "admin_username": "e2e-admin",
        "admin_password_hash": password_hash,
        "totp_secret": "",
        "totp_enabled": False,
        "recovery_codes": [],
        "api_listen": "0.0.0.0",
        "api_port": 8080,
        "ui_enabled": True,
        "dns_servers": [cfg.dns],
        "dhcp_enabled": False,
        "default_policy": "permissive",
        "nat_enabled": False,
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


def ssh_command(private_key: Path, host: str, command: str) -> list[str]:
    return [
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
        f"root@{host}",
        command,
    ]


def wait_ssh(private_key: Path, host: str, timeout: int = 600) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(
            ssh_command(private_key, host, "test -f /usr/local/etc/aifw/aifw.conf"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            return
        time.sleep(5)
    raise HarnessError(f"SSH/setup readiness timed out for {host}")


def login_and_check(cfg: LabConfig) -> dict[str, Any]:
    base = f"https://{cfg.address}:8080"
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


def appliance_checks(cfg: LabConfig, private_key: Path) -> dict[str, Any]:
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
            ssh_command(private_key, cfg.address, command),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    return login_and_check(cfg)


def collect_diagnostics(
    pve: Proxmox,
    cfg: LabConfig,
    private_key: Path,
    vmid: int,
    output_dir: Path,
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
            ssh_command(private_key, cfg.address, command),
            stdout=handle,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=90,
        )


def reboot_and_check(cfg: LabConfig, private_key: Path) -> dict[str, Any]:
    subprocess.run(
        ssh_command(private_key, cfg.address, "shutdown -r now"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(10)
    wait_ssh(private_key, cfg.address, timeout=600)
    return appliance_checks(cfg, private_key)


class Lifecycle:
    def __init__(self, pve: Proxmox, keep_on_failure: bool):
        self.pve = pve
        self.keep_on_failure = keep_on_failure
        self.vmid: int | None = None
        self.volumes: list[str] = []
        self.failed = False

    def cleanup(self) -> None:
        if self.keep_on_failure and self.failed:
            print(f"preserving failed VM {self.vmid} by explicit request", flush=True)
            return
        if self.vmid is not None:
            with contextlib.suppress(Exception):
                config = self.pve.vm_config(self.vmid)
                name = config.get("name", "")
                if not name.startswith(RESOURCE_PREFIX):
                    raise HarnessError(
                        f"refusing to destroy VM {self.vmid} with unexpected name {name!r}"
                    )
                self.pve.destroy(self.vmid)
        for volume in self.volumes:
            if RESOURCE_PREFIX in volume:
                self.pve.delete_volume(volume)


def run(args: argparse.Namespace) -> int:
    cfg = LabConfig.from_env()
    run_id = args.run_id or uuid.uuid4().hex[:10]
    if not all(c in "0123456789abcdef-" for c in run_id.lower()):
        raise HarnessError("run ID may contain only hexadecimal characters and hyphens")
    output_dir = Path(args.artifacts) / run_id
    output_dir.mkdir(parents=True, mode=0o700)
    work_root = Path(args.work_dir)
    work_root.mkdir(parents=True, mode=0o700)
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
        manifest["initial_status"] = appliance_checks(cfg, private_key)
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
        manifest["finished_at"] = int(time.time())
        output_dir.joinpath("manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        lifecycle.cleanup()
        # Only remove the exact, prefix-validated per-run directory. This
        # contains the private key, seed config, and decompressed source IMG.
        if work_dir.parent == work_root and work_dir.name.startswith(RESOURCE_PREFIX):
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
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "run":
            return run(args)
    except HarnessError as error:
        print(f"E2E ERROR: {error}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
