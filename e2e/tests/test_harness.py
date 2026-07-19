from pathlib import Path

import pytest
from argon2 import PasswordHasher

from e2e.aifw_e2e import (
    HarnessError,
    LabConfig,
    Proxmox,
    build_image,
    make_builder_seed,
    make_seed,
    prepare_builder_image,
    prepare_image,
)


def config(password: str = "temporary-test-password") -> LabConfig:
    return LabConfig(
        pve_url="https://pve.invalid:8006",
        pve_node="pve",
        image_storage="local",
        vm_storage="local-lvm",
        bridge="vmbr0",
        verify_tls=True,
        address_cidr="192.0.2.10/24",
        gateway="192.0.2.1",
        dns="192.0.2.1",
        token_id="root@pam!test",
        token_secret="not-a-real-token",
        admin_password=password,
    )


def test_prepare_image_rejects_non_image(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("not an image")
    with pytest.raises(HarnessError, match="must be an .img"):
        prepare_image(artifact, tmp_path, "abc123")


def test_prepare_builder_image_rejects_non_qcow2(tmp_path: Path) -> None:
    artifact = tmp_path / "builder.raw.xz"
    artifact.write_bytes(b"not a builder")
    with pytest.raises(HarnessError, match="must be a .qcow2"):
        prepare_builder_image(artifact, tmp_path, "abc123")


def test_seed_uses_argon2_and_excludes_plaintext(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    created: list[list[str]] = []

    def fake_run(args: list[str], **_kwargs: object) -> object:
        created.append(args)
        Path(args[args.index("-o") + 1]).write_bytes(b"fake iso")
        return object()

    monkeypatch.setattr("e2e.aifw_e2e.shutil.which", lambda _name: "/usr/bin/xorrisofs")
    monkeypatch.setattr("e2e.aifw_e2e.run_checked", fake_run)
    password = "unique-plain-text-secret"
    seed = make_seed(config(password), tmp_path, "abc123", "ssh-ed25519 AAAAtest")

    setup_text = (tmp_path / "seed" / "setup.json").read_text()
    assert password not in setup_text
    assert "not-a-real-token" not in setup_text
    assert seed.read_bytes() == b"fake iso"
    assert created

    import json

    setup = json.loads(setup_text)
    PasswordHasher().verify(setup["admin_password_hash"], password)


def test_seed_has_only_one_management_interface(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("e2e.aifw_e2e.shutil.which", lambda _name: "/usr/bin/xorrisofs")

    def fake_run(args: list[str], **_kwargs: object) -> object:
        Path(args[args.index("-o") + 1]).write_bytes(b"fake iso")
        return object()

    monkeypatch.setattr("e2e.aifw_e2e.run_checked", fake_run)
    make_seed(config(), tmp_path, "def456", "ssh-ed25519 AAAAtest")

    import json

    setup = json.loads((tmp_path / "seed" / "setup.json").read_text())
    assert setup["wan_interface"] == "vtnet0"
    assert setup["lan_interface"] is None
    assert setup["default_policy"] == "permissive"


def test_builder_seed_uses_reserved_address_and_public_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("e2e.aifw_e2e.shutil.which", lambda _name: "/usr/bin/xorrisofs")

    def fake_run(args: list[str], **_kwargs: object) -> object:
        Path(args[args.index("-o") + 1]).write_bytes(b"fake builder seed")
        return object()

    monkeypatch.setattr("e2e.aifw_e2e.run_checked", fake_run)
    seed = make_builder_seed(
        config(), tmp_path, "def456", "ssh-ed25519 AAAAbuilder"
    )

    user_data = (tmp_path / "builder-seed" / "user-data").read_text()
    network = (tmp_path / "builder-seed" / "network-config").read_text()
    assert "ssh-ed25519 AAAAbuilder" in user_data
    assert "temporary-test-password" not in user_data
    assert "192.0.2.10" in network
    assert "255.255.255.0" in network
    assert "192.0.2.1" in network
    assert seed.read_bytes() == b"fake builder seed"


def test_build_accepts_precreated_work_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import argparse

    work_root = tmp_path / ".run"
    work_root.mkdir()
    builder_image = tmp_path / "builder.qcow2"
    builder_image.write_bytes(b"builder")
    monkeypatch.setattr(LabConfig, "from_env", classmethod(lambda _cls: config()))
    monkeypatch.setattr(Proxmox, "upload", lambda *_args, **_kwargs: (_ for _ in ()).throw(HarnessError("stop after setup")))

    args = argparse.Namespace(
        run_id="abc123",
        work_dir=str(work_root),
        output=str(tmp_path / "aifw.img.xz"),
        builder_image=str(builder_image),
        builder_disk_size="+40G",
        boot_timeout=1,
    )
    monkeypatch.setattr("e2e.aifw_e2e.make_ssh_key", lambda path: (path / "key", "ssh-ed25519 test"))
    monkeypatch.setattr("e2e.aifw_e2e.make_builder_seed", lambda _cfg, path, _run, _key: path / "seed.iso")
    monkeypatch.setattr("e2e.aifw_e2e.prepare_builder_image", lambda _src, path, _run: path / "builder.qcow2")

    with pytest.raises(HarnessError, match="stop after setup"):
        build_image(args)


def test_builder_cloudinit_url_encodes_ssh_key() -> None:
    pve = Proxmox(config())
    captured: dict[str, object] = {}

    def fake_request(method: str, path: str, **kwargs: object) -> None:
        captured.update(method=method, path=path, **kwargs)

    pve.request = fake_request  # type: ignore[method-assign]
    pve.configure_builder_cloudinit(101, "ssh-ed25519 AAAAtest aifw-e2e\n")

    data = captured["data"]
    assert isinstance(data, dict)
    assert data["sshkeys"] == "ssh-ed25519%20AAAAtest%20aifw-e2e"
    assert data["ipconfig0"] == "ip=192.0.2.10/24,gw=192.0.2.1"
