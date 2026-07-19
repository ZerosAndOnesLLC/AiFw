from pathlib import Path

import pytest
from argon2 import PasswordHasher

from e2e.aifw_e2e import HarnessError, LabConfig, make_seed, prepare_image


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
