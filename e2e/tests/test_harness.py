from pathlib import Path

import pytest
from argon2 import PasswordHasher

from e2e.aifw_e2e import (
    HarnessError,
    LabConfig,
    Lifecycle,
    Proxmox,
    as_root,
    build_image,
    make_builder_seed,
    make_seed,
    prepare_builder_image,
    prepare_image,
    wait_appliance_ready,
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
    assert "192.0.2.10/24" in network
    assert "192.0.2.1" in network
    assert '"version": 2' in network
    assert '"ethernets"' in network
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


def test_builder_uses_early_default_freebsd_user() -> None:
    source = Path("e2e/aifw_e2e.py").read_text()
    build_section = source[source.index("def build_image(") : source.index("def run(")]
    assert 'user="freebsd"' in build_section
    assert 'user="builder"' not in build_section
    assert "/home/freebsd/AiFw" in build_section
    assert "make_builder_seed" in build_section
    assert "configure_builder_cloudinit" not in build_section


def test_as_root_quotes_the_entire_command() -> None:
    assert as_root("id -u && echo 'safe value'") == (
        "su root -c 'id -u && echo '\"'\"'safe value'\"'\"''"
    )


def test_appliance_firstboot_is_not_sentinel_gated() -> None:
    source = Path("freebsd/overlay/usr/local/etc/rc.d/aifw_firstboot").read_text()
    directives = [line for line in source.splitlines() if line.startswith("# KEYWORD:")]
    assert directives == []
    assert 'if [ -f "$AIFW_CONF" ]; then' in source


def test_writable_image_root_label_matches_boot_configuration() -> None:
    source = Path("freebsd/build-iso.sh").read_text()
    assert 'newfs -U -j -L aifw "/dev/${MD}p3"' in source
    assert "/dev/ufs/aifw  /       ufs" in source
    assert 'vfs.root.mountfrom="ufs:/dev/ufs/aifw"' in source


def test_setup_persists_aifw_pf_rules_path() -> None:
    source = Path("aifw-setup/src/apply.rs").read_text()
    assert 'run_best_effort("sysrc", &["pf_enable=YES"])' in source
    assert 'format!("pf_rules={}/pf.conf.aifw", config.config_dir)' in source


def test_complete_readiness_retries_transient_pf_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = iter(
        [
            HarnessError("authenticated status reports pf_running=false"),
            {"pf_running": True},
        ]
    )

    def fake_checks(_cfg: LabConfig, _key: Path) -> dict[str, object]:
        result = next(attempts)
        if isinstance(result, BaseException):
            raise result
        return result

    monkeypatch.setattr("e2e.aifw_e2e.appliance_checks", fake_checks)
    monkeypatch.setattr("e2e.aifw_e2e.time.sleep", lambda _seconds: None)
    assert wait_appliance_ready(config(), Path("key"), timeout=1) == {
        "pf_running": True
    }


def test_import_finishes_before_boot_order_is_set() -> None:
    pve = Proxmox(config())
    requests: list[dict[str, object]] = []

    def fake_request(method: str, path: str, **kwargs: object) -> str:
        requests.append({"method": method, "path": path, **kwargs})
        return f"task-{len(requests)}"

    pve.request = fake_request  # type: ignore[method-assign]
    pve.wait_task = lambda _task: None  # type: ignore[method-assign]
    pve.attach_imported_disk(101, "local:import/aifw.raw", "local:iso/seed.iso")

    assert requests[0]["data"] == {
        "virtio0": "local-lvm:0,import-from=local:import/aifw.raw,discard=on",
        "ide2": "local:iso/seed.iso,media=cdrom",
    }
    assert requests[1]["data"] == {"boot": "order=virtio0"}


def test_cleanup_deletes_owned_resources_and_proves_absence() -> None:
    class FakeProxmox:
        vm_present = True
        present_volumes = {"local:iso/aifw-e2e-seed.iso"}
        audited = False

        def vm_exists(self, vmid: int) -> bool:
            assert vmid == 101
            return self.vm_present

        def vm_config(self, vmid: int) -> dict[str, str]:
            assert vmid == 101
            return {"name": "aifw-e2e-abc123"}

        def destroy(self, vmid: int) -> None:
            assert vmid == 101
            self.vm_present = False

        def volume_exists(self, volume: str) -> bool:
            return volume in self.present_volumes

        def delete_volume(self, volume: str) -> None:
            self.present_volumes.remove(volume)

        def wait_resources_absent(
            self, vmid: int | None, volumes: list[str]
        ) -> None:
            assert vmid == 101
            assert volumes == ["local:iso/aifw-e2e-seed.iso"]
            assert not self.vm_present
            assert not self.present_volumes
            self.audited = True

    pve = FakeProxmox()
    lifecycle = Lifecycle(pve, keep_on_failure=False)  # type: ignore[arg-type]
    lifecycle.vmid = 101
    lifecycle.volumes = ["local:iso/aifw-e2e-seed.iso"]
    lifecycle.cleanup()
    assert pve.audited


def test_cleanup_refuses_unowned_volume() -> None:
    class FakeProxmox:
        def vm_exists(self, _vmid: int) -> bool:
            return False

    lifecycle = Lifecycle(FakeProxmox(), keep_on_failure=False)  # type: ignore[arg-type]
    lifecycle.volumes = ["local:iso/unrelated.iso"]
    with pytest.raises(HarnessError, match="unexpected volume"):
        lifecycle.cleanup()
