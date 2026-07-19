from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from incident_response_agent.executor import DisposableFilesystemExecutor
from incident_response_agent.sandbox import MARKER_NAME, DisposableSandbox, SandboxViolation
from incident_response_agent.schemas import RemediationOption


def _cleanup_option() -> RemediationOption:
    return RemediationOption(
        action_id="cleanup_rotated_logs",
        title="cleanup",
        evidence=["rotation_error"],
        confidence=1.0,
        impact="bounded",
        risk="low",
        action_preview="fixed",
    )


@pytest.mark.parametrize(
    "unsafe_root",
    [Path("/"), Path(tempfile.gettempdir()), Path.home(), Path.cwd()],
)
def test_rejects_broad_or_application_roots(unsafe_root):
    with pytest.raises(SandboxViolation):
        DisposableSandbox.create_test_fixture(unsafe_root)


def test_rejects_traversal_and_non_empty_arbitrary_directory(tmp_path):
    non_empty = tmp_path / "existing"
    non_empty.mkdir()
    (non_empty / "unrelated.txt").write_text("preserve", encoding="utf-8")
    with pytest.raises(SandboxViolation):
        DisposableSandbox.create_test_fixture(non_empty)
    with pytest.raises(SandboxViolation):
        DisposableSandbox.create_test_fixture(tmp_path / "parent" / ".." / "escape")


def test_rejects_symlinked_parent(tmp_path):
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(SandboxViolation):
        DisposableSandbox.create_test_fixture(linked_parent / "sandbox")


def test_executor_rejects_child_symlink_escape(tmp_path):
    sandbox = DisposableSandbox.create_test_fixture(tmp_path / "sandbox")
    outside = tmp_path / "outside"
    outside.mkdir()
    (sandbox.root / "logs").symlink_to(outside, target_is_directory=True)
    result = DisposableFilesystemExecutor(sandbox).execute(_cleanup_option())
    assert result.success is False
    assert result.failure_reason_code == "unsafe_sandbox_root"


def test_executor_rejects_missing_ownership_marker(tmp_path):
    sandbox = DisposableSandbox.create_test_fixture(tmp_path / "sandbox")
    (sandbox.root / MARKER_NAME).unlink()
    result = DisposableFilesystemExecutor(sandbox).execute(_cleanup_option())
    assert result.success is False
    assert result.failure_reason_code == "unsafe_sandbox_root"


def test_executor_rejects_missing_sandbox(tmp_path):
    sandbox = DisposableSandbox.create_test_fixture(tmp_path / "sandbox")
    (sandbox.root / MARKER_NAME).unlink()
    sandbox.root.rmdir()
    result = DisposableFilesystemExecutor(sandbox).execute(_cleanup_option())
    assert result.success is False
    assert result.failure_reason_code == "unsafe_sandbox_root"


def test_legitimate_disposable_sandbox_executes(tmp_path):
    sandbox = DisposableSandbox.create_test_fixture(tmp_path / "sandbox")
    logs = sandbox.resolve_child("logs")
    logs.mkdir()
    rotated = logs / "service.1.rotated"
    rotated.write_text("synthetic", encoding="utf-8")
    result = DisposableFilesystemExecutor(sandbox).execute(_cleanup_option())
    assert result.success is True
    assert result.deleted_count == 1
    assert not rotated.exists()
