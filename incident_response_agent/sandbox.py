from __future__ import annotations

import os
import secrets
import tempfile
from pathlib import Path


MARKER_NAME = ".incident-agent-sandbox"


class SandboxViolation(ValueError):
    pass


def _contains_symlink(path: Path) -> bool:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if current.exists() and current.is_symlink():
            return True
    return False


class DisposableSandbox:
    """An owned capability for a disposable execution directory."""

    def __init__(self, root: Path, marker_token: str, temporary_directory: tempfile.TemporaryDirectory[str] | None = None):
        self.root = root
        self._marker_token = marker_token
        self._temporary_directory = temporary_directory
        self.validate()

    @classmethod
    def create_runtime(cls) -> "DisposableSandbox":
        parent = Path(tempfile.gettempdir()).resolve()
        temporary_directory = tempfile.TemporaryDirectory(prefix="incident-agent-", dir=parent)
        root = Path(temporary_directory.name).resolve()
        root.chmod(0o700)
        token = secrets.token_hex(32)
        marker = root / MARKER_NAME
        marker.write_text(token, encoding="utf-8")
        marker.chmod(0o600)
        return cls(root, token, temporary_directory)

    @classmethod
    def create_test_fixture(cls, path: str | Path) -> "DisposableSandbox":
        requested = Path(path)
        if ".." in requested.parts:
            raise SandboxViolation("sandbox path traversal is not allowed")
        absolute = requested.absolute()
        if _contains_symlink(absolute):
            raise SandboxViolation("sandbox path may not contain symlinks")
        resolved = absolute.resolve()
        cls._reject_unsafe_root(resolved)
        if resolved.exists():
            if not resolved.is_dir() or any(resolved.iterdir()):
                raise SandboxViolation("test sandbox must be an empty directory")
        else:
            resolved.mkdir(parents=False, mode=0o700)
        resolved.chmod(0o700)
        token = secrets.token_hex(32)
        marker = resolved / MARKER_NAME
        marker.write_text(token, encoding="utf-8")
        marker.chmod(0o600)
        return cls(resolved, token)

    @staticmethod
    def _reject_unsafe_root(root: Path) -> None:
        disallowed = {
            Path("/").resolve(),
            Path(tempfile.gettempdir()).resolve(),
            Path.home().resolve(),
            Path.cwd().resolve(),
            Path(__file__).resolve().parents[1],
        }
        if root in disallowed or root.parent == root:
            raise SandboxViolation("sandbox root is not disposable")

    def validate(self) -> None:
        self._reject_unsafe_root(self.root)
        if not self.root.exists() or not self.root.is_dir() or self.root.is_symlink():
            raise SandboxViolation("sandbox root is missing or invalid")
        if self.root.resolve() != self.root or _contains_symlink(self.root):
            raise SandboxViolation("sandbox root may not contain symlinks")
        if hasattr(os, "geteuid") and self.root.stat().st_uid != os.geteuid():
            raise SandboxViolation("sandbox root is not owned by the current process user")
        marker = self.root / MARKER_NAME
        if not marker.is_file() or marker.is_symlink() or marker.read_text(encoding="utf-8") != self._marker_token:
            raise SandboxViolation("sandbox ownership marker is missing or invalid")

    def resolve_child(self, relative: str | Path) -> Path:
        self.validate()
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise SandboxViolation("sandbox child path traversal is not allowed")
        candidate = self.root / relative_path
        if _contains_symlink(candidate.absolute()):
            raise SandboxViolation("sandbox child path may not contain symlinks")
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise SandboxViolation("sandbox child escaped root") from exc
        return resolved

    def close(self) -> None:
        if self._temporary_directory is not None:
            self._temporary_directory.cleanup()
            self._temporary_directory = None
