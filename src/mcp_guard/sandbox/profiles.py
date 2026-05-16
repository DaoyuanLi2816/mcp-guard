"""Sandbox profiles. Each profile maps to a set of Docker run flags."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    network: str = "none"  # docker --network value
    read_only_rootfs: bool = True
    drop_caps: bool = True
    no_new_privileges: bool = True
    pids_limit: int = 256
    memory_limit: str = "512m"
    cpu_limit: str = "1.0"
    timeout_seconds: int = 60
    extra_security_opts: tuple[str, ...] = ()
    tmpfs_paths: tuple[str, ...] = ("/tmp", "/run")
    extra_mounts: tuple[str, ...] = field(default_factory=tuple)
    additional_capabilities: tuple[str, ...] = ()
    allow_writes: bool = False


PROFILES: dict[str, Profile] = {
    "strict": Profile(
        name="strict",
        description=(
            "No network, read-only rootfs, all caps dropped, no-new-privileges, "
            "memory/CPU/pids limits, /tmp tmpfs."
        ),
    ),
    "filesystem-readonly": Profile(
        name="filesystem-readonly",
        description="Read-only rootfs but with the default Docker bridge network.",
        network="bridge",
    ),
    "network-deny": Profile(
        name="network-deny",
        description="Network disabled; writes to rootfs allowed.",
        read_only_rootfs=False,
        allow_writes=True,
    ),
    "dev": Profile(
        name="dev",
        description=(
            "Loose profile for local development: bridge network, writable rootfs, "
            "no-new-privileges still on. Not for untrusted servers."
        ),
        network="bridge",
        read_only_rootfs=False,
        drop_caps=False,
        allow_writes=True,
    ),
}


def get_profile(name: str) -> Profile:
    try:
        return PROFILES[name]
    except KeyError as e:
        raise KeyError(
            f"Unknown profile '{name}'. Available: {sorted(PROFILES)}"
        ) from e
