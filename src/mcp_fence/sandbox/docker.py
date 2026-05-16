"""Build and (optionally) execute Docker sandbox commands."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path

from ..mcp.inventory import ServerSpec
from ..models import SandboxPlan
from ..utils.logging import get_logger
from .profiles import Profile, get_profile

log = get_logger()


def docker_available() -> bool:
    return shutil.which("docker") is not None


def _quote_argv(argv: list[str]) -> str:
    # shlex.join is POSIX-safe; on Windows we still print the POSIX form because
    # `docker run` parses it the same way.
    return shlex.join(argv)


def _resolve_mount_dir(spec: ServerSpec) -> Path:
    if spec.cwd and spec.cwd.exists():
        return spec.cwd
    if spec.argv:
        for token in spec.argv:
            p = Path(token)
            if p.is_absolute() and p.exists():
                return p.parent
            cand = Path.cwd() / token
            if cand.exists():
                return cand.parent
    return Path.cwd()


def build_plan(
    spec: ServerSpec,
    *,
    profile_name: str = "strict",
    image: str = "python:3.12-slim",
) -> SandboxPlan:
    """Construct a SandboxPlan for *spec* using *profile_name*."""
    profile: Profile = get_profile(profile_name)
    notes: list[str] = []
    if not spec.argv:
        raise ValueError("Sandbox requires a stdio command/argv to wrap")

    workdir = "/app"
    host_dir = _resolve_mount_dir(spec).resolve()
    docker_argv: list[str] = ["docker", "run", "--rm", "-i"]

    docker_argv += ["--network", profile.network]
    if profile.read_only_rootfs:
        docker_argv += ["--read-only"]
        notes.append("rootfs mounted read-only")
    else:
        notes.append(f"rootfs writable ({profile.name})")
    if profile.drop_caps:
        docker_argv += ["--cap-drop", "ALL"]
        notes.append("all Linux capabilities dropped")
    for cap in profile.additional_capabilities:
        docker_argv += ["--cap-add", cap]
    if profile.no_new_privileges:
        docker_argv += ["--security-opt", "no-new-privileges"]
    for opt in profile.extra_security_opts:
        docker_argv += ["--security-opt", opt]
    if profile.pids_limit:
        docker_argv += ["--pids-limit", str(profile.pids_limit)]
    if profile.memory_limit:
        docker_argv += ["--memory", profile.memory_limit]
        docker_argv += ["--memory-swap", profile.memory_limit]
    if profile.cpu_limit:
        docker_argv += ["--cpus", profile.cpu_limit]
    for tmp in profile.tmpfs_paths:
        docker_argv += ["--tmpfs", f"{tmp}:rw,noexec,nosuid,nodev,size=64m"]
    for mnt in profile.extra_mounts:
        docker_argv += ["-v", mnt]

    docker_argv += ["-v", f"{host_dir}:{workdir}:ro"]
    docker_argv += ["-w", workdir]
    docker_argv += ["-e", "PYTHONUNBUFFERED=1", "-e", "PYTHONIOENCODING=utf-8"]
    docker_argv += [image]

    # Try to relativise the script path so it makes sense inside the
    # container's bind-mount.
    container_argv: list[str] = []
    for tok in spec.argv:
        try:
            p = Path(tok)
            if p.is_absolute() and p.exists():
                try:
                    rel = p.resolve().relative_to(host_dir)
                    container_argv.append(f"{workdir}/{rel.as_posix()}")
                    continue
                except ValueError:
                    pass
            cand = (Path.cwd() / tok).resolve()
            if cand.exists() and cand.is_relative_to(host_dir):
                rel = cand.relative_to(host_dir)
                container_argv.append(f"{workdir}/{rel.as_posix()}")
                continue
        except (OSError, ValueError):
            pass
        container_argv.append(tok)

    docker_argv += container_argv

    compose_fragment = _compose_fragment(spec, profile, image, host_dir, workdir, container_argv)

    return SandboxPlan(
        target=spec.source,
        profile=profile_name,
        image=image,
        command_args=container_argv,
        docker_argv=docker_argv,
        docker_command=_quote_argv(docker_argv),
        compose_fragment=compose_fragment,
        notes=notes,
        docker_available=docker_available(),
    )


def _compose_fragment(
    spec: ServerSpec,
    profile: Profile,
    image: str,
    host_dir: Path,
    workdir: str,
    container_argv: list[str],
) -> str:
    lines: list[str] = []
    lines.append("services:")
    lines.append(f"  {spec.name or 'mcp-server'}:")
    lines.append(f"    image: {image}")
    lines.append(f"    network_mode: {'none' if profile.network == 'none' else 'bridge'}")
    if profile.read_only_rootfs:
        lines.append("    read_only: true")
    lines.append(f"    pids_limit: {profile.pids_limit}")
    lines.append(f"    mem_limit: {profile.memory_limit}")
    lines.append(f"    cpus: '{profile.cpu_limit}'")
    lines.append("    cap_drop:")
    if profile.drop_caps:
        lines.append("      - ALL")
    for cap in profile.additional_capabilities:
        lines.append(f"    cap_add:\n      - {cap}")
    lines.append("    security_opt:")
    if profile.no_new_privileges:
        lines.append("      - no-new-privileges:true")
    for opt in profile.extra_security_opts:
        lines.append(f"      - {opt}")
    lines.append("    tmpfs:")
    for tmp in profile.tmpfs_paths:
        lines.append(f"      - {tmp}:rw,noexec,nosuid,nodev,size=64m")
    lines.append("    volumes:")
    lines.append(f"      - {host_dir}:{workdir}:ro")
    lines.append(f"    working_dir: {workdir}")
    lines.append("    stdin_open: true")
    lines.append("    command:")
    for tok in container_argv:
        lines.append(f"      - {shlex.quote(tok)}")
    return "\n".join(lines) + "\n"


def execute_plan(plan: SandboxPlan, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
    """Run the prepared docker command. Returns the completed process.

    Honors :data:`Profile.timeout_seconds` if you don't pass an explicit timeout.
    """
    if not plan.docker_available:
        raise RuntimeError(
            "Docker is not available on this host. Install Docker (https://docs.docker.com/"
            "engine/install/) and re-run, or use --dry-run to print the command."
        )
    log.info("running %s", plan.docker_command)
    return subprocess.run(
        plan.docker_argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env={**os.environ},
    )
