from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import shlex
import shutil
import signal
from typing import Sequence


@dataclass(slots=True)
class ProcessResult:
    program: str
    args: list[str]
    exit_code: int
    stdout: bytes
    stderr: bytes
    started_at: str
    finished_at: str
    timed_out: bool = False
    dry_run: bool = False
    output_truncated: bool = False

    @property
    def command_display(self) -> str:
        return shlex.join([self.program, *self.args])


class _OutputLimitExceeded(Exception):
    pass


async def _bounded_read(stream: asyncio.StreamReader, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > max_bytes:
            raise _OutputLimitExceeded("scanner output exceeded the configured limit")
        chunks.append(chunk)


class SafeProcessRunner:
    """Run local scanner binaries without a shell and with bounded resource usage.

    On Linux/macOS, subprocesses are placed into their own session to stop
    descendants when a timeout/cancellation/output limit occurs. This is not
    an OS sandbox; scanner binaries should still be installed from trusted sources.
    """

    async def execute(
        self, program: str, args: Sequence[str], *, timeout: int = 300,
        cwd: str | Path | None = None, stdin: bytes | None = None,
        dry_run: bool = False, max_output_bytes: int = 32 * 1024 * 1024,
    ) -> ProcessResult:
        if timeout <= 0 or max_output_bytes <= 0:
            raise ValueError("timeout and max_output_bytes must be positive")
        resolved = shutil.which(program)
        if not resolved:
            raise FileNotFoundError(f"required executable not found: {program}")
        args = [str(a) for a in args]
        if any("\x00" in a for a in [program, *args]):
            raise ValueError("NUL byte in executable or process argument")
        started = datetime.now(timezone.utc).isoformat()
        if dry_run:
            return ProcessResult(resolved, args, 0, b"", b"", started, datetime.now(timezone.utc).isoformat(), dry_run=True)

        proc = await asyncio.create_subprocess_exec(
            resolved, *args,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            start_new_session=(os.name == "posix"),
        )
        timed_out = False
        truncated = False
        stdout, stderr = b"", b""

        async def collect() -> tuple[bytes, bytes]:
            async def feed_stdin():
                if proc.stdin is not None:
                    try:
                        proc.stdin.write(stdin or b"")
                        await proc.stdin.drain()
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    finally:
                        proc.stdin.close()
            feeding = asyncio.create_task(feed_stdin())
            try:
                # Each output stream is limited independently. A child that
                # produces excessive output is terminated instead of growing RAM.
                result = await asyncio.gather(
                    _bounded_read(proc.stdout, max_output_bytes),
                    _bounded_read(proc.stderr, max_output_bytes),
                )
                await proc.wait()
                return result[0], result[1]
            finally:
                feeding.cancel()
                await asyncio.gather(feeding, return_exceptions=True)

        def kill_tree() -> None:
            if proc.returncode is not None:
                return
            try:
                if os.name == "posix":
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
                    proc.kill()
            except ProcessLookupError:
                pass

        try:
            stdout, stderr = await asyncio.wait_for(collect(), timeout=timeout)
        except asyncio.TimeoutError:
            timed_out = True
            kill_tree()
            await proc.wait()
        except _OutputLimitExceeded:
            truncated = True
            kill_tree()
            await proc.wait()
        except asyncio.CancelledError:
            kill_tree()
            await proc.wait()
            raise
        return ProcessResult(
            resolved, args,
            proc.returncode if proc.returncode is not None else -1,
            stdout, stderr, started, datetime.now(timezone.utc).isoformat(),
            timed_out=timed_out, output_truncated=truncated,
        )
