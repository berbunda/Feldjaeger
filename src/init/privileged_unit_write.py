"""Fixed stdin-only privileged unit writer; no third-party packages."""
import os
import secrets
import stat
import sys


def write_unit(target, marker, size):
    if os.geteuid() != 0 or size > 1024 * 1024 or size < 0:
        raise ValueError("invalid writer context")
    # sudo -S may consume the password line, or leave it in stdin when cached /
    # NOPASSWD. Accept the unpredictable marker in either of the first two lines.
    stream = sys.stdin.buffer
    for _ in range(2):
        if stream.readline(4096) == marker.encode("ascii") + b"\n":
            break
    else:
        raise ValueError("invalid input frame")
    contents = stream.read(size + 1)
    if len(contents) != size:
        raise ValueError("invalid input size")
    parts = target.split("/")
    if parts[0] or any(part in ("", ".", "..") for part in parts[1:]):
        raise ValueError("invalid path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open("/", flags)
    stage = None
    stage_fd = None
    try:
        for component in parts[1:-1] + [None]:
            metadata = os.fstat(parent)
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise ValueError("untrusted unit directory")
            if component is not None:
                child = os.open(component, flags, dir_fd=parent)
                os.close(parent)
                parent = child
        for _ in range(8):
            candidate = ".feldjaeger-unit-" + secrets.token_hex(16)
            try:
                os.mkdir(candidate, 0o700, dir_fd=parent)
                stage = candidate
                break
            except FileExistsError:
                continue
        if stage is None:
            raise ValueError("cannot create staging directory")
        stage_fd = os.open(stage, flags, dir_fd=parent)
        metadata = os.fstat(stage_fd)
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise ValueError("unsafe staging directory")
        fd = os.open("contents", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=stage_fd)
        with os.fdopen(fd, "wb") as output:
            output.write(contents)
            output.flush()
            os.fchmod(output.fileno(), 0o644)
            os.fsync(output.fileno())
        try:
            current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None and not stat.S_ISREG(current.st_mode):
            raise ValueError("refusing non-regular unit target")
        os.replace("contents", parts[-1], src_dir_fd=stage_fd, dst_dir_fd=parent)
    finally:
        if stage_fd is not None:
            try:
                os.unlink("contents", dir_fd=stage_fd)
            except FileNotFoundError:
                pass
            os.close(stage_fd)
        if stage is not None:
            os.rmdir(stage, dir_fd=parent)
        os.close(parent)


if __name__ == "__main__":
    try:
        write_unit(sys.argv[1], sys.argv[2], int(sys.argv[3]))
    except Exception:
        # No arbitrary exception / input text: unit bodies and credentials are private.
        print("privileged unit write failed; verify target before retrying", file=sys.stderr)
        sys.exit(1)
