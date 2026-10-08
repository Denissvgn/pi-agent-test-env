"""Descriptor-relative patches for a parent-confirmed quiescent workspace.

The caller must hold the run launch lock and confirm every managed writer stopped.
No active or uncertain-cleanup workspace is admitted. Host users/processes are
trusted; concurrent unrelated host mutation is outside that lease.
"""
import os
from pathlib import PurePosixPath
import stat
import uuid

class PatchError(RuntimeError):
    pass


def check_target(target, protected):
    p=PurePosixPath(target)
    if not target or p.is_absolute() or '..' in p.parts or '\\' in target or '\0' in target or not p.parts:
        raise PatchError('Patch target must be a relative path')
    if p.parts[0] in ('.pi-runtime','.pi-lab','.git'):
        raise PatchError('Reserved workspace path')
    normalized=p.as_posix()
    for item in protected:
        q=PurePosixPath(item).as_posix()
        if normalized==q or normalized.startswith(q+'/') or q.startswith(normalized+'/'):
            raise PatchError('Protected acceptance input: use a new configuration/trial')
    return p.parts


def directory(parent, name):
    return os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)


def same_tree(root, parts, fds):
    """Revalidate pinned ancestor inodes under the caller's exclusive writer lease."""
    current=os.dup(root)
    try:
        for index,part in enumerate(parts):
            nxt=directory(current,part);os.close(current);current=nxt
            if (os.fstat(current).st_dev,os.fstat(current).st_ino)!=(os.fstat(fds[index]).st_dev,os.fstat(fds[index]).st_ino):
                raise PatchError('Workspace ancestry changed')
    finally:os.close(current)


def check_capabilities():
    if os.name!='posix' or not hasattr(os,'O_NOFOLLOW') or not all(f in os.supports_dir_fd for f in (os.open,os.stat,os.mkdir,os.rename,os.unlink)):
        raise PatchError('Required no-follow/descriptor-relative filesystem operations unavailable')


def apply(workspace, identity, target, content, protected):
    check_capabilities()
    parts=check_target(target,protected)
    if len(content)>16*1024*1024:raise PatchError('Patch exceeds 16 MiB')
    root=os.open(workspace,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    opened=[];temp=None
    try:
        root_stat=os.fstat(root)
        if [root_stat.st_dev,root_stat.st_ino]!=identity:raise PatchError('Workspace root was replaced')
        parent=root
        for part in parts[:-1]:
            try:child=directory(parent,part)
            except FileNotFoundError:
                os.mkdir(part,0o755,dir_fd=parent);child=directory(parent,part)
            opened.append(child);parent=child
        mode=0o644
        try:
            dest=os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)
            if not stat.S_ISREG(dest.st_mode) or dest.st_nlink!=1:raise PatchError('Target must be a non-linked regular file')
            mode=stat.S_IMODE(dest.st_mode)&0o777
        except FileNotFoundError:pass
        temp='.pi-patch-'+uuid.uuid4().hex
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        with os.fdopen(fd,'wb') as f:
            f.write(content);f.flush();os.fchmod(f.fileno(),mode);os.fsync(f.fileno())
        same_tree(root,parts[:-1],opened)
        # Atomic replacement never follows a raced leaf link. Ancestor movement
        # is prevented by quiescence, not by this last inode check alone.
        os.rename(temp,parts[-1],src_dir_fd=parent,dst_dir_fd=parent)
        temp=None;os.fsync(parent)
    except OSError as exc:
        raise PatchError(f'Unsafe or unsupported patch path: {exc}') from exc
    finally:
        if temp:
            try:os.unlink(temp,dir_fd=opened[-1] if opened else root)
            except FileNotFoundError:pass
        for fd in reversed(opened):os.close(fd)
        os.close(root)


def preflight(workspace,identity,target,protected):
    check_capabilities()
    parts=check_target(target,protected)
    root=os.open(workspace,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);current=root
    try:
        st=os.fstat(root)
        if [st.st_dev,st.st_ino]!=identity:raise PatchError('Workspace root was replaced')
        for part in parts[:-1]:
            try:child=directory(current,part)
            except FileNotFoundError:return
            if current!=root:os.close(current)
            current=child
        try:
            leaf=os.stat(parts[-1],dir_fd=current,follow_symlinks=False)
            if not stat.S_ISREG(leaf.st_mode) or leaf.st_nlink!=1:raise PatchError('Unsafe patch leaf')
        except FileNotFoundError:pass
    finally:
        if current!=root:os.close(current)
        os.close(root)
