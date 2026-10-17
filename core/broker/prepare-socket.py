"""Systemd pre-start: refuse live/foreign sockets; remove only stale root socket."""
import errno,os,socket,stat
from pathlib import Path
p=Path('/opt/awema-ai/core/data/broker/ops.sock')
if p.exists() or p.is_symlink():
 s=p.lstat()
 if s.st_uid!=0 or not stat.S_ISSOCK(s.st_mode):raise PermissionError('unexpected broker socket')
 with socket.socket(socket.AF_UNIX) as probe:
  probe.settimeout(1)
  try:probe.connect(str(p))
  except OSError as e:
   if e.errno not in [errno.ECONNREFUSED,errno.ENOENT]:raise
  else:raise RuntimeError('broker socket already listening')
 now=p.lstat()
 if (s.st_dev,s.st_ino)!=(now.st_dev,now.st_ino):raise RuntimeError('socket changed')
 p.unlink()
