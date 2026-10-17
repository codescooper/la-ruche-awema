"""Operator only. Restore preimage only if current revision is unchanged."""
from pathlib import Path
import hashlib, os
p=Path('/opt/awema-ai/data/profiles/cto/agents/security.md')
b=Path('/opt/awema-autonomy/backups/security-v2.md')
assert hashlib.sha256(p.read_bytes()).hexdigest()=='cc7147546685dfdfce81f9bf743fc6c9d1cb745550d6190e358fb1943612fd4d', 'concurrent change: stop'
assert hashlib.sha256(b.read_bytes()).hexdigest()=='eb9acd19fa4fc6e6988ccd57b468bde15dd391b27ee7986c6b4422b9a3155fd8', 'backup mismatch: stop'
st=p.stat();p.write_bytes(b.read_bytes());os.chown(p,st.st_uid,st.st_gid);os.chmod(p,st.st_mode & 0o777)
print('Previous role restored; scheduling and laboratory unchanged')
