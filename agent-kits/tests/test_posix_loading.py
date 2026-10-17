"""Run only as root on POSIX. Creates/removes its own synthetic /root fixture only."""
import os,shutil,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));import kit_loader as K
@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()==0,'requires actual POSIX root ownership/modes')
class PosixLoading(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='awema-kit-fixture-',dir='/root');self.root=Path(self.temp.name);self.bundle=self.root/'kits';shutil.copytree(ROOT/'bundle',self.bundle)
  for p in [self.bundle,*self.bundle.rglob('*')]:os.chmod(p,0o755 if p.is_dir() else 0o444)
  self.pin=K.sha((self.bundle/'catalog.json').read_bytes())
 def tearDown(self):self.temp.cleanup()
 def test_actual_root_loading_and_umask027_staging(self):
  kit=K.load_role_kit(self.bundle,self.pin,'designer');old=os.umask(0o027)
  try:snapshot=K.stage_role_kit(kit,self.root/'snapshot')
  finally:os.umask(old)
  for p in [self.root/'snapshot',*(self.root/'snapshot').rglob('*')]:self.assertEqual(p.stat().st_mode&0o777,0o755 if p.is_dir() else 0o444)
  self.assertEqual(K.verify_staged_kit(kit,self.root/'snapshot'),snapshot)
 def test_group_writable_source_and_symlink_refused(self):
  p=self.bundle/'common/METHOD.md';os.chmod(p,0o666)
  with self.assertRaisesRegex(K.KitError,'path_protection'):K.load_role_kit(self.bundle,self.pin,'dev')
  os.chmod(p,0o444);other=self.root/'own-fixture.txt';other.write_text('not a credential');p.unlink();p.symlink_to(other)
  with self.assertRaisesRegex(K.KitError,'path_protection'):K.load_role_kit(self.bundle,self.pin,'dev')
 def test_snapshot_tamper_extra_symlink_and_no_overwrite(self):
  kit=K.load_role_kit(self.bundle,self.pin,'dev');dest=self.root/'snapshot';K.stage_role_kit(kit,dest)
  with self.assertRaises(FileExistsError):K.stage_role_kit(kit,dest)
  extra=dest/'unexpected';extra.symlink_to(dest/'common',target_is_directory=True)
  with self.assertRaisesRegex(K.KitError,'snapshot_symlink'):K.verify_staged_kit(kit,dest)
  extra.unlink();p=dest/'roles/dev/METHOD.md';os.chmod(p,0o644);p.write_text('changed');os.chmod(p,0o444)
  with self.assertRaisesRegex(K.KitError,'snapshot_changed'):K.verify_staged_kit(kit,dest)
if __name__=='__main__':unittest.main(verbosity=2)
