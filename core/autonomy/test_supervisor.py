import unittest,tempfile,json,fcntl,subprocess
from pathlib import Path
from unittest.mock import patch
import supervisor
from supervisor import decide,command,AUTHOR

class Gates(unittest.TestCase):
 def setUp(self):self.rows=[{'board':'awema-migration','id':'t_12345678','block':'needs_input','failures':0}]
 def test_no_work_no_model(self):self.assertEqual(decide([],0,{},'day')[0],'no_blockers')
 def test_active_work_blocks_new_queue(self):self.assertEqual(decide(self.rows,1,{},'day')[0],'work_in_progress')
 def test_duplicate_observation_is_silent(self):
  _,h=decide(self.rows,0,{},'day');self.assertEqual(decide(self.rows,0,{'seen':[h]},'nextday')[0],'unchanged')
 def test_daily_attempt_budget(self):self.assertEqual(decide(self.rows,0,{'day':'day','attempts':1},'day')[0],'daily_limit')
 def test_changed_source_can_prepare_later(self):self.assertEqual(decide(self.rows,0,{'day':'before','attempts':1},'day')[0],'prepare')
 def test_closed_command_scope(self):
  c=command(self.rows,'a'*64);self.assertIn('local-only',c);self.assertIn('dir:/workspace',c);self.assertIn(AUTHOR,c);self.assertEqual(c[c.index('--max-retries')+1],'1');self.assertNotIn('--goal',c)
 def test_pause_before_observation(self):
  with tempfile.TemporaryDirectory() as d,patch.object(supervisor,'ROOT',Path(d)),patch.object(supervisor,'snapshot') as observe:
   (Path(d)/'PAUSE').touch();supervisor.main();observe.assert_not_called()
 def test_pause_during_observation(self):
  with tempfile.TemporaryDirectory() as d,patch.object(supervisor,'ROOT',Path(d)),patch.object(supervisor.subprocess,'run') as run:
   def observe():(Path(d)/'PAUSE').touch();return self.rows,0
   with patch.object(supervisor,'snapshot',side_effect=observe):supervisor.main()
   run.assert_not_called()
 def test_exclusive_lock(self):
  with tempfile.TemporaryDirectory() as d,patch.object(supervisor,'ROOT',Path(d)),patch.object(supervisor,'snapshot') as observe:
   with (Path(d)/'lock').open('a') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);supervisor.main();observe.assert_not_called()
 def test_timeout_consumes_budget(self):
  with tempfile.TemporaryDirectory() as d,patch.object(supervisor,'ROOT',Path(d)),patch.object(supervisor,'snapshot',return_value=(self.rows,0)),patch.object(supervisor,'export_sources'),patch.object(supervisor.subprocess,'run',side_effect=subprocess.TimeoutExpired('fixture',1)):
   with self.assertRaises(subprocess.TimeoutExpired):supervisor.main()
   self.assertEqual(json.loads((Path(d)/'state.json').read_text())['attempts'],1)
 def test_success_not_repeated(self):
  with tempfile.TemporaryDirectory() as d,patch.object(supervisor,'ROOT',Path(d)),patch.object(supervisor,'snapshot',return_value=(self.rows,0)),patch.object(supervisor,'export_sources'),patch.object(supervisor.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'{"id":"t_12345678"}','')) as run:
   supervisor.main();supervisor.main();self.assertEqual(run.call_count,1)
   self.assertFalse((Path(d)/'state.tmp').exists())
 def test_source_export_rejects_unscoped_reference(self):
  with patch.object(supervisor.subprocess,'run') as run:
   for rows in [[{'board':'other','id':'t_12345678'}],[{'board':'awema-migration','id':'../secret'}]]:
    with self.assertRaises(ValueError):supervisor.export_sources(rows)
   run.assert_not_called()
 def test_source_export_has_fixed_unprivileged_transport(self):
  with patch.object(supervisor.subprocess,'run') as run:supervisor.export_sources(self.rows)
  args=run.call_args.args[0]
  self.assertEqual(args[args.index('--user')+1],'10000:10000');self.assertIn('-I',args)
  self.assertEqual(json.loads(args[-1]),self.rows);self.assertTrue(run.call_args.kwargs['check'])
 def test_failed_export_cannot_queue_model(self):
  with tempfile.TemporaryDirectory() as d,patch.object(supervisor,'ROOT',Path(d)),patch.object(supervisor,'snapshot',return_value=(self.rows,0)),patch.object(supervisor,'export_sources',side_effect=OSError('fixture')),patch.object(supervisor.subprocess,'run') as run:
   with self.assertRaises(OSError):supervisor.main()
   run.assert_not_called();self.assertEqual(json.loads((Path(d)/'state.json').read_text())['attempts'],1)
 def test_pause_during_export_prevents_queue(self):
  with tempfile.TemporaryDirectory() as d,patch.object(supervisor,'ROOT',Path(d)),patch.object(supervisor,'snapshot',return_value=(self.rows,0)),patch.object(supervisor,'export_sources',side_effect=lambda rows:(Path(d)/'PAUSE').touch()),patch.object(supervisor.subprocess,'run') as run:
   supervisor.main();run.assert_not_called()
if __name__=='__main__':unittest.main()
