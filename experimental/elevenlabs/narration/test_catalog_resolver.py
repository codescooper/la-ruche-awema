"""SQLite fixtures + actual viewer_v2.Catalog; no network/production access."""
import hashlib
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import socketserver
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"baseline"/"source"))
# Windows lacks UnixStreamServer. The legacy module merely defines its server
# subclass on import; substitute the unused class base for this offline test.
# No server/listener/authenticate function is instantiated or called.
with patch.object(socketserver,"UnixStreamServer",getattr(socketserver,"UnixStreamServer",socketserver.TCPServer),create=True):
    from viewer_v2 import Catalog
from catalog_resolver import CatalogResolver, SessionIdentity
import narration as n

MID="f_"+"a"*24
OTHER="f_"+"b"*24
SESSION=SessionIdentity("owner-01","owner","a"*64)
SQL="""
CREATE TABLE meta(id INTEGER PRIMARY KEY,schema TEXT,observed_at REAL);
CREATE TABLE missions(id TEXT PRIMARY KEY,owner_id TEXT,objective_sanitized TEXT,state TEXT,created REAL,updated REAL,event_count INTEGER,artifact_count INTEGER);
CREATE TABLE events(mission_id TEXT,id INTEGER,agent TEXT,kind TEXT,summary TEXT,created REAL,source_event_sha256 TEXT,PRIMARY KEY(mission_id,id));
"""

class ResolverTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="awema-narration-catalog-")
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/"projection.sqlite"
        self.now=time.time();self.current=SESSION;self.opens=0;self.mission_reads=0
        with closing(sqlite3.connect(self.path)) as c, c:
            c.executescript(SQL)
            c.execute("INSERT INTO meta VALUES(1,?,?)",("awema-agent-standup-catalog-v2",self.now))
            c.executemany("INSERT INTO missions VALUES(?,?,?,?,?,?,?,?)",[(MID,"director-01","Mission A","review",self.now-50,self.now-5,1,0),(OTHER,"other-director","Mission B","review",self.now-50,self.now-5,1,0)])
            for mid in (MID,OTHER):
                c.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?)",(mid,52,"qa","qa_completed","TEXTE NON FIABLE À NE JAMAIS REPRENDRE",self.now-5,hashlib.sha256(b"qa_completed").hexdigest()))
        self.permissions()
        self.resolver=self.make()

    def permissions(self):
        if os.name=="posix":
            if os.geteuid()!=0:
                self.skipTest("Actual Catalog fixture requires operator-owned POSIX file")
            os.chown(self.path,0,10001);os.chmod(self.path,0o640)

    def factory(self,user):
        self.opens+=1
        parent=self
        class ObservedCatalog(Catalog):
            def mission(inner,mid=None):
                parent.mission_reads+=1
                return super().mission(mid)
        return ObservedCatalog(user,path=self.path)

    def make(self,session=SESSION,**kwargs):
        return CatalogResolver(session,reauthenticate=kwargs.get("reauthenticate",lambda:self.current),catalog_factory=kwargs.get("catalog_factory",self.factory),clock=kwargs.get("clock",lambda:self.now))

    def modify(self,sql,params=()):
        with closing(sqlite3.connect(self.path)) as c, c:c.execute(sql,params)
        self.permissions()

    def auth(self,mid=MID):
        return self.resolver.authorize(self.current.user,mid)

    def project(self):
        return n.project_event(self.current.user,MID,52,self.resolver)

    def bad(self,call,code):
        with self.assertRaisesRegex(n.NarrationError,"^"+code+"$"):call()

    def test_real_catalog_sqlite_read_only_projection(self):
        before=self.path.read_bytes()
        out=self.project()
        self.assertEqual(self.path.read_bytes(),before)
        self.assertEqual(out["voice_role"],"system")
        self.assertEqual(out["step_role"],"qa")
        self.assertIn("reste à relire",out["text"])
        self.assertEqual(out["provenance"]["source_event_digest_scope"],"event_code_only")

    def test_no_summary_text_in_output(self):
        self.assertNotIn("NON FIABLE",self.project()["text"])

    def test_owner_can_see_all_catalog_missions(self):
        auth=self.auth(OTHER)
        self.assertTrue(auth.allowed)
        self.assertEqual(self.resolver.resolve_event(auth,OTHER,52).binding.mission_id,OTHER)

    def test_director_only_own_mission(self):
        self.current=SessionIdentity("director-01","director","b"*64)
        self.resolver=self.make(self.current)
        self.assertTrue(self.auth().allowed)
        self.bad(lambda:self.auth(OTHER),"catalog_unavailable")

    def test_wrong_caller_no_catalog_access(self):
        auth=self.resolver.authorize("unrelated-user",MID)
        self.assertFalse(auth.allowed);self.assertEqual(self.opens,0)

    def test_missing_server_generation_rejected(self):
        self.bad(lambda:self.make(replace(SESSION,generation="")),"session_identity_incomplete")

    def test_client_dictionary_not_authenticated_identity(self):
        self.bad(lambda:self.make({"user":"owner-01","role":"owner","generation":"a"*64}),"session_identity_incomplete")

    def test_generation_must_be_opaque_server_tag(self):
        for generation in (1,True,"client-value","g"*64):
            with self.subTest(generation=generation):
                self.bad(lambda:self.make(replace(SESSION,generation=generation)),"session_identity_incomplete")

    def test_mandatory_reauthentication_callback(self):
        self.bad(lambda:CatalogResolver(SESSION,reauthenticate=None,catalog_factory=self.factory),"session_revalidation_required")

    def test_scope_stable_and_separates_missions(self):
        first=self.auth();second=self.auth()
        self.assertEqual(first.scope_id,second.scope_id)
        self.assertRegex(first.scope_id,r"^[a-f0-9]{64}$")
        self.assertNotEqual(first.scope_id,self.auth(OTHER).scope_id)
        self.assertNotIn(SESSION.user,first.scope_id)

    def test_relogin_new_server_generation_reuses_stable_scope(self):
        first=self.auth();self.current=replace(SESSION,generation="c"*64)
        resolver=self.make(self.current)
        self.assertEqual(first.scope_id,resolver.authorize(self.current.user,MID).scope_id)

    def test_acl_policy_revision_separates_cache_scope(self):
        first=self.auth();self.current=replace(SESSION,acl_policy_version="owner-director-ownmission-v2")
        resolver=self.make(self.current)
        self.assertNotEqual(first.scope_id,resolver.authorize(self.current.user,MID).scope_id)

    def test_acl_revision_change_denies_old_identity(self):
        self.current=replace(SESSION,acl_policy_version="owner-director-ownmission-v2")
        self.bad(self.auth,"session_changed")

    def test_old_generation_denied(self):
        self.current=replace(SESSION,generation="c"*64)
        self.bad(self.auth,"session_changed")

    def test_revoked_session_denied(self):
        self.current=replace(SESSION,active=False)
        self.bad(self.auth,"session_not_authorized")

    def test_role_change_denies_old_resolver(self):
        self.current=replace(SESSION,role="director")
        self.bad(self.auth,"session_changed")

    def test_current_auth_failure_hides_details(self):
        def fail():raise RuntimeError("do-not-echo-secret")
        resolver=self.make(reauthenticate=fail)
        self.bad(lambda:resolver.authorize(SESSION.user,MID),"session_not_authorized")

    def test_acl_checked_before_after_and_fresh_snapshot(self):
        self.auth()
        self.assertEqual(self.opens,2)
        self.assertEqual(self.mission_reads,3)

    def test_revoke_between_source_and_post_check(self):
        calls=0
        def refresh():
            nonlocal calls
            calls+=1
            return SESSION if calls==1 else replace(SESSION,active=False)
        resolver=self.make(reauthenticate=refresh)
        self.bad(lambda:resolver.authorize(SESSION.user,MID),"session_not_authorized")

    def test_owner_change_detected_in_new_projection_after_read(self):
        self.current=SessionIdentity("director-01","director","b"*64)
        opens=0
        def factory(user):
            nonlocal opens
            opens+=1
            if opens==2:self.modify("UPDATE missions SET owner_id='other-user' WHERE id=?",(MID,))
            return self.factory(user)
        resolver=self.make(self.current,catalog_factory=factory)
        self.bad(lambda:resolver.authorize(self.current.user,MID),"catalog_unavailable")

    def test_stale_projection_fail_closed(self):
        self.modify("UPDATE meta SET observed_at=?",(self.now-11,))
        self.bad(self.auth,"catalog_unavailable")

    def test_becomes_stale_before_post_check(self):
        calls=0
        def clock():
            nonlocal calls
            calls+=1
            return self.now if calls==1 else self.now+11
        resolver=self.make(clock=clock)
        self.bad(lambda:resolver.authorize(SESSION.user,MID),"projection_stale")

    def test_missing_mission_no_event_lookup(self):
        self.bad(lambda:self.resolver.authorize(SESSION.user,"f_"+"c"*24),"catalog_unavailable")

    def test_event_id_must_match_mission(self):
        self.modify("DELETE FROM events WHERE mission_id=?",(MID,))
        auth=self.auth()
        self.bad(lambda:self.resolver.resolve_event(auth,MID,52),"event_missing")

    def test_unrelated_authorization_rejected(self):
        auth=self.auth(OTHER)
        self.bad(lambda:self.resolver.resolve_event(auth,MID,52),"access_denied")

    def test_scope_cannot_be_client_supplied(self):
        auth=replace(self.auth(),scope_id="f"*64)
        self.bad(lambda:self.resolver.resolve_event(auth,MID,52),"access_denied")

    def test_event_role_code_agent_mismatch(self):
        self.modify("UPDATE events SET agent='dev' WHERE mission_id=?",(MID,))
        auth=self.auth()
        self.bad(lambda:self.resolver.resolve_event(auth,MID,52),"event_role_mismatch")

    def test_system_event_cannot_acquire_agent_voice(self):
        self.modify("UPDATE events SET kind='plan_created',source_event_sha256=? WHERE mission_id=?",(hashlib.sha256(b"plan_created").hexdigest(),MID))
        auth=self.auth()
        self.bad(lambda:self.resolver.resolve_event(auth,MID,52),"event_role_mismatch")

    def test_event_hash_mismatch(self):
        self.modify("UPDATE events SET source_event_sha256=? WHERE mission_id=?",("d"*64,MID))
        auth=self.auth()
        self.bad(lambda:self.resolver.resolve_event(auth,MID,52),"event_digest_mismatch")

    def test_unmapped_code_not_falsely_attested(self):
        self.modify("UPDATE events SET kind='unmapped' WHERE mission_id=?",(MID,))
        auth=self.auth()
        self.bad(lambda:self.resolver.resolve_event(auth,MID,52),"event_code_not_attestable")

    def test_unknown_metadata_not_invented(self):
        event=self.resolver.resolve_event(self.auth(),MID,52)
        self.assertIsNone(event.binding.ordinal)
        self.assertIsNone(event.binding.attempt)
        self.assertIsNone(event.binding.run_id)
        self.assertIsNone(event.binding.checkpoint_id)
        self.assertIsNone(event.worker_report_id)

    def test_worker_report_always_unavailable(self):
        auth=self.auth();event=self.resolver.resolve_event(auth,MID,52)
        self.bad(lambda:self.resolver.resolve_report(auth,event,"fake-report"),"worker_reports_unavailable")

    def test_only_event_evidence_supported(self):
        auth=self.auth();event=self.resolver.resolve_event(auth,MID,52)
        self.bad(lambda:self.resolver.resolve_evidence(auth,event.binding,"artifact:QA.md"),"journal_reference_required")

    def test_evidence_binding_exact(self):
        auth=self.auth();event=self.resolver.resolve_event(auth,MID,52)
        self.bad(lambda:self.resolver.resolve_evidence(auth,replace(event.binding,run_id=154),"event:52"),"evidence_binding_mismatch")

    def test_proof_recorded_never_verified(self):
        auth=self.auth();event=self.resolver.resolve_event(auth,MID,52)
        proof=self.resolver.resolve_evidence(auth,event.binding,"event:52")
        self.assertEqual(proof.level,"recorded")
        self.assertEqual(proof.sha256,event.source_event_sha256)

    def test_all_nine_roles_lifecycle_only(self):
        for role in n.ROLES:
            with self.subTest(role=role):
                kind=role+"_completed"
                self.modify("UPDATE events SET agent=?,kind=?,source_event_sha256=? WHERE mission_id=?",(role,kind,hashlib.sha256(kind.encode()).hexdigest(),MID))
                out=self.project()
                self.assertEqual(out["voice_role"],"system")
                self.assertEqual(out["step_role"],role)
                self.assertFalse(out["provenance"]["attested"])

    def test_read_transaction_required_on_factory(self):
        parent=self
        class BadCatalog(Catalog):
            def __enter__(inner):
                super().__enter__();inner.conn.rollback();return inner
        resolver=self.make(catalog_factory=lambda user:BadCatalog(user,path=parent.path))
        self.bad(lambda:resolver.authorize(SESSION.user,MID),"read_transaction_required")

    def test_query_only_required_on_factory(self):
        parent=self
        class BadCatalog(Catalog):
            def __enter__(inner):
                super().__enter__();inner.conn.execute("PRAGMA query_only=OFF");return inner
        resolver=self.make(catalog_factory=lambda user:BadCatalog(user,path=parent.path))
        self.bad(lambda:resolver.authorize(SESSION.user,MID),"query_only_required")

    def test_sql_queries_are_bound_and_malformed_ids_refused(self):
        for mid in (MID+"' OR 1=1--","../private",None):
            with self.subTest(mid=mid):
                self.bad(lambda:self.resolver.authorize(SESSION.user,mid),"mission_id_invalid")

if __name__=="__main__":unittest.main()
