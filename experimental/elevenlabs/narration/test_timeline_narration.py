"""Pure timeline projection tests; source/provider/DB never accessed."""
import copy
from dataclasses import replace
import hashlib
import unittest
from unittest.mock import patch
import narration as n
from test_narration import MID, OTHER, MemoryResolver
from timeline_narration import project_timeline

def packet(kind="qa_completed", agent="qa", eid=52, stamp=100000):
    return {"id":MID,"proj":"awema","ep":"awema-"+MID,
            "mission":{"id":MID,"state":"review"},
            "agents":[{"id":"main","name":"CTO","type":"main"},
                      {"id":"qa","name":"Vérification","type":"general-purpose"},
                      {"id":"journal","name":"Journal système","type":"system"}],
            "events":[{"k":"awema:"+str(eid),"source_event_id":eid,"ts":stamp,
                       "t":0,"agent":agent,"kind":"report","to":"journal",
                       "title":"TEXTE SOURCE À IGNORER","text":"FAUSSE PHRASE SOURCE",
                       "fr":"FAUSSE TRADUCTION SOURCE","awema_kind":kind,"awema_role":agent}],
            "seq":eid,"total":1,"has_more":False,"durationMs":0,
            "provenance":{"projection_sha256":"d"*64},"artifacts":[]}

class TimelineTests(unittest.TestCase):
    def setUp(self):
        self.resolver=MemoryResolver()
        self.source=packet()
    def project(self):return project_timeline("owner",self.source,self.resolver)
    def bad(self,code):
        with self.assertRaisesRegex(n.NarrationError,"^"+code+"$"):self.project()

    def test_canonical_text_voice_bubble_replay_identical(self):
        e=self.project()["events"][0];canonical=n.project_event("owner",MID,52,self.resolver)
        self.assertEqual(e["text"],canonical["text"])
        self.assertEqual(e["fr"],canonical["text"])
        for key in ("text","bubble","subtitle","audio_text","replay_text"):
            self.assertEqual(e["awema_narration"][key],canonical["text"])
        self.assertEqual(e["awema_narration"]["narration_sha256"],canonical["narration_sha256"])
    def test_system_journal_speaker_not_agent(self):
        e=self.project()["events"][0]
        self.assertEqual(e["agent"],"journal")
        self.assertEqual(e["awema_narration"]["voice_role"],"system")
        self.assertFalse(e["awema_narration"]["provenance"]["attested"])
    def test_no_upstream_done_prefix_or_order_label(self):
        e=self.project()["events"][0]
        self.assertEqual(e["kind"],"say")
        self.assertNotIn("to",e);self.assertNotIn("title",e)
        self.assertFalse(e["text"].startswith("Terminé."))
    def test_actual_role_and_code_preserved_for_state_not_speech(self):
        e=self.project()["events"][0]
        self.assertEqual(e["awema_role"],"qa");self.assertEqual(e["awema_kind"],"qa_completed")
    def test_source_freeform_summary_and_translation_not_used(self):
        out=str(self.project())
        self.assertNotIn("FAUSSE PHRASE",out);self.assertNotIn("FAUSSE TRADUCTION",out)
        self.assertNotIn("TEXTE SOURCE À IGNORER",out)
    def test_no_source_mutation(self):
        before=copy.deepcopy(self.source);self.project();self.assertEqual(before,self.source)
    def test_metadata_artifacts_pagination_preserved(self):
        self.source.update(has_more=True,total=90,artifacts=[{"name":"QA.md"}])
        out=self.project()
        self.assertTrue(out["has_more"]);self.assertEqual(out["total"],90)
        self.assertEqual(out["artifacts"],[{"name":"QA.md"}])
    def test_original_projection_hash_not_relabelled_as_new_hash(self):
        out=self.project()
        self.assertEqual(out["provenance"]["projection_sha256"],"d"*64)
        meta=out["provenance"]["narration_projection"]
        self.assertEqual(meta["events_sha256"],n.digest(out["events"]))
        self.assertEqual(meta["source_event_digest_scope"],"event_code_only")
    def test_missing_journal_profile_added_not_worker(self):
        self.source["agents"]=[a for a in self.source["agents"] if a["id"]!="journal"]
        out=self.project()
        self.assertEqual(len([a for a in out["agents"] if a["id"]=="journal"]),1)
        self.assertEqual(out["agents"][-1]["type"],"system")
    def test_duplicate_profile_rejected(self):
        self.source["agents"].append({"id":"qa"});self.bad("timeline_agents_invalid")
    def test_mission_binding_mismatch(self):
        self.source["mission"]["id"]=OTHER;self.bad("timeline_mission_mismatch")
    def test_episode_binding_mismatch(self):
        self.source["ep"]="awema-"+OTHER;self.bad("timeline_identity_invalid")
    def test_project_binding_mismatch(self):
        self.source["proj"]="unrelated";self.bad("timeline_identity_invalid")
    def test_bool_event_id_rejected(self):
        self.source["events"][0]["source_event_id"]=True;self.bad("timeline_event_identity_invalid")
    def test_key_event_id_mismatch(self):
        self.source["events"][0]["k"]="awema:53";self.bad("timeline_event_identity_invalid")
    def test_duplicate_event_rejected(self):
        self.source["events"].append(copy.deepcopy(self.source["events"][0]));self.bad("timeline_event_identity_invalid")
    def test_out_of_order_events_rejected(self):
        self.source["events"]=[dict(self.source["events"][0],source_event_id=53,k="awema:53"),self.source["events"][0]]
        self.source["seq"]=53
        # Resolver cannot bind first53; fails before any partially projected result.
        self.bad("event_binding_mismatch")
    def test_sequence_cannot_precede_event(self):
        self.source["seq"]=51;self.bad("timeline_sequence_invalid")
    def test_event_kind_source_mismatch_rejected(self):
        self.source["events"][0]["awema_kind"]="dev_completed";self.bad("timeline_event_code_mismatch")
    def test_timestamp_source_mismatch_rejected(self):
        self.source["events"][0]["ts"]+=1;self.bad("timeline_event_timestamp_mismatch")
    def test_relative_time_nonnegative(self):
        self.source["events"][0]["t"]=-1;self.bad("timeline_relative_time_invalid")
    def test_unknown_fields_cannot_inject_tools_or_end(self):
        for key in ("tools","items","end","prompt","reasoning"):
            with self.subTest(key=key):
                self.source=packet();self.source["events"][0][key]="unexpected"
                self.bad("timeline_event_fields_invalid")
    def test_source_speaker_role_spoof_is_replaced(self):
        self.source["events"][0].update(agent="dev",awema_role="dev")
        e=self.project()["events"][0]
        self.assertEqual(e["agent"],"journal");self.assertEqual(e["awema_role"],"qa")
    def test_cto_role_maps_main_for_status(self):
        self.resolver=MemoryResolver(role="cto");self.source=packet(kind="cto_completed",agent="main")
        e=self.project()["events"][0]
        self.assertEqual(e["agent"],"journal");self.assertEqual(e["awema_role"],"main")
    def test_dispatch_still_only_planned(self):
        kind="qa_dispatching";sha=hashlib.sha256(kind.encode()).hexdigest()
        self.resolver.event=replace(self.resolver.event,kind=kind,source_event_sha256=sha)
        self.resolver.proof=replace(self.resolver.proof,sha256=sha,action_state="planned")
        self.source=packet(kind=kind);self.source["events"][0].update(kind="order",to="qa")
        e=self.project()["events"][0]
        self.assertEqual(e["awema_narration"]["action_state"],"planned")
        self.assertIn("reste à confirmer",e["text"])
        self.assertEqual(e["kind"],"say")
    def test_true_worker_reports_explicitly_refused_by_current_catalog_adapter(self):
        self.resolver=MemoryResolver(True)
        self.source=packet(kind="worker_progress_reported")
        self.bad("worker_narration_not_supported_by_catalog")
    def test_authorization_failure_stops_projection(self):
        self.resolver.auth=replace(self.resolver.auth,allowed=False);self.bad("access_denied")
    def test_no_partial_projection_or_mutation_on_failure(self):
        self.source["events"].append(dict(self.source["events"][0],source_event_id=53,k="awema:53"));self.source["seq"]=53
        before=copy.deepcopy(self.source)
        self.bad("event_binding_mismatch");self.assertEqual(self.source,before)
    def test_canonical_projection_idempotent(self):
        once=self.project();twice=project_timeline("owner",once,self.resolver)
        self.assertEqual(once,twice)
    def test_empty_page_remains_valid(self):
        self.source["events"]=[];self.source["seq"]=0
        out=self.project();self.assertEqual(out["events"],[])
        self.assertEqual(out["provenance"]["narration_projection"]["event_count"],0)
    def test_empty_page_still_requires_current_authorization(self):
        self.source["events"]=[];self.source["seq"]=0
        self.resolver.auth=replace(self.resolver.auth,allowed=False)
        self.bad("access_denied")
    def test_policy_revision_cannot_mix_scopes_in_one_packet(self):
        original=self.resolver.authorize;calls=0
        def changing(caller,mission):
            nonlocal calls
            calls+=1
            auth=original(caller,mission)
            return auth if calls==1 else replace(auth,scope_id="another-policy-scope")
        self.resolver.authorize=changing
        self.bad("timeline_authorization_scope_changed")
    def test_event_limit_bounded(self):
        self.source["events"]=[{}]*1001;self.bad("timeline_event_window_invalid")
    def test_all_nine_roles_journal_only(self):
        for role in n.ROLES:
            with self.subTest(role=role):
                self.resolver=MemoryResolver(role=role)
                self.source=packet(kind=role+"_completed",agent="main" if role=="cto" else role)
                e=self.project()["events"][0];self.assertEqual(e["agent"],"journal")
                self.assertEqual(e["awema_narration"]["voice_role"],"system")
    def test_forty_five_synthetic_journal_events_exact(self):
        r=MemoryResolver();records={};proofs={};events=[]
        for index in range(45):
            eid=index+1;kind="plan_created";sha=hashlib.sha256(kind.encode()).hexdigest()
            binding=n.Binding(MID,eid)
            records[eid]=n.EventRecord(binding,kind,100+index,sha)
            proofs[eid]=n.EvidenceProof(binding,"event:"+str(eid),sha,"completed","recorded")
            events.append(packet(kind=kind,agent="journal",eid=eid,stamp=(100+index)*1000)["events"][0])
        r.resolve_event=lambda auth,mid,eid:records[eid]
        r.resolve_evidence=lambda auth,binding,ref:proofs[binding.event_id]
        self.source.update(events=events,seq=45,total=45)
        out=project_timeline("owner",self.source,r)
        self.assertEqual(len(out["events"]),45)
        self.assertTrue(all(e["agent"]=="journal" and e["kind"]=="say" for e in out["events"]))
        self.assertTrue(all(e["text"]==e["fr"]==e["awema_narration"]["audio_text"] for e in out["events"]))

if __name__=="__main__":unittest.main()
