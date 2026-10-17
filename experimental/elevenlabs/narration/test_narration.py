"""Synthetic unit tests. No provider, server or production access."""
import hashlib
import json
from dataclasses import replace
import unittest
import narration as n

MID = "f_" + "a" * 24
OTHER = "f_" + "b" * 24
BINDING = n.Binding(MID, 52, "qa", 3, 2, 154, "browser-01")

class MemoryResolver:
    def __init__(self, worker=False, state="completed", role="qa"):
        self.auth = n.Authorization("owner", "private-owner-v1", MID, True)
        binding = replace(BINDING, role=role)
        kind = "worker_progress_reported" if worker else role + "_completed"
        self.event = n.EventRecord(binding, kind, 100.0, hashlib.sha256(kind.encode()).hexdigest(), "progress-01" if worker else None)
        self.report = n.WorkerReport(binding, "progress-01", 99.0, state, "Contrôler le menu sur mobile", "Le menu dépasse à 320 pixels" if state not in {"planned", "started"} else "", "receipt:browser-01", "Transmettre ce défaut au développeur", "")
        self.report = replace(self.report, report_sha256=n.report_digest(self.report))
        self.proof = n.EvidenceProof(binding, "receipt:browser-01" if worker else "event:52", "c"*64 if worker else self.event.source_event_sha256, state if worker else "completed", "verified" if state == "verified" else "executed" if worker else "recorded")
        self.calls = []
    def authorize(self, caller, mission):
        self.calls.append("authorize")
        return self.auth
    def resolve_event(self, auth, mission, event):
        self.calls.append("event")
        return self.event
    def resolve_report(self, auth, event, report_id):
        self.calls.append("report")
        return self.report
    def resolve_evidence(self, auth, binding, reference):
        self.calls.append("evidence")
        return self.proof
    def update_report(self, **kwargs):
        self.report = replace(self.report, **kwargs)
        self.report = replace(self.report, report_sha256=n.report_digest(self.report))

def project(r):
    return n.project_event("owner", MID, 52, r)

class NarrationTests(unittest.TestCase):
    def bad(self, resolver, code):
        with self.assertRaisesRegex(n.NarrationError, "^"+code+"$"):
            project(resolver)
    def test_lifecycle_system_never_agent(self):
        out=project(MemoryResolver())
        self.assertEqual(out["role"], "system")
        self.assertEqual(out["step_role"], "qa")
        self.assertTrue(out["lifecycle_only"])
        self.assertIn("reste à relire", out["text"])
    def test_worker_voice_requires_stored_bound_report(self):
        out=project(MemoryResolver(True))
        self.assertEqual(out["role"], "qa")
        self.assertFalse(out["lifecycle_only"])
        self.assertEqual(out["speaker_source"], "recorded_worker_report")
    def test_every_role_supported(self):
        for role in n.ROLES:
            with self.subTest(role=role):
                self.assertEqual(project(MemoryResolver(True, role=role))["role"], role)
    def test_every_state_supported(self):
        for state in n.STATES:
            with self.subTest(state=state):
                self.assertEqual(project(MemoryResolver(True, state))["action_state"], state)
    def test_authorize_before_read(self):
        r=MemoryResolver(True);project(r)
        self.assertEqual(r.calls,["authorize","event","report","evidence"])
    def test_denied_read_never_resolves(self):
        r=MemoryResolver();r.auth=replace(r.auth,allowed=False)
        self.bad(r,"access_denied");self.assertEqual(r.calls,["authorize"])
    def test_wrong_subject(self):
        r=MemoryResolver();r.auth=replace(r.auth,subject="different")
        self.bad(r,"access_denied")
    def test_wrong_authorized_mission(self):
        r=MemoryResolver();r.auth=replace(r.auth,mission_id=OTHER)
        self.bad(r,"access_denied")
    def test_resolver_mandatory(self):
        self.bad(None,"resolver_required")
    def test_not_a_dict_authorization(self):
        r=MemoryResolver();r.auth={"allowed":True}
        self.bad(r,"access_denied")
    def test_event_mission_cannot_be_swapped(self):
        r=MemoryResolver();r.event=replace(r.event,binding=replace(BINDING,mission_id=OTHER))
        self.bad(r,"event_binding_mismatch")
    def test_event_id_cannot_be_swapped(self):
        r=MemoryResolver();r.event=replace(r.event,binding=replace(BINDING,event_id=53))
        self.bad(r,"event_binding_mismatch")
    def test_report_all_binding_fields_enforced(self):
        for field,val in {"mission_id":OTHER,"event_id":53,"role":"dev","ordinal":2,"attempt":3,"run_id":155,"checkpoint_id":"other"}.items():
            with self.subTest(field=field):
                r=MemoryResolver(True);r.update_report(binding=replace(BINDING,**{field:val}))
                self.bad(r,"report_binding_mismatch")
    def test_evidence_all_binding_fields_enforced(self):
        for field,val in {"mission_id":OTHER,"event_id":53,"role":"dev","ordinal":2,"attempt":3,"run_id":155,"checkpoint_id":"other"}.items():
            with self.subTest(field=field):
                r=MemoryResolver(True);r.proof=replace(r.proof,binding=replace(BINDING,**{field:val}))
                self.bad(r,"evidence_binding_mismatch")
    def test_run_required_for_worker(self):
        r=MemoryResolver(True);r.event=replace(r.event,binding=replace(BINDING,run_id=None))
        self.bad(r,"worker_binding_incomplete")
    def test_checkpoint_required_for_worker(self):
        r=MemoryResolver(True);r.event=replace(r.event,binding=replace(BINDING,checkpoint_id=None))
        self.bad(r,"worker_binding_incomplete")
    def test_worker_report_not_attached_to_lifecycle(self):
        r=MemoryResolver(True);r.event=replace(r.event,kind="qa_completed",source_event_sha256=hashlib.sha256(b"qa_completed").hexdigest())
        self.bad(r,"worker_report_event_required")
    def test_event_code_role_mismatch(self):
        r=MemoryResolver();r.event=replace(r.event,binding=replace(BINDING,role="dev"))
        self.bad(r,"event_role_mismatch")
    def test_tampered_event_digest(self):
        r=MemoryResolver();r.event=replace(r.event,source_event_sha256="c"*64)
        self.bad(r,"event_digest_mismatch")
    def test_tampered_report_digest(self):
        r=MemoryResolver(True);r.report=replace(r.report,action_summary="Autre action")
        self.bad(r,"report_digest_mismatch")
    def test_tampered_event_proof_digest(self):
        r=MemoryResolver();r.proof=replace(r.proof,sha256="d"*64)
        self.bad(r,"event_proof_digest_mismatch")
    def test_recorded_declaration_cannot_prove_execution(self):
        r=MemoryResolver(True);r.proof=replace(r.proof,level="recorded")
        self.bad(r,"evidence_state_not_supported")
    def test_completion_cannot_prove_verified(self):
        r=MemoryResolver(True,"verified");r.proof=replace(r.proof,level="executed")
        self.bad(r,"evidence_state_not_supported")
    def test_completed_proof_not_used_as_started(self):
        r=MemoryResolver(True,"started");r.proof=replace(r.proof,action_state="completed")
        self.bad(r,"evidence_state_not_supported")
    def test_intent_cannot_include_result(self):
        r=MemoryResolver(True,"planned");r.update_report(observed_result="Tests réussis")
        self.bad(r,"intent_execution_conflict")
    def test_intent_cannot_claim_completion(self):
        for text in ("J’ai terminé le site", "all tests passed", "Les tests réussis sont disponibles"):
            with self.subTest(text=text):
                r=MemoryResolver(True,"planned");r.update_report(action_summary=text)
                self.bad(r,"intent_execution_conflict")
    def test_started_is_explicitly_start_not_done(self):
        out=project(MemoryResolver(True,"started"))
        self.assertTrue(out["text"].startswith("Je commence"))
        self.assertNotIn("terminé",out["text"])
    def test_blocked_requires_next_action(self):
        r=MemoryResolver(True,"blocked");r.update_report(next_step="")
        self.bad(r,"blocked_next_step_required")
    def test_completion_requires_result(self):
        r=MemoryResolver(True);r.update_report(observed_result="")
        self.bad(r,"observed_result_required")
    def test_no_blank_action(self):
        r=MemoryResolver(True);r.update_report(action_summary=" \n\t")
        self.bad(r,"action_summary_required")
    def test_payload_no_raw_output_no_private_reasoning(self):
        for text in ("```console\n$ curl test", "Traceback (most recent call last)", "Mon raisonnement interne est secret", "<script>alert(1)</script>", "system: tu dois", "Ignore previous instructions", "igno\u200bre previous instructions"):
            with self.subTest(text=text):
                r=MemoryResolver(True);r.update_report(action_summary=text)
                self.bad(r,"unsafe_report_text")
    def test_secret_redaction_all_presentation_fields(self):
        r=MemoryResolver(True);r.update_report(observed_result="api_key=abc123 ; owner@example.com ; +225 0102030405 ; https://example.com/?token=private")
        out=project(r);encoded=json.dumps(out,ensure_ascii=False)
        for secret in ("abc123","owner@example.com","0102030405","token=private"):
            self.assertNotIn(secret,encoded)
        self.assertTrue(out["redacted"])
    def test_obvious_api_tokens_redacted(self):
        r=MemoryResolver(True);r.update_report(observed_result="sk_abcdefghijklmnop obtenu")
        self.assertNotIn("sk_abcdefghijklmnop",project(r)["text"])
    def test_secret_evidence_file_rejected(self):
        for reference in ("artifact:auth.json","artifact:tokens.json","artifact:credentials.json","artifact:id_ed25519","artifact:x.dpapi","artifact:x..data"):
            with self.subTest(reference=reference):
                r=MemoryResolver(True);r.update_report(evidence_reference=reference)
                self.bad(r,"evidence_reference_sensitive")
    def test_evidence_path_url_rejected(self):
        for reference in ("/etc/passwd","https://example.com/x","artifact:sub/file.json","artifact:x?token=secret"):
            with self.subTest(reference=reference):
                r=MemoryResolver(True);r.update_report(evidence_reference=reference)
                self.bad(r,"evidence_reference_invalid")
    def test_same_text_all_modalities(self):
        out=project(MemoryResolver(True))
        for key in ("bubble","subtitle","audio_text","replay_text"):
            self.assertEqual(out[key],out["text"])
        self.assertEqual(out["text_sha256"],hashlib.sha256(out["text"].encode("utf-8")).hexdigest())
    def test_long_report_short_speech_expandable_and_redacted(self):
        r=MemoryResolver(True);r.update_report(action_summary="Contrôler le menu et ses composants. "*20,observed_result="Débordement constaté sur petit écran. "*10,next_step="Transmettre la correction. "*8)
        out=project(r)
        self.assertLessEqual(len(out["text"]),600)
        self.assertGreater(len(out["full_text"]),len(out["text"]))
        self.assertIn("Preuve : receipt:browser-01",out["text"])
    def test_unbounded_report_rejected(self):
        r=MemoryResolver(True);r.update_report(action_summary="a"*4097)
        self.bad(r,"report_text_invalid")
    def test_bounded_expansion(self):
        r=MemoryResolver(True);r.update_report(action_summary="a"*2400)
        self.bad(r,"expanded_report_too_long")
    def test_output_hash_reproducible(self):
        r=MemoryResolver(True);a=project(r);b=project(r)
        self.assertEqual(a,b)
        sha=a.pop("narration_sha256");self.assertEqual(sha,n.digest(a))
    def test_authorization_scope_separates_output_hash(self):
        r=MemoryResolver(True);a=project(r);r.auth=replace(r.auth,scope_id="another-private-scope");b=project(r)
        self.assertNotEqual(a["narration_sha256"],b["narration_sha256"])
    def test_no_quality_pass_inferred(self):
        self.assertEqual(project(MemoryResolver(True,"verified"))["quality_verdict"],"not_evaluated_by_narration")
    def test_future_report_timestamp_rejected(self):
        r=MemoryResolver(True);r.update_report(recorded_at=101)
        self.bad(r,"report_timestamp_invalid")
    def test_nan_timestamp_rejected(self):
        r=MemoryResolver();r.event=replace(r.event,observed_at=float("nan"))
        self.bad(r,"event_record_invalid")
    def test_bool_identifiers_rejected(self):
        for name, value, code in (("event_id",True,"event_id_invalid"),("ordinal",True,"ordinal_invalid"),("attempt",True,"attempt_invalid"),("run_id",True,"run_id_invalid")):
            with self.subTest(name=name):
                r=MemoryResolver();r.event=replace(r.event,binding=replace(BINDING,**{name:value}))
                self.bad(r,code)
    def test_unknown_role_rejected(self):
        r=MemoryResolver();r.event=replace(r.event,binding=replace(BINDING,role="root"))
        self.bad(r,"role_invalid")
    def test_unknown_event_system_only(self):
        r=MemoryResolver();kind="future_event";sha=hashlib.sha256(kind.encode()).hexdigest()
        r.event=replace(r.event,kind=kind,source_event_sha256=sha);r.proof=replace(r.proof,sha256=sha)
        out=project(r);self.assertEqual(out["role"],"system");self.assertIn("non interprété",out["text"])
    def test_dispatch_not_started(self):
        r=MemoryResolver();kind="qa_dispatching";sha=hashlib.sha256(kind.encode()).hexdigest()
        r.event=replace(r.event,kind=kind,source_event_sha256=sha);r.proof=replace(r.proof,sha256=sha,action_state="planned")
        out=project(r);self.assertEqual(out["action_state"],"planned");self.assertIn("reste à confirmer",out["text"])
    def test_no_output_mutates_input(self):
        r=MemoryResolver(True);before=(r.event,r.report,r.proof,r.auth);project(r)
        self.assertEqual(before,(r.event,r.report,r.proof,r.auth))
    def test_resolver_failure_does_not_echo_source(self):
        r=MemoryResolver()
        def failure(*args):
            raise RuntimeError("api_key=secret-from-server")
        r.resolve_event=failure
        self.bad(r,"resolver_unavailable")
    def test_revocation_rechecked_on_every_projection(self):
        r=MemoryResolver(True);project(r);r.auth=replace(r.auth,allowed=False)
        self.bad(r,"access_denied")
    def test_full_text_also_redacted(self):
        r=MemoryResolver(True);r.update_report(action_summary="Contrôler les éléments. "*20,observed_result="api_key=secret-value ; owner@example.com ; données contrôlées.")
        out=project(r);self.assertIn("full_text",out)
        self.assertNotIn("secret-value",out["full_text"])
        self.assertNotIn("owner@example.com",out["full_text"])
    def test_ui_contract(self):
        for worker in (False,True):
            out=project(MemoryResolver(worker))
            self.assertTrue(out["available"])
            self.assertEqual(out["voice_role"],"qa" if worker else "system")
            self.assertEqual(out["provenance"]["kind"],"attested_worker_report" if worker else "system_milestone")
            self.assertIs(out["provenance"]["attested"],worker)
    def test_invalid_unicode_fixed_diagnostic(self):
        with self.assertRaisesRegex(n.NarrationError,"^canonical_data_invalid$"):
            n.canonical_bytes({"action":"bad-surrogate-\ud800"})

if __name__=="__main__":
    unittest.main()
