'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const vm = require('node:vm');
const { createController, PROFILE_NAMES } = require('./awema-voice.js');
const MID = 'f_0123456789abcdef01234567', MID2 = 'f_1123456789abcdef01234567';
const NOW = 1792212000000, text = 'Le développement a transmis son livrable à la vérification.';
const digest = async input => createHash('sha256').update(input).digest('hex');
const bytes = new Uint8Array([73, 68, 51, 3, 0, 0, 0, 0]);
const sha = input => createHash('sha256').update(input).digest('hex');
const narration = () => ({ available: true, mission_id: MID, event_id: 7, text,
  text_sha256: sha(text), narration_sha256: 'a'.repeat(64), voice_role: 'system',
  provenance: { kind: 'system_milestone', attested: false, role: 'system', source_event_sha256: 'b'.repeat(64) } });
const json = (value, code = 200) => new Response(JSON.stringify(value), { status: code, headers: { 'content-type': 'application/json' } });
const settle = () => new Promise(resolve => setImmediate(resolve));

function setup(overrides = {}) {
  const calls = [], captions = [], statuses = [], revoked = [], audios = [], narrated = [];
  const timers = new Map(), intervals = new Map(); let sequence = 0;
  const ctx = { missionId: MID, token: 1, hidden: false, offline: false, muted: false };
  const n = narration(); if (overrides.narration) overrides.narration(n);
  const generated = { available: true, mission_id: MID, event_id: 7, narration_sha256: n.narration_sha256,
    voice_role: n.voice_role, cached: false, audio: { url: '/finance/standup/api/voice/audio/fixture',
      expires_at: NOW / 1000 + 60, mime_type: 'audio/mpeg', sha256: sha(bytes) } };
  if (overrides.generated) overrides.generated(generated);
  const makeAudio = url => {
    const a = { url, paused: false, removed: false, load() {}, pause() { this.paused = true; }, removeAttribute() { this.removed = true; },
      play() {
        if (overrides.audioReject) return Promise.reject(Error('NotAllowedError'));
        queueMicrotask(() => { this.onplaying?.(); if (!overrides.holdAudio) this.onended?.(); }); return Promise.resolve();
      } };
    audios.push(a); return a;
  };
  const fetcher = async (url, init) => {
    calls.push({ url, init });
    const path = new URL(url).pathname;
    if (path.endsWith('/status')) return json(overrides.status || { available: true, provider: 'elevenlabs', csrf_token: 'csrf-fixture-1234567890' });
    if (path.endsWith('/narration')) return overrides.narrationFetch ? overrides.narrationFetch(url, init) : json(n);
    if (path.endsWith('/generate')) return overrides.generateFetch ? overrides.generateFetch(url, init) : json(generated, overrides.generateStatus || 200);
    if (path.endsWith('/test')) {
      if (overrides.testFetch) return overrides.testFetch(url, init);
      const role = JSON.parse(init.body).role;
      const phrase = 'Bonjour, je suis ' + PROFILE_NAMES[role] + '. Ceci est un test de ma voix dans la Danse.';
      const reply = { available: true, purpose: 'voice_profile_test', role, voice_role: role, text: phrase,
        text_sha256: sha(phrase), narration_sha256: 'f'.repeat(64), cached: false, audio: { ...generated.audio } };
      overrides.profileReply?.(reply);
      return json(reply);
    }
    if (path.includes('/audio/')) return overrides.audioFetch ? overrides.audioFetch(url, init) : new Response(bytes, { headers: { 'content-type': 'audio/mpeg' } });
    throw Error('Unexpected request ' + url);
  };
  const controller = createController({ fetch: fetcher, context: () => ctx, digest,
    baseURL: 'https://laruche.awema.cloud/finance/standup/', now: () => NOW,
    createAudio: makeAudio, createObjectURL: () => 'blob:fixture', revokeObjectURL: u => revoked.push(u),
    onStatus: s => statuses.push(s), onCaption: (...c) => captions.push(c), onNarration: n => narrated.push(n),
    setTimeout: (fn, ms) => { const id = ++sequence; timers.set(id, { fn, ms }); return id; }, clearTimeout: id => timers.delete(id),
    setInterval: (fn, ms) => { const id = ++sequence; intervals.set(id, { fn, ms }); return id; }, clearInterval: id => intervals.delete(id) });
  return { controller, calls, captions, statuses, revoked, audios, narrated, ctx, n, timers, intervals,
    tick() { for (const timer of [...intervals.values()]) timer.fn(); },
    timeout(ms) { for (const [id, timer] of [...timers]) if (timer.ms === ms) { timers.delete(id); timer.fn(); } } };
}

test('page construction, disabled playback and absent consent perform zero requests', async () => {
  const h = setup();
  assert.equal(h.calls.length, 0);
  assert.equal((await h.controller.enable(false)).reason, 'explicit_opt_in_required');
  assert.equal((await h.controller.play(7, 1)).reason, 'not_enabled');
  assert.equal(h.calls.length, 0);
});
test('disabled backend is a text-only result and never generates', async () => {
  const h = setup({ status: { available: false } });
  assert.equal((await h.controller.enable(true)).reason, 'backend_disabled');
  await h.controller.play(7, 1);
  assert.equal(h.calls.length, 1); assert.equal(h.controller.enabled, false);
});
test('missing CSRF capability fails closed without generation', async () => {
  const h = setup({ status: { available: true, provider: 'elevenlabs' } });
  assert.equal((await h.controller.enable(true)).reason, 'backend_disabled'); assert.equal(h.calls.length, 1);
});
test('activation checks status only: no generation, preloading or audio', async () => {
  const h = setup(); assert.equal((await h.controller.enable(true)).okay, true);
  assert.equal(h.calls.length, 1); assert.equal(h.audios.length, 0);
});
test('system milestone uses journal, exact canonical text, protected same-origin audio', async () => {
  const h = setup(); await h.controller.enable(true); const r = await h.controller.play(7, 1);
  assert.equal(r.okay, true); assert.equal(h.captions[0][0], 'journal'); assert.equal(h.captions[0][1], text);
  assert.equal(h.narrated.length, 1); assert.equal(h.narrated[0].text, text);
  assert.equal(h.audios[0].preload, 'none'); assert.equal(h.audios[0].paused, true); assert.deepEqual(h.revoked, ['blob:fixture']);
  assert.equal(h.timers.size, 0); assert.equal(h.intervals.size, 0);
  for (const call of h.calls) { assert.equal(new URL(call.url).origin, 'https://laruche.awema.cloud'); assert.equal(call.init.credentials, 'same-origin'); assert.equal(call.init.redirect, 'error'); assert.equal(call.init.mode, 'same-origin'); }
  const post = h.calls.find(c => c.init.method === 'POST');
  assert.deepEqual(JSON.parse(post.init.body), { mission_id: MID, event_id: 7 });
  assert.equal(post.init.headers['X-CSRF-Token'], 'csrf-fixture-1234567890');
  assert.equal(post.init.headers['X-AWEMA-Voice-Consent'], 'true');
  assert.ok(!post.init.body.includes(text)); assert.ok(!post.init.headers.Authorization);
});
test('only attested worker report uses the corresponding agent voice', async () => {
  const h = setup({ narration(n) { n.voice_role = 'cto'; n.provenance = { ...n.provenance, kind: 'attested_worker_report', attested: true, role: 'cto', report_sha256: 'c'.repeat(64), evidence_sha256: 'd'.repeat(64) }; } });
  await h.controller.enable(true); assert.equal((await h.controller.play(7, 1)).okay, true); assert.equal(h.captions[0][0], 'main');
});
test('unattested worker summary cannot trigger provider generation', async () => {
  const h = setup({ narration(n) { n.voice_role = 'dev'; n.provenance.kind = 'attested_worker_report'; n.provenance.role = 'dev'; } });
  await h.controller.enable(true); assert.equal((await h.controller.play(7, 1)).reason, 'worker_report_not_attested'); assert.equal(h.calls.length, 2);
});
test('system milestone cannot impersonate an agent', async () => {
  const h = setup({ narration(n) { n.voice_role = 'dev'; } }); await h.controller.enable(true);
  assert.equal((await h.controller.play(7, 1)).reason, 'system_voice_required'); assert.equal(h.calls.length, 2);
});
test('text digest is verified separately from opaque narration identity', async () => {
  const h = setup({ narration(n) { n.text = 'Texte remplacé après empreinte.'; } }); await h.controller.enable(true);
  assert.equal((await h.controller.play(7, 1)).reason, 'narration_text_digest_mismatch'); assert.equal(h.calls.length, 2);
});
test('narration from another event is rejected before generation', async () => {
  const h = setup({ narration(n) { n.event_id = 8; } }); await h.controller.enable(true);
  assert.equal((await h.controller.play(7, 1)).reason, 'narration_invalid'); assert.equal(h.calls.length, 2);
});
test('generated audio must match the narration object, event and role', async () => {
  const h = setup({ generated(g) { g.narration_sha256 = 'e'.repeat(64); } }); await h.controller.enable(true);
  assert.equal((await h.controller.play(7, 1)).reason, 'generated_audio_invalid'); assert.equal(h.calls.length, 3);
});
test('external, redirected or unscoped audio URLs are rejected without fetching', async () => {
  for (const url of ['https://api.elevenlabs.io/audio/x', '/finance/api/session', '//evil.invalid/voice.mp3', '/finance/standup/api/voice/audio/../private']) {
    const h = setup({ generated(g) { g.audio.url = url; } }); await h.controller.enable(true);
    assert.equal((await h.controller.play(7, 1)).reason, 'audio_origin_invalid'); assert.equal(h.calls.length, 3);
  }
});
test('expired audio is not fetched or played', async () => {
  const h = setup({ generated(g) { g.audio.expires_at = NOW / 1000; } }); await h.controller.enable(true);
  assert.equal((await h.controller.play(7, 1)).reason, 'audio_expired'); assert.equal(h.calls.length, 3);
});
test('a permissive lifetime longer than five minutes is rejected', async () => {
  const h = setup({ generated(g) { g.audio.expires_at = NOW / 1000 + 3600; } }); await h.controller.enable(true);
  assert.equal((await h.controller.play(7, 1)).reason, 'audio_expired');
});
test('mismatching audio bytes never reach Audio', async () => {
  const h = setup({ audioFetch() { return new Response(new Uint8Array([9, 8]), { headers: { 'content-type': 'audio/mpeg' } }); } }); await h.controller.enable(true);
  assert.equal((await h.controller.play(7, 1)).reason, 'audio_digest_mismatch'); assert.equal(h.audios.length, 0);
});
test('oversize audio header is rejected before buffering', async () => {
  const h = setup({ audioFetch() { return new Response(bytes, { headers: { 'content-type': 'audio/mpeg', 'content-length': '999999999' } }); } }); await h.controller.enable(true);
  assert.equal((await h.controller.play(7, 1)).reason, 'audio_invalid'); assert.equal(h.audios.length, 0);
});
test('oversize streaming audio is cancelled even without a content-length', async () => {
  let cancelled = false;
  const h = setup({ audioFetch() { return new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array(8 * 1024 * 1024 + 1)); }, cancel() { cancelled = true; } }), { headers: { 'content-type': 'audio/mpeg' } }); } });
  await h.controller.enable(true); assert.equal((await h.controller.play(7, 1)).reason, 'audio_too_large'); assert.equal(cancelled, true);
});
test('session expiry disables remote voice and has no automatic retry', async () => {
  const h = setup({ generateStatus: 401 }); await h.controller.enable(true);
  assert.equal((await h.controller.play(7, 1)).reason, 'session_expired'); assert.equal(h.controller.enabled, false); assert.equal(h.calls.length, 3);
});
test('generation uncertainty/failure never retries or blocks the caller', async () => {
  const h = setup({ generateFetch() { return json({ error: 'provider_outcome_uncertain' }, 503); } }); await h.controller.enable(true);
  assert.equal((await h.controller.play(7, 1)).okay, false); assert.equal(h.calls.filter(c => c.init.method === 'POST').length, 1); assert.equal(h.audios.length, 0);
});
test('pause aborts an in-flight generation, without playing its late result', async () => {
  let signal;
  const h = setup({ generateFetch(_url, init) { signal = init.signal; return new Promise((_r, reject) => init.signal.addEventListener('abort', () => reject(Error('AbortError')), { once: true })); } });
  await h.controller.enable(true); const play = h.controller.play(7, 1); await settle(); assert.ok(signal);
  h.controller.stop(); assert.equal(signal.aborted, true); assert.equal((await play).okay, false); assert.equal(h.audios.length, 0);
});
test('generation has one bounded timeout, with no retry', async () => {
  let signal;
  const h = setup({ generateFetch(_url, init) { signal = init.signal; return new Promise((_r, reject) => init.signal.addEventListener('abort', () => reject(Error('AbortError')), { once: true })); } });
  await h.controller.enable(true); const play = h.controller.play(7, 1); await settle(); h.timeout(20000);
  assert.equal((await play).okay, false); assert.equal(signal.aborted, true); assert.equal(h.calls.length, 3);
});
for (const state of ['hidden', 'offline', 'muted', 'token', 'missionId']) test(state + ' change stops playback and revokes the current audio buffer', async () => {
  const h = setup({ holdAudio: true }); await h.controller.enable(true); const play = h.controller.play(7, 1); await settle();
  assert.equal(h.audios.length, 1);
  h.ctx[state] = state === 'missionId' ? MID2 : state === 'token' ? 2 : true; h.tick();
  assert.equal((await play).okay, false); assert.equal(h.audios[0].paused, true); assert.deepEqual(h.revoked, ['blob:fixture']); assert.equal(h.intervals.size, 0);
});
test('provider audio end, expiry and autoplay rejection all release playback', async () => {
  const reject = setup({ audioReject: true }); await reject.controller.enable(true); assert.equal((await reject.controller.play(7, 1)).okay, false); assert.equal(reject.revoked.length, 1);
  const expiry = setup({ holdAudio: true }); await expiry.controller.enable(true); const play = expiry.controller.play(7, 1); await settle(); expiry.timeout(60000);
  assert.equal((await play).okay, false); assert.equal(expiry.audios[0].paused, true);
});
test('dispose and opt-out cancel all audio and prevent future activation', async () => {
  const h = setup({ holdAudio: true }); await h.controller.enable(true); const play = h.controller.play(7, 1); await settle(); h.controller.dispose();
  assert.equal((await play).okay, false); assert.equal(h.controller.enabled, false); assert.equal((await h.controller.enable(true)).reason, 'explicit_opt_in_required'); assert.equal(h.calls.length, 4);
});

test('profile auditions require the existing explicit opt-in and never warm up', async () => {
  const h = setup();
  assert.equal((await h.controller.testProfile('dev', 1)).reason, 'not_enabled'); assert.equal(h.calls.length, 0);
  await h.controller.enable(true); assert.equal(h.calls.length, 1);
  assert.equal(h.audios.length, 0);
});
test('all nine role profiles send role only, read the fixed phrase and remain outside recorded activity', async () => {
  assert.equal(Object.keys(PROFILE_NAMES).length, 9);
  for (const role of Object.keys(PROFILE_NAMES)) {
    const h = setup(); await h.controller.enable(true);
    assert.equal((await h.controller.testProfile(role, 1)).okay, true, role);
    const posts = h.calls.filter(c => c.init.method === 'POST'); assert.equal(posts.length, 1);
    assert.ok(posts[0].url.endsWith('/api/voice/test'));
    assert.deepEqual(JSON.parse(posts[0].init.body), { role });
    assert.equal(posts[0].init.headers['X-AWEMA-Voice-Consent'], 'true');
    assert.equal(posts[0].init.headers['X-CSRF-Token'], 'csrf-fixture-1234567890');
    assert.equal(h.narrated.length, 0); assert.equal(h.captions[0][0], 'journal');
    assert.equal(h.captions[0][1], 'Bonjour, je suis ' + PROFILE_NAMES[role] + '. Ceci est un test de ma voix dans la Danse.');
    assert.ok(h.statuses.some(s => s.includes('TEST DE VOIX')));
    assert.equal(h.calls.filter(c => /\/narration\?|\/generate$/.test(c.url)).length, 0);
  }
});
test('unknown profile, provider ID, client text and fake system role are rejected before the network', async () => {
  const h = setup(); await h.controller.enable(true);
  for (const role of ['system', 'all', 'voice_provider_identifier', { role: 'dev', text: 'Free text' }]) {
    assert.equal((await h.controller.testProfile(role, 1)).reason, 'invalid_voice_profile');
  }
  assert.equal(h.calls.length, 1);
});
test('profile test response cannot masquerade as a real mission event or another voice', async () => {
  for (const mutate of [r => { r.role = 'qa'; }, r => { r.voice_role = 'qa'; }, r => { r.purpose = 'attested_worker_report'; },
    r => { r.mission_id = MID; }, r => { r.event_id = 7; }, r => { r.text = 'J’ai terminé une tâche réelle.'; r.text_sha256 = sha(r.text); }]) {
    const h = setup({ profileReply: mutate }); await h.controller.enable(true);
    assert.equal((await h.controller.testProfile('dev', 1)).reason, 'voice_profile_test_invalid');
    assert.equal(h.audios.length, 0); assert.equal(h.narrated.length, 0); assert.equal(h.calls.length, 2);
  }
});
test('profile test verifies exact UTF-8 text digest before any audio fetch', async () => {
  const h = setup({ profileReply(r) { r.text_sha256 = 'a'.repeat(64); } }); await h.controller.enable(true);
  assert.equal((await h.controller.testProfile('dev', 1)).reason, 'voice_profile_text_digest_mismatch');
  assert.equal(h.calls.length, 2); assert.equal(h.audios.length, 0);
});
for (const state of ['hidden', 'offline', 'token', 'missionId']) test('profile audition stops on ' + state + ' change', async () => {
  const h = setup({ holdAudio: true }); await h.controller.enable(true); const audition = h.controller.testProfile('dev', 1); await settle();
  assert.equal(h.audios.length, 1); h.ctx[state] = state === 'missionId' ? MID2 : state === 'token' ? 2 : true; h.tick();
  assert.equal((await audition).okay, false); assert.equal(h.audios[0].paused, true); assert.deepEqual(h.revoked, ['blob:fixture']);
});
test('profile audition generation cancelled by pause does not retry', async () => {
  let signal;
  const h = setup({ testFetch(_url, init) { signal = init.signal; return new Promise((_r, reject) => init.signal.addEventListener('abort', () => reject(Error('AbortError')), { once: true })); } });
  await h.controller.enable(true); const audition = h.controller.testProfile('dev', 1); await settle(); h.controller.stop();
  assert.equal((await audition).okay, false); assert.equal(signal.aborted, true); assert.equal(h.calls.length, 2); assert.equal(h.audios.length, 0);
});
test('unavailable profile test leaves the mission path usable in text and has no retry', async () => {
  const h = setup({ testFetch() { return json({ available: false, reason: 'role_voice_not_configured' }, 503); } });
  await h.controller.enable(true); assert.equal((await h.controller.testProfile('dev', 1)).okay, false);
  assert.equal(h.calls.length, 2); assert.equal(h.narrated.length, 0);
});

// A small DOM mock executes the actual adapter, including local-only French filtering and UI consent.
function mountAdapter(overrides = {}) {
  const elements = [], events = {}, calls = [], said = [], captions = [];
  class Element {
    constructor(tag) { this.tagName = tag; this.children = []; this.dataset = {}; this.value = ''; this.disabled = false; this.hidden = false; this.checked = false; }
    append(...children) { this.children.push(...children); if (this.tagName === 'select' && !this.value && this.children[0]) this.value = this.children[0].value; }
    insertBefore(child) { this.append(child); }
    replaceChildren(...children) { this.children = []; this.value = ''; this.append(...children); }
    setAttribute(key, value) { this[key] = value; }
    get lastElementChild() { return this.children.at(-1); }
  }
  const banner = new Element('div'), panel = new Element('div'); panel.append(new Element('button'));
  const document = { hidden: false, documentElement: new Element('html'),
    createElement(tag) { const e = new Element(tag); elements.push(e); return e; }, createTextNode(t) { return { textContent: t }; },
    querySelector: () => banner, getElementById: () => panel, addEventListener(type, fn) { events[type] = fn; } };
  const local = { name: 'Français local', voiceURI: 'fr-local', lang: 'fr-FR', localService: true };
  const state = { cur: { id: MID }, token: 1, events: [] }, aud = { muted: false, off() { return this.muted; } };
  const sandbox = { console, URL, Blob, AbortController, TextEncoder, Uint8Array, Promise,
    Audio: function (url) { this.url = url; this.pause = () => {}; this.removeAttribute = () => {}; this.load = () => {}; this.play = () => { queueMicrotask(() => { this.onplaying?.(); this.onended?.(); }); return Promise.resolve(); }; },
    document, navigator: { onLine: true }, location: { origin: 'https://laruche.awema.cloud' },
    crypto: { randomUUID: () => 'fixture-client', subtle: require('node:crypto').webcrypto.subtle },
    Option: function (label, value) { this.textContent = label; this.value = value; }, MutationObserver: class { observe() {} disconnect() {} },
    BroadcastChannel: class { postMessage() {} close() {} },
    setTimeout: () => 1, clearTimeout() {}, setInterval: () => 2, clearInterval() {},
    S: state, AUD: aud, prefs: {}, CID: 'fixture', sleep: async () => {}, estMs: () => 1, spd: () => 1,
    captionRun: (...x) => captions.push(x), pause: () => { state.token++; }, applyMute() {}, warmTTS() {}, speakLine() {},
    window: { speechSynthesis: { getVoices: () => [local, { ...local, localService: false, voiceURI: 'fr-online' }, { ...local, lang: 'en-US', voiceURI: 'en' }], addEventListener() {}, cancel() {}, speak(u) { said.push(u); u.onstart?.(); u.onend?.(); } },
      SpeechSynthesisUtterance: function (text) { this.text = text; }, fetch: async (...x) => { calls.push(x); return overrides.fetch ? overrides.fetch(...x) : json({ available: false }); }, addEventListener(type, fn) { events[type] = fn; } } };
  sandbox.globalThis = sandbox.window;
  vm.createContext(sandbox); vm.runInContext(readFileSync(require.resolve('./awema-voice.js'), 'utf8'), sandbox);
  return { elements, events, calls, said, captions, sandbox, state, byId: id => elements.find(e => e.id === id) };
}
test('actual UI defaults to local French voices with zero remote requests', async () => {
  const h = mountAdapter(), select = h.byId('awema-voice-select'); assert.equal(h.calls.length, 0); assert.equal(select.children.length, 1); assert.equal(select.children[0].value, 'fr-local');
  await h.byId('awema-voice').onclick();
  const ev = { source_event_id: 7, agent: 'dev' }; h.state.events.push(ev);
  await h.sandbox.speakLine(text, { id: 'dev' }, true, 1, 'fr', false, ev);
  assert.equal(h.said.length, 1); assert.equal(h.said[0].voice.localService, true); assert.equal(h.captions[0][0], 'journal'); assert.equal(h.calls.length, 0);
});
test('upstream synthetic/free-text speech has no event and is never voiced', async () => {
  const h = mountAdapter(); await h.byId('awema-voice').onclick();
  await h.sandbox.speakLine('Invented conversation', { id: 'dev' }, true, 1);
  assert.equal(h.said.length, 0); assert.equal(h.calls.length, 0);
});
test('ElevenLabs selection alone and activation without checkbox send nothing', async () => {
  const h = mountAdapter(), provider = h.byId('awema-voice-provider'); provider.value = 'elevenlabs'; provider.onchange();
  assert.equal(h.calls.length, 0); await h.byId('awema-voice').onclick(); assert.equal(h.calls.length, 0);
  h.byId('awema-voice-remote-consent').checked = true; await h.byId('awema-voice').onclick(); assert.equal(h.calls.length, 1); assert.equal(h.byId('awema-voice')['aria-pressed'], 'false');
});
test('existing voice-test button exposes nine explicit audition profiles and is disabled without activation', async () => {
  const h = mountAdapter(), profile = h.byId('awema-voice-profile'), button = h.byId('awema-voice-test');
  assert.equal(profile.children.length, 9); assert.equal(profile.hidden, true); assert.equal(button.disabled, true);
  const provider = h.byId('awema-voice-provider'); provider.value = 'elevenlabs'; provider.onchange();
  assert.equal(profile.hidden, false); assert.equal(profile.disabled, true); assert.equal(button.disabled, true);
  await button.onclick(); assert.equal(h.calls.length, 0); assert.equal(h.state.events.length, 0);
});
test('actual activated voice-test button auditions every profile without events, agent bubbles or narration calls', async () => {
  const h = mountAdapter({ fetch(url, init) {
    if (url.endsWith('/status')) return json({ available: true, provider: 'elevenlabs', csrf_token: 'csrf-fixture-1234567890' });
    if (url.endsWith('/test')) {
      const role = JSON.parse(init.body).role;
      const phrase = 'Bonjour, je suis ' + PROFILE_NAMES[role] + '. Ceci est un test de ma voix dans la Danse.';
      return json({ available: true, purpose: 'voice_profile_test', role, voice_role: role, text: phrase,
        text_sha256: sha(phrase), narration_sha256: 'f'.repeat(64), cached: false,
        audio: { url: '/finance/standup/api/voice/audio/profile-fixture', expires_at: Date.now() / 1000 + 60,
          mime_type: 'audio/mpeg', sha256: sha(bytes) } });
    }
    if (url.includes('/audio/')) return new Response(bytes, { headers: { 'content-type': 'audio/mpeg' } });
    throw Error('Unexpected mission request during profile audition');
  } });
  const provider = h.byId('awema-voice-provider'); provider.value = 'elevenlabs'; provider.onchange();
  h.byId('awema-voice-remote-consent').checked = true; await h.byId('awema-voice').onclick();
  assert.equal(h.byId('awema-voice')['aria-pressed'], 'true'); assert.equal(h.byId('awema-voice-test').disabled, false);
  const profile = h.byId('awema-voice-profile');
  for (const role of Object.keys(PROFILE_NAMES)) {
    profile.value = role; profile.onchange(); await h.byId('awema-voice-test').onclick();
    assert.equal(h.byId('awema-voice-test').disabled, false);
  }
  assert.equal(h.state.events.length, 0);
  assert.equal(h.calls.filter(c => c[1].method === 'POST').length, 9);
  assert.equal(h.captions.length, 9); assert.ok(h.captions.every(c => c[0] === 'journal'));
  assert.equal(h.calls.filter(c => /\/narration\?|\/generate$/.test(c[0])).length, 0);
  assert.ok(h.byId('awema-voice-status').textContent.includes('TEST DE VOIX'));
});
