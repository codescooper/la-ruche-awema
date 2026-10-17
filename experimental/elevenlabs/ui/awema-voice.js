/* Optional La Danse speech. Candidate only: no microphone, provider secret or remote preloading. */
(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.AWEMADanseVoiceCore = api;
})(typeof globalThis === 'object' ? globalThis : this, function () {
  'use strict';
  const MID = /^f_[a-f0-9]{24}$/, SHA = /^[a-f0-9]{64}$/;
  const PROFILE_NAMES = Object.freeze({ cto: 'CTO', pm: 'Chef de projet', designer: 'Designer', dev: 'Développeur',
    qa: 'Vérification', security: 'Sécurité', ops: 'Opérations', assa: 'Direction AWEMA', 'cl-producer': 'CL Producer' });
  const ROLES = new Set(Object.keys(PROFILE_NAMES));
  const MIME = new Set(['audio/mpeg', 'audio/ogg', 'audio/wav']);
  const MAX_AUDIO = 8 * 1024 * 1024, MAX_TEXT = 600;
  const normalized = text => String(text || '').replace(/\s+/g, ' ').trim();
  const identity = (mission, event) => MID.test(mission || '') && Number.isSafeInteger(event) && event > 0;
  const unavailable = reason => ({ okay: false, reason });

  function createController(options) {
    const { fetch: fetcher, context, digest, createAudio, createObjectURL, revokeObjectURL } = options;
    const now = options.now || Date.now, onStatus = options.onStatus || (() => {}), onCaption = options.onCaption || (() => {});
    const onNarration = options.onNarration || (() => {});
    const later = options.setTimeout || setTimeout, cancelLater = options.clearTimeout || clearTimeout;
    const repeat = options.setInterval || setInterval, cancelRepeat = options.clearInterval || clearInterval;
    const base = new URL(options.baseURL);
    let allowed = false, approvedMission = '', csrf = '', epoch = 0, request = null, audio = null, objectURL = null;
    let resolveCurrent = null, finishTimer = null, guard = null, disposed = false;

    function stop() {
      epoch++; request?.abort(); request = null;
      if (audio) {
        audio.onended = audio.onerror = audio.onplaying = null;
        try { audio.pause(); audio.removeAttribute('src'); audio.load?.(); } catch {}
      }
      audio = null;
      if (objectURL) { revokeObjectURL(objectURL); objectURL = null; }
      if (finishTimer !== null) cancelLater(finishTimer);
      if (guard !== null) cancelRepeat(guard);
      finishTimer = guard = null;
      const resolve = resolveCurrent; resolveCurrent = null; resolve?.(false);
    }
    function disable(reason) {
      allowed = false; approvedMission = ''; csrf = ''; stop();
      if (reason) onStatus(reason);
    }
    function isCurrent(run, mission, token) {
      const ctx = context();
      return !disposed && allowed && epoch === run && ctx.missionId === mission && approvedMission === mission &&
        ctx.token === token && !ctx.hidden && !ctx.offline && !ctx.muted;
    }
    const url = route => new URL('api/voice/' + route, base);
    async function json(route, signal, body) {
      const headers = { Accept: 'application/json' };
      const init = { method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store',
        redirect: 'error', mode: 'same-origin', signal, headers };
      if (body !== undefined) {
        if (!csrf) throw Error('csrf_required');
        headers['Content-Type'] = 'application/json'; headers['X-CSRF-Token'] = csrf;
        headers['X-AWEMA-Voice-Consent'] = 'true'; init.body = JSON.stringify(body);
      }
      const response = await fetcher(url(route).href, init);
      if (response.status === 401 || response.status === 403) { disable('Session vocale expirée ou accès refusé. Reconnectez-vous avant une nouvelle activation.'); throw Error('session_expired'); }
      if (!response.ok || !/application\/json/i.test(response.headers.get('content-type') || '')) throw Error('voice_unavailable');
      return response.json();
    }
    async function enable(consent) {
      disable();
      if (disposed || consent !== true) return unavailable('explicit_opt_in_required');
      const ctx = context();
      if (!MID.test(ctx.missionId || '') || ctx.hidden || ctx.offline) return unavailable('mission_unavailable');
      // First network request: neither loading the page nor selecting a provider sends anything.
      const controller = request = new AbortController(), run = epoch;
      const deadline = later(() => controller.abort(), 10000);
      try {
        const status = await json('status', controller.signal);
        if (run !== epoch || disposed || context().missionId !== ctx.missionId || context().hidden || context().offline) return unavailable('cancelled');
        if (!status || status.available !== true || status.provider !== 'elevenlabs' ||
          typeof status.csrf_token !== 'string' || status.csrf_token.length < 16 || status.csrf_token.length > 512) {
          onStatus('ElevenLabs est désactivé ou indisponible. La voix locale et le suivi en texte restent disponibles.'); return unavailable('backend_disabled');
        }
        csrf = status.csrf_token; approvedMission = ctx.missionId; allowed = true;
        onStatus('ElevenLabs activé pour cette mission. Seules les narrations vérifiées sont transmises, à leur lecture.'); return { okay: true };
      } catch {
        if (run === epoch) onStatus('Connexion vocale indisponible. Aucun nouvel essai automatique ; le suivi continue en texte.');
        return unavailable('voice_unavailable');
      } finally { cancelLater(deadline); if (request === controller) request = null; }
    }
    async function validateNarration(data, mission, event) {
      if (!data || data.available !== true || data.mission_id !== mission || data.event_id !== event ||
        typeof data.text !== 'string' || !data.text.trim() || data.text.length > MAX_TEXT ||
        !SHA.test(data.narration_sha256 || '') || !SHA.test(data.text_sha256 || '')) throw Error('narration_invalid');
      // narration_sha256 identifies the canonical server object, not the text. Never conflate them.
      if (await digest(data.text) !== data.text_sha256) throw Error('narration_text_digest_mismatch');
      const p = data.provenance;
      if (!p || (p.kind !== 'system_milestone' && p.kind !== 'attested_worker_report') || !SHA.test(p.source_event_sha256 || '')) throw Error('narration_provenance_invalid');
      if (p.kind === 'system_milestone') {
        if (data.voice_role !== 'system') throw Error('system_voice_required');
      } else if (p.attested !== true || !ROLES.has(p.role) || data.voice_role !== p.role ||
        !SHA.test(p.report_sha256 || '') || !SHA.test(p.evidence_sha256 || '')) throw Error('worker_report_not_attested');
      return data;
    }
    async function validateProfileTest(data, role) {
      const expected = 'Bonjour, je suis ' + PROFILE_NAMES[role] + '. Ceci est un test de ma voix dans la Danse.';
      if (!data || data.available !== true || data.purpose !== 'voice_profile_test' || data.role !== role ||
        data.voice_role !== role || data.text !== expected || !SHA.test(data.text_sha256 || '') ||
        !SHA.test(data.narration_sha256 || '') || 'mission_id' in data || 'event_id' in data) throw Error('voice_profile_test_invalid');
      if (await digest(data.text) !== data.text_sha256) throw Error('voice_profile_text_digest_mismatch');
      return data;
    }
    async function audioBytes(response, signal) {
      const mime = String(response.headers.get('content-type') || '').split(';')[0].trim().toLowerCase(), length = response.headers.get('content-length');
      if (!response.ok || !MIME.has(mime) || (length && (!/^\d+$/.test(length) || Number(length) > MAX_AUDIO))) throw Error('audio_invalid');
      if (!response.body?.getReader) throw Error('bounded_audio_stream_unavailable');
      const reader = response.body.getReader(), parts = []; let size = 0;
      try {
        while (true) {
          if (signal.aborted) throw Error('cancelled');
          const item = await reader.read(); if (item.done) break;
          size += item.value.byteLength; if (size > MAX_AUDIO) throw Error('audio_too_large'); parts.push(item.value);
        }
      } finally { if (signal.aborted || size > MAX_AUDIO) await reader.cancel().catch(() => {}); reader.releaseLock?.(); }
      if (!size) throw Error('audio_empty');
      const bytes = new Uint8Array(size); let at = 0; for (const part of parts) { bytes.set(part, at); at += part.byteLength; }
      return { bytes, mime };
    }
    function audioURL(value) {
      if (typeof value !== 'string' || value.length > 2048) throw Error('audio_url_invalid');
      const target = new URL(value, base), prefix = new URL('api/voice/audio/', base).pathname;
      if (target.origin !== base.origin || !target.pathname.startsWith(prefix) || target.username || target.password || target.hash) throw Error('audio_origin_invalid');
      return target;
    }
    async function run(eventId, token, profileRole = null) {
      const mission = context().missionId;
      const profileTest = profileRole !== null;
      if (profileTest && !ROLES.has(profileRole)) return unavailable('invalid_voice_profile');
      if (!allowed || (profileTest ? !MID.test(mission || '') : !identity(mission, eventId))) return unavailable('not_enabled');
      stop(); const run = epoch, controller = request = new AbortController();
      if (!isCurrent(run, mission, token)) { stop(); return unavailable('cancelled'); }
      guard = repeat(() => { if (!isCurrent(run, mission, token)) stop(); }, 75);
      const deadline = later(() => controller.abort(), 20000);
      try {
        let narration, generated;
        if (profileTest) {
          // Explicit audition only: no mission event, free text, provider voice ID or fake activity.
          generated = await json('test', controller.signal, { role: profileRole });
          if (!isCurrent(run, mission, token)) return unavailable('cancelled');
          narration = await validateProfileTest(generated, profileRole);
          onStatus('TEST DE VOIX · ' + PROFILE_NAMES[profileRole] + ' · audition hors activité de mission.');
        } else {
          narration = await validateNarration(await json('narration?mission_id=' + encodeURIComponent(mission) + '&event_id=' + eventId, controller.signal), mission, eventId);
          if (!isCurrent(run, mission, token)) return unavailable('cancelled');
          onNarration(narration);
          // Identities only. Browser text, provider voice IDs and instructions are never sent.
          generated = await json('generate', controller.signal, { mission_id: mission, event_id: eventId });
        }
        if (!isCurrent(run, mission, token)) return unavailable('cancelled');
        if (!generated || generated.available !== true || (!profileTest && (generated.mission_id !== mission || generated.event_id !== eventId)) ||
          generated.narration_sha256 !== narration.narration_sha256 || generated.voice_role !== narration.voice_role ||
          !generated.audio || !SHA.test(generated.audio.sha256 || '') || !MIME.has(generated.audio.mime_type)) throw Error('generated_audio_invalid');
        const expires = generated.audio.expires_at;
        if (!Number.isFinite(expires) || expires * 1000 <= now() || expires * 1000 > now() + 300000) throw Error('audio_expired');
        const response = await fetcher(audioURL(generated.audio.url).href, { method: 'GET', credentials: 'same-origin', cache: 'no-store',
          redirect: 'error', mode: 'same-origin', signal: controller.signal, headers: { Accept: generated.audio.mime_type } });
        if (response.status === 401 || response.status === 403) { disable('Accès audio expiré. Réactivez la voix après connexion.'); return unavailable('session_expired'); }
        const { bytes, mime } = await audioBytes(response, controller.signal);
        if (mime !== generated.audio.mime_type || await digest(bytes) !== generated.audio.sha256) throw Error('audio_digest_mismatch');
        if (!isCurrent(run, mission, token) || expires * 1000 <= now()) return unavailable('cancelled');
        objectURL = createObjectURL(new Blob([bytes], { type: mime })); const currentAudio = audio = createAudio(objectURL); cancelLater(deadline);
        const played = await new Promise(resolve => {
          let done = false;
          const finish = okay => { if (done) return; done = true; if (resolveCurrent === finish) resolveCurrent = null; resolve(okay); };
          resolveCurrent = finish; currentAudio.preload = 'none';
          currentAudio.onplaying = () => {
            if (!isCurrent(run, mission, token) || now() >= expires * 1000) { stop(); return; }
            const actor = profileTest || narration.voice_role === 'system' ? 'journal' : narration.voice_role === 'cto' ? 'main' : narration.voice_role;
            onCaption(actor, narration.text, Math.min(60000, Math.max(500, narration.text.length * 75)));
          };
          currentAudio.onended = () => finish(true); currentAudio.onerror = () => finish(false);
          finishTimer = later(() => { finish(false); stop(); }, Math.min(60000, expires * 1000 - now()));
          try { Promise.resolve(currentAudio.play()).catch(() => finish(false)); } catch { finish(false); }
        });
        if (!played && isCurrent(run, mission, token)) onStatus('Audio non lu. Le suivi continue en texte ; vérifiez le son avant de reprendre.');
        return { okay: played };
      } catch (error) {
        if (run === epoch) onStatus(profileTest ? 'Test de voix indisponible ou non vérifié. Aucune activité de mission créée ; aucun nouvel essai automatique.' : 'Narration indisponible ou non vérifiée. Le suivi continue en texte ; aucun nouvel essai automatique.');
        return unavailable(error.message || 'voice_unavailable');
      } finally { cancelLater(deadline); if (epoch === run) stop(); }
    }
    return { enable, play: (eventId, token) => run(eventId, token), testProfile: (role, token) => run(null, token, role),
      stop, disable, get enabled() { return allowed; }, dispose() { disposed = true; disable(); } };
  }
  return { createController, normalized, identity, PROFILE_NAMES };
});

// Classic-script adapter for the existing La Danse player. Replaces the old awema-voice.js.
if (typeof window === 'object' && typeof document === 'object') (() => {
  'use strict';
  const banner = document.querySelector('.awema-prototype-banner'), panel = document.getElementById('awema-display-panel');
  if (!banner || !panel || typeof S === 'undefined' || typeof AUD === 'undefined') return;
  const core = window.AWEMADanseVoiceCore, synth = window.speechSynthesis, Utterance = window.SpeechSynthesisUtterance;
  const node = (tag, text) => { const n = document.createElement(tag); if (text) n.textContent = text; return n; };
  const button = node('button', 'Activer les voix'); button.id = 'awema-voice'; button.type = 'button'; button.setAttribute('aria-pressed', 'false'); banner.append(button);
  const heading = node('h3', 'Lecture vocale'), notice = node('p'); notice.id = 'awema-voice-status'; notice.setAttribute('role', 'status');
  const provider = node('select'); provider.id = 'awema-voice-provider'; provider.setAttribute('aria-label', 'Moteur de lecture vocale');
  provider.append(new Option('Voix française locale · gratuite', 'local'), new Option('ElevenLabs · option serveur', 'elevenlabs'));
  const select = node('select'); select.id = 'awema-voice-select'; select.setAttribute('aria-label', 'Voix française locale');
  const test = node('button', 'Tester la voix locale'); test.id = 'awema-voice-test'; test.type = 'button'; test.disabled = true;
  const profile = node('select'); profile.id = 'awema-voice-profile'; profile.hidden = true;
  profile.setAttribute('aria-label', 'Profil vocal à écouter · test hors mission');
  for (const [role, name] of Object.entries(core.PROFILE_NAMES)) profile.append(new Option(name + ' · test vocal', role));
  const consentLabel = node('label'); consentLabel.id = 'awema-voice-consent-label'; consentLabel.hidden = true;
  const consent = node('input'); consent.type = 'checkbox'; consent.id = 'awema-voice-remote-consent';
  consentLabel.append(consent, document.createTextNode(' J’autorise les narrations vérifiées de cette mission et les tests de profils vocaux que je déclenche à utiliser ElevenLabs et le quota configuré. Aucun microphone ni texte libre.'));
  for (const el of [heading, notice, provider, select, profile, test, consentLabel]) panel.insertBefore(el, panel.lastElementChild);
  let enabled = false, voices = [], voiceKey = '', epoch = 0, activeFinish = null, testBusy = false;
  let channel = null; const client = crypto.randomUUID(); try { channel = new BroadcastChannel('awema.standup.local-voice'); } catch {}
  const status = text => { notice.textContent = text; button.title = text; };
  const currentMission = () => String(S.cur?.id || window.AWEMA_SELECTED_MISSION || '');
  const context = () => ({ missionId: currentMission(), token: S.token, hidden: document.hidden,
    offline: navigator.onLine === false || document.documentElement.dataset.awemaOffline === 'true', muted: AUD.off() });
  const digest = async value => [...new Uint8Array(await crypto.subtle.digest('SHA-256', typeof value === 'string' ? new TextEncoder().encode(value) : value))].map(n => n.toString(16).padStart(2, '0')).join('');
  const remote = core.createController({ fetch: window.fetch.bind(window), context, digest, baseURL: new URL('/finance/standup/', location.origin).href,
    createAudio: url => new Audio(url), createObjectURL: blob => URL.createObjectURL(blob), revokeObjectURL: url => URL.revokeObjectURL(url),
    onStatus: status, onCaption: (id, text, ms) => captionRun(id, text, ms),
    onNarration: narration => {
      const actor = narration.voice_role === 'system' ? 'journal' : narration.voice_role === 'cto' ? 'main' : narration.voice_role;
      startTalk(actor, narration.text, narration.provenance.kind === 'attested_worker_report' ? 'Rapport attesté' : 'Journal système');
    } });
  const syncUI = () => {
    const isRemote = provider.value === 'elevenlabs';
    button.textContent = enabled ? 'Couper les voix' : isRemote ? 'Activer ElevenLabs' : 'Activer les voix'; button.setAttribute('aria-pressed', String(enabled));
    profile.hidden = !isRemote; profile.disabled = !enabled || testBusy;
    test.textContent = testBusy ? 'Test vocal en cours…' : isRemote ? 'Tester la voix · ' + core.PROFILE_NAMES[profile.value] : 'Tester la voix locale';
    test.disabled = !enabled || testBusy || (isRemote ? !remote.enabled : !voices.length);
  };
  function stopCurrent() { epoch++; const finish = activeFinish; activeFinish = null; finish?.(false); try { synth?.cancel(); } catch {} remote.stop(); }
  function disable(message) { enabled = false; prefs.voice = false; consent.checked = false; remote.disable(); stopCurrent(); syncUI(); if (message) status(message); }
  function updateVoices() {
    const old = voiceKey;
    voices = synth && Utterance ? synth.getVoices().filter(v => v.localService === true && /^fr(?:[-_]|$)/i.test(v.lang || '')).sort((a, b) => String(a.name).localeCompare(String(b.name))) : [];
    select.replaceChildren(); voices.forEach((v, i) => select.append(new Option(v.name + ' · ' + v.lang, v.voiceURI || String(i))));
    if (!voices.length) select.append(new Option('Aucune voix française locale', ''));
    voiceKey = voices.some((v, i) => (v.voiceURI || String(i)) === old) ? old : (voices[0]?.voiceURI || '0'); select.value = voiceKey;
    select.disabled = !voices.length || provider.value !== 'local'; button.disabled = provider.value === 'local' && !voices.length; syncUI();
    if (!enabled && provider.value === 'local') status(voices.length ? 'Voix française locale disponible. Les jalons sont lus par le journal système ; aucune donnée envoyée à un fournisseur vocal.' : 'Aucune voix française locale disponible. Le suivi reste utilisable en texte. ElevenLabs reste désactivé sans configuration serveur et consentement.');
  }
  provider.onchange = () => { disable(); consentLabel.hidden = provider.value !== 'elevenlabs'; updateVoices(); if (provider.value === 'elevenlabs') status('Option ElevenLabs : cochez le consentement puis activez. Aucun appel n’a encore été effectué. Le serveur peut laisser cette option désactivée.'); };
  select.onchange = () => { stopCurrent(); voiceKey = select.value; };
  profile.onchange = () => { stopCurrent(); syncUI(); };
  consent.onchange = () => { if (!consent.checked && provider.value === 'elevenlabs') disable('Consentement retiré : narration ElevenLabs arrêtée.'); };
  if (channel) channel.onmessage = event => { if (event.data?.type === 'claim' && event.data.client !== client && enabled) disable('Voix désactivées ici : une autre réunion a pris la lecture vocale.'); };
  button.onclick = async () => {
    if (enabled) { disable('Voix coupées. La mission et la relecture continuent en texte.'); return; }
    if (provider.value === 'elevenlabs') {
      if (!consent.checked) { status('Cochez le consentement avant d’activer ElevenLabs. Aucun texte transmis.'); return; }
      button.disabled = true; const result = await remote.enable(true); button.disabled = false;
      if (!result.okay || !consent.checked || provider.value !== 'elevenlabs') { remote.disable(); return; }
    } else { updateVoices(); if (!voices.length || !synth || !Utterance) return; }
    enabled = true; prefs.voice = true; AUD.muted = false; S.owner = CID; syncUI(); channel?.postMessage({ type: 'claim', client });
    if (provider.value === 'local') status('Voix française locale activée. Le journal lit les jalons enregistrés, sans simuler la parole des agents.');
  };
  const selectedVoice = () => voices.find((v, i) => (v.voiceURI || String(i)) === voiceKey) || voices[0];
  function speakChunk(text, token, mine) {
    return new Promise(resolve => {
      if (!enabled || AUD.off() || mine !== epoch || token !== S.token || !selectedVoice()) return resolve(false);
      const utterance = new Utterance(text); let done = false, startTimer, endTimer, watch;
      const finish = okay => { if (done) return; done = true; clearTimeout(startTimer); clearTimeout(endTimer); clearInterval(watch); if (activeFinish === finish) activeFinish = null; utterance.onstart = utterance.onend = utterance.onerror = null; resolve(okay); };
      activeFinish = finish; utterance.voice = selectedVoice(); utterance.lang = utterance.voice.lang; utterance.rate = Math.max(.8, Math.min(1.4, Number(spd()) || 1)); utterance.pitch = 1; utterance.volume = 1;
      utterance.onstart = () => { clearTimeout(startTimer); if (!enabled || mine !== epoch || token !== S.token) { stopCurrent(); return; } captionRun('journal', text, Math.max(500, text.length * 75)); };
      utterance.onend = () => finish(true); utterance.onerror = () => { if (mine === epoch) status('Voix locale interrompue ; le suivi continue en texte.'); finish(false); };
      startTimer = setTimeout(() => { finish(false); try { synth.cancel(); } catch {} status('La voix locale ne démarre pas. Vérifiez le son et utilisez le test local.'); }, 4000);
      endTimer = setTimeout(() => { finish(false); try { synth.cancel(); } catch {} }, 30000);
      watch = setInterval(() => { if (token !== S.token || mine !== epoch || !enabled || AUD.off() || document.hidden || context().offline) { finish(false); try { synth.cancel(); } catch {} } }, 75);
      try { synth.speak(utterance); } catch { finish(false); }
    });
  }
  warmTTS = () => {}; // Never warm up upstream speculative/provider speech.
  speakLine = async function (text, person, primary, token, language, always, event) {
    if (token !== S.token) return;
    if (!enabled || AUD.off() || document.hidden) return sleep(estMs(text));
    if (context().offline) { disable('Observation hors ligne : narration arrêtée.'); return; }
    // Exact recorded event from playOne only. S.idx may already point at the end of a playback group.
    if (!event || !core.identity(currentMission(), event.source_event_id) || !S.events.includes(event)) return;
    if (provider.value === 'elevenlabs') { await remote.play(event.source_event_id, token); if (!remote.enabled) disable(); return; }
    const mine = epoch;
    for (const part of core.normalized(text).match(/.{1,220}(?:\s|$)|\S{1,220}/g) || []) {
      if (token !== S.token || !enabled || mine !== epoch || !await speakChunk(part.trim(), token, mine)) return;
    }
  };
  test.onclick = async () => {
    if (!enabled || testBusy) return;
    pause();
    if (provider.value === 'elevenlabs') {
      if (!consent.checked || !remote.enabled) return;
      testBusy = true; syncUI(); status('TEST DE VOIX · ' + core.PROFILE_NAMES[profile.value] + ' · relecture en pause, aucune activité de mission créée.');
      try { await remote.testProfile(profile.value, S.token); if (!remote.enabled) disable(); }
      finally { testBusy = false; syncUI(); }
    } else { status('Test local du journal. La mission reste en pause.'); await speakChunk('Je lis les jalons enregistrés de la Ruche.', S.token, epoch); }
  };
  const originalPause = pause; pause = function () { stopCurrent(); return originalPause(); };
  const originalApplyMute = applyMute; applyMute = function () { originalApplyMute(); if (AUD.off()) disable('Sourdine activée : narration arrêtée.'); };
  let knownMission = currentMission();
  const missionWatch = setInterval(() => { const mission = currentMission(); if (mission !== knownMission) { knownMission = mission; disable('Mission changée : réactivez les voix pour cette mission.'); } }, 100);
  window.addEventListener('awema-observation-failed', () => disable('Observation interrompue : narration arrêtée.'));
  window.addEventListener('offline', () => disable('Connexion perdue : narration arrêtée.'));
  document.addEventListener('visibilitychange', () => { if (document.hidden) stopCurrent(); });
  const sourceObserver = new MutationObserver(() => { if (context().offline) disable('Source indisponible : narration arrêtée.'); });
  sourceObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-awema-offline'] });
  window.addEventListener('pagehide', () => { disable(); remote.dispose(); sourceObserver.disconnect(); clearInterval(missionWatch); channel?.close(); });
  if (synth?.addEventListener) synth.addEventListener('voiceschanged', updateVoices);
  updateVoices(); setTimeout(updateVoices, 1200);
})();
