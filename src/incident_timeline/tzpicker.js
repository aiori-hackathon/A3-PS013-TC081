/* ORISECT time-zone picker.
 *
 * A matching engine plus an accessible combobox for the "Source time zone" field.
 * Typing "kolkata", "IST", "india", "calcuta", "pacific", "+5:30" or "gmt 530"
 * all lead to a value the server accepts: "UTC", a fixed offset such as
 * "+05:30", or an IANA name such as "Asia/Kolkata" (see timeutil.resolve_tz).
 *
 * The engine (OrisectTZ.search / resolve / parseOffset) has no DOM dependency, so
 * it also runs under Node for tests.
 */
(function (root) {
  'use strict';

  /* ---------- Candidate zones ---------- */
  const FALLBACK_ZONES = [
    'Africa/Cairo', 'Africa/Johannesburg', 'Africa/Lagos', 'Africa/Nairobi', 'America/Anchorage',
    'America/Argentina/Buenos_Aires', 'America/Bogota', 'America/Chicago', 'America/Denver',
    'America/Halifax', 'America/Los_Angeles', 'America/Mexico_City', 'America/New_York',
    'America/Phoenix', 'America/Sao_Paulo', 'America/St_Johns', 'America/Toronto', 'America/Vancouver',
    'Asia/Bangkok', 'Asia/Colombo', 'Asia/Dhaka', 'Asia/Dubai', 'Asia/Hong_Kong', 'Asia/Jakarta',
    'Asia/Jerusalem', 'Asia/Karachi', 'Asia/Kathmandu', 'Asia/Kolkata', 'Asia/Manila', 'Asia/Riyadh',
    'Asia/Seoul', 'Asia/Shanghai', 'Asia/Singapore', 'Asia/Taipei', 'Asia/Tehran', 'Asia/Tokyo',
    'Atlantic/Reykjavik', 'Australia/Adelaide', 'Australia/Brisbane', 'Australia/Perth',
    'Australia/Sydney', 'Europe/Amsterdam', 'Europe/Athens', 'Europe/Berlin', 'Europe/Dublin',
    'Europe/Istanbul', 'Europe/Kyiv', 'Europe/Lisbon', 'Europe/London', 'Europe/Madrid',
    'Europe/Moscow', 'Europe/Paris', 'Europe/Rome', 'Europe/Stockholm', 'Europe/Warsaw',
    'Europe/Zurich', 'Pacific/Auckland', 'Pacific/Honolulu'
  ];

  // Abbreviations, countries, states and cities that aren't IANA names themselves.
  const ALIASES = {
    'Asia/Kolkata': 'ist india indian calcutta delhi new delhi mumbai bombay bangalore bengaluru chennai madras hyderabad pune ahmedabad kochi howrah shibpur',
    'Asia/Karachi': 'pkt pakistan lahore islamabad',
    'Asia/Dhaka': 'bangladesh dacca',
    'Asia/Kathmandu': 'npt nepal katmandu',
    'Asia/Colombo': 'sri lanka slst',
    'Asia/Dubai': 'gst uae emirates abu dhabi gulf',
    'Asia/Riyadh': 'saudi arabia ast',
    'Asia/Tehran': 'iran irst',
    'Asia/Jerusalem': 'israel tel aviv',
    'Asia/Shanghai': 'china cst beijing peking prc shenzhen guangzhou',
    'Asia/Hong_Kong': 'hkt hongkong',
    'Asia/Taipei': 'taiwan',
    'Asia/Tokyo': 'jst japan osaka',
    'Asia/Seoul': 'kst korea south korea',
    'Asia/Singapore': 'sgt',
    'Asia/Bangkok': 'ict thailand vietnam hanoi ho chi minh',
    'Asia/Jakarta': 'wib indonesia',
    'Asia/Manila': 'pht philippines',
    'Europe/London': 'gmt bst uk britain british england united kingdom scotland wales',
    'Europe/Dublin': 'ireland',
    'Europe/Paris': 'cet cest france',
    'Europe/Berlin': 'germany frankfurt munich',
    'Europe/Amsterdam': 'netherlands holland',
    'Europe/Madrid': 'spain barcelona',
    'Europe/Rome': 'italy milan',
    'Europe/Zurich': 'switzerland geneva',
    'Europe/Stockholm': 'sweden',
    'Europe/Warsaw': 'poland',
    'Europe/Athens': 'eet eest greece',
    'Europe/Istanbul': 'turkey trt',
    'Europe/Kyiv': 'ukraine kiev',
    'Europe/Moscow': 'msk russia st petersburg',
    'Africa/Cairo': 'egypt',
    'Africa/Johannesburg': 'sast south africa cape town',
    'Africa/Lagos': 'wat nigeria',
    'Africa/Nairobi': 'eat kenya',
    'America/New_York': 'est edt eastern us east east coast new york nyc boston washington dc miami atlanta',
    'America/Chicago': 'cst cdt central us central texas dallas houston',
    'America/Denver': 'mst mdt mountain',
    'America/Phoenix': 'arizona',
    'America/Los_Angeles': 'pst pdt pacific us west west coast california san francisco seattle la',
    'America/Anchorage': 'akst alaska',
    'Pacific/Honolulu': 'hst hawaii',
    'America/Toronto': 'canada ontario ottawa',
    'America/Vancouver': 'british columbia',
    'America/Halifax': 'atlantic nova scotia',
    'America/St_Johns': 'newfoundland nst',
    'America/Mexico_City': 'mexico',
    'America/Sao_Paulo': 'brt brazil rio',
    'America/Argentina/Buenos_Aires': 'art argentina',
    'America/Bogota': 'colombia',
    'Australia/Sydney': 'aest aedt australia melbourne canberra',
    'Australia/Brisbane': 'queensland',
    'Australia/Perth': 'awst western australia',
    'Australia/Adelaide': 'acst',
    'Pacific/Auckland': 'nzst nzdt new zealand nz wellington',
    'Atlantic/Reykjavik': 'iceland'
  };
  // Zones most people mean; a small tie-break boost.
  const POPULAR = new Set(['Asia/Kolkata', 'Europe/London', 'America/New_York', 'America/Los_Angeles',
    'America/Chicago', 'Europe/Berlin', 'Europe/Paris', 'Asia/Tokyo', 'Asia/Singapore', 'Asia/Dubai',
    'Australia/Sydney', 'Asia/Shanghai']);

  const norm = s => String(s).toLowerCase().replace(/[_/\-.,()]+/g, ' ').replace(/\s+/g, ' ').trim();

  // Chrome and Safari still report some zones by their pre-2020 names.
  const LINKS = {
    'Asia/Calcutta': 'Asia/Kolkata', 'Asia/Katmandu': 'Asia/Kathmandu', 'Europe/Kiev': 'Europe/Kyiv',
    'Asia/Saigon': 'Asia/Ho_Chi_Minh', 'Asia/Rangoon': 'Asia/Yangon', 'America/Buenos_Aires': 'America/Argentina/Buenos_Aires',
    'Asia/Dacca': 'Asia/Dhaka', 'Asia/Thimbu': 'Asia/Thimphu', 'Atlantic/Faeroe': 'Atlantic/Faroe',
    'America/Godthab': 'America/Nuuk', 'Pacific/Enderbury': 'Pacific/Kanton'
  };
  function zoneList() {
    let all = [];
    try { all = Intl.supportedValuesOf('timeZone') || []; } catch (_) { /* older browsers */ }
    return [...new Set([...all.map(z => LINKS[z] || z), ...FALLBACK_ZONES])];
  }

  function fmtOffset(minutes) {
    const sign = minutes < 0 ? '-' : '+', m = Math.abs(minutes);
    return `${sign}${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`;
  }

  // Current UTC offset of a zone in minutes, or null if the runtime can't tell.
  function zoneOffset(zone, at = new Date()) {
    try {
      const part = new Intl.DateTimeFormat('en-US', { timeZone: zone, timeZoneName: 'shortOffset' })
        .formatToParts(at).find(p => p.type === 'timeZoneName');
      const m = part && /GMT(?:([+-])(\d{1,2})(?::(\d{2}))?)?/.exec(part.value);
      if (!m) return null;
      if (!m[1]) return 0;
      const v = Number(m[2]) * 60 + Number(m[3] || 0);
      return m[1] === '-' ? -v : v;
    } catch (_) { return null; }
  }

  function zoneLongName(zone) {
    try {
      const part = new Intl.DateTimeFormat('en-US', { timeZone: zone, timeZoneName: 'long' })
        .formatToParts(new Date()).find(p => p.type === 'timeZoneName');
      return part && !/^GMT/.test(part.value) ? part.value : '';
    } catch (_) { return ''; }
  }

  let INDEX = null;
  function index() {
    if (INDEX) return INDEX;
    INDEX = [{ value: 'UTC', label: 'UTC', detail: 'Coordinated Universal Time', offset: 0, keys: ['utc', 'z', 'gmt', 'zulu', 'universal', 'coordinated universal time'], popular: true }];
    for (const zone of zoneList()) {
      if (zone === 'UTC' || /^Etc\//.test(zone)) continue;
      const parts = zone.split('/'), city = parts[parts.length - 1].replace(/_/g, ' ');
      const longName = zoneLongName(zone);
      const keys = [norm(city), norm(zone), ...parts.map(norm)];
      if (longName) keys.push(norm(longName));
      keys.push(...splitAliases(ALIASES[zone]));
      INDEX.push({ value: zone, label: zone.replace(/_/g, ' '), detail: longName, offset: zoneOffset(zone), keys, popular: POPULAR.has(zone) });
    }
    return INDEX;
  }
  // Alias strings list single words and multi-word names; keep both forms searchable.
  function splitAliases(text) {
    if (!text) return [];
    const words = text.split(' ');
    const out = new Set(words);
    for (let i = 0; i < words.length - 1; i++) out.add(words[i] + ' ' + words[i + 1]);
    for (let i = 0; i < words.length - 2; i++) out.add(words[i] + ' ' + words[i + 1] + ' ' + words[i + 2]);
    return [...out];
  }

  /* ---------- Offsets typed by hand: "+5:30", "gmt+0530", "utc 5.5", "-8" ---------- */
  function parseOffset(text) {
    const s = String(text).trim().toLowerCase().replace(/\s+/g, '');
    const m = /^(?:utc|gmt)?([+-])?(\d{1,2})(?:[:.]?(\d{2})|\.(\d))?$/.exec(s);
    if (!m || (!m[1] && !/^(utc|gmt)/.test(s) && !/[:.]/.test(s))) return null;
    let minutes = Number(m[2]) * 60;
    if (m[3]) minutes += Number(m[3]);
    if (m[4]) minutes += Math.round(Number('0.' + m[4]) * 60);
    if (m[3] && Number(m[3]) >= 60) return null;
    if (minutes > 14 * 60) return null;
    return m[1] === '-' ? -minutes : minutes;
  }

  /* ---------- Scoring ---------- */
  function editDistance(a, b, max) {
    // Damerau–Levenshtein (optimal string alignment), with an early exit past `max`.
    if (Math.abs(a.length - b.length) > max) return max + 1;
    const prev2 = new Array(b.length + 1), prev = new Array(b.length + 1), cur = new Array(b.length + 1);
    for (let j = 0; j <= b.length; j++) prev[j] = j;
    for (let i = 1; i <= a.length; i++) {
      cur[0] = i; let best = cur[0];
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) cur[j] = Math.min(cur[j], prev2[j - 2] + 1);
        if (cur[j] < best) best = cur[j];
      }
      if (best > max) return max + 1;
      for (let j = 0; j <= b.length; j++) { prev2[j] = prev[j]; prev[j] = cur[j]; }
    }
    return prev[b.length];
  }
  const typoBudget = n => (n <= 3 ? 0 : n <= 5 ? 1 : n <= 9 ? 2 : 3);

  function scoreKey(q, key) {
    if (key === q) return 100;
    if (key.startsWith(q)) return 92 - Math.min(10, key.length - q.length) * 0.5;
    const words = key.split(' ');
    if (words.some(w => w.startsWith(q))) return 82;
    if (q.includes(' ') && key.includes(q)) return 76;
    if (key.replace(/ /g, '').startsWith(q.replace(/ /g, ''))) return 74;
    if (q.length >= 3 && key.includes(q)) return 64;
    const budget = typoBudget(q.length);
    if (budget) {
      let best = Infinity;
      for (const w of [key, ...words]) {
        const head = w.slice(0, q.length + 1);
        best = Math.min(best, editDistance(q, w, budget), editDistance(q, head, budget) + 0.5);
      }
      if (best <= budget) return 58 - best * 8;
    }
    return 0;
  }

  /**
   * Best matches for what the user typed, highest first.
   * Each result: { value, label, detail, offset, score }.
   */
  function search(query, limit = 8) {
    const q = norm(query);
    const zones = index();
    if (!q) return zones.filter(z => z.popular).slice(0, limit).map(z => ({ ...z, score: 0 }));
    const results = [];
    const typedOffset = parseOffset(query);
    if (typedOffset !== null) {
      const value = typedOffset === 0 ? 'UTC' : fmtOffset(typedOffset);
      results.push({ value, label: value === 'UTC' ? 'UTC' : `UTC${value}`, detail: 'Fixed offset, no daylight saving', offset: typedOffset, score: 101 });
      for (const z of zones) if (z.offset === typedOffset && z.value !== 'UTC') results.push({ ...z, score: 70 + (z.popular ? 5 : 0) });
    }
    for (const z of zones) {
      let best = 0;
      for (const key of z.keys) { const s = scoreKey(q, key); if (s > best) best = s; if (best === 100) break; }
      if (best > 0) results.push({ ...z, score: best + (z.popular ? 3 : 0) });
    }
    const seen = new Set(), out = [];
    for (const r of results.sort((a, b) => b.score - a.score || a.label.localeCompare(b.label))) {
      if (seen.has(r.value)) continue;
      seen.add(r.value); out.push(r);
      if (out.length >= limit) break;
    }
    return out;
  }

  /** The value the server should receive for what was typed, or null if nothing fits well. */
  function resolve(query) {
    const raw = String(query).trim();
    if (!raw) return null;
    const exact = index().find(z => z.value.toLowerCase() === raw.toLowerCase());
    if (exact) return exact.value;
    const off = parseOffset(raw);
    if (off !== null) return off === 0 ? 'UTC' : fmtOffset(off);
    const [top] = search(raw, 1);
    return top && top.score >= 50 ? top.value : null;
  }

  function isValid(value) {
    const v = String(value).trim();
    return !!v && (index().some(z => z.value === v) || /^[+-]\d{2}:\d{2}$/.test(v));
  }

  const engine = { search, resolve, isValid, parseOffset, fmtOffset, _index: index };

  /* ---------- Combobox UI ---------- */
  let uid = 0;
  function attach(input, { onChange } = {}) {
    if (typeof document === 'undefined') return;
    const id = `tzp-${++uid}`;
    const list = document.createElement('ul');
    list.className = 'tzp-list'; list.id = id + '-list'; list.setAttribute('role', 'listbox'); list.hidden = true;
    list.addEventListener('click', ev => ev.stopPropagation());
    list.addEventListener('pointerdown', ev => ev.preventDefault()); // scrollbar drags keep the input focused
    const status = document.createElement('span');
    status.className = 'tzp-status'; status.id = id + '-status'; status.setAttribute('aria-live', 'polite');
    input.insertAdjacentElement('afterend', status);
    input.setAttribute('role', 'combobox');
    input.setAttribute('aria-autocomplete', 'list');
    input.setAttribute('aria-expanded', 'false');
    input.setAttribute('aria-controls', list.id);
    input.setAttribute('aria-describedby', [input.getAttribute('aria-describedby'), status.id].filter(Boolean).join(' '));
    input.spellcheck = false;
    let items = [], active = -1;

    const place = () => {
      const r = input.getBoundingClientRect();
      const below = window.innerHeight - r.bottom, above = r.top;
      const height = Math.min(320, Math.max(below, above) - 16);
      list.style.left = `${r.left}px`;
      list.style.width = `${Math.max(r.width, 280)}px`;
      list.style.maxHeight = `${height}px`;
      if (below < 200 && above > below) { list.style.top = ''; list.style.bottom = `${window.innerHeight - r.top + 6}px`; }
      else { list.style.bottom = ''; list.style.top = `${r.bottom + 6}px`; }
    };
    const setActive = i => {
      active = i;
      [...list.children].forEach((li, n) => li.setAttribute('aria-selected', String(n === i)));
      if (i >= 0 && list.children[i]) {
        input.setAttribute('aria-activedescendant', list.children[i].id);
        list.children[i].scrollIntoView({ block: 'nearest' });
      } else input.removeAttribute('aria-activedescendant');
    };
    const open = () => {
      // Inside a modal dialog the list must live in the dialog, or it renders behind it and can't be clicked.
      const host = input.closest('dialog') || document.body;
      if (list.parentElement !== host) host.append(list);
      place(); list.hidden = false; input.setAttribute('aria-expanded', 'true');
    };
    const close = () => { list.hidden = true; input.setAttribute('aria-expanded', 'false'); setActive(-1); };
    const render = () => {
      items = search(input.value);
      list.replaceChildren(...items.map((it, n) => {
        const li = document.createElement('li');
        li.id = `${id}-o${n}`; li.setAttribute('role', 'option'); li.className = 'tzp-option';
        const main = document.createElement('span'); main.className = 'tzp-label'; main.textContent = it.label;
        const off = document.createElement('span'); off.className = 'tzp-offset';
        off.textContent = it.offset === null || it.offset === undefined ? '' : (it.offset === 0 ? 'UTC' : 'UTC' + fmtOffset(it.offset));
        li.append(main, off);
        if (it.detail) { const d = document.createElement('span'); d.className = 'tzp-detail'; d.textContent = it.detail; li.append(d); }
        // Keep focus in the input on press; choose on the full click so the release
        // can't land on whatever sits behind the list (a dialog would read it as
        // a click on its backdrop and close).
        li.addEventListener('pointerdown', ev => ev.preventDefault());
        li.addEventListener('click', ev => { ev.stopPropagation(); choose(n); });
        return li;
      }));
      if (!items.length) {
        const li = document.createElement('li'); li.className = 'tzp-empty';
        li.textContent = 'No matching time zone. Try a city, country, abbreviation or an offset like +05:30.';
        list.append(li);
      }
      setActive(items.length && input.value.trim() ? 0 : -1);
    };
    const validate = () => {
      const ok = isValid(input.value);
      input.setAttribute('aria-invalid', String(!ok && !!input.value.trim()));
      status.textContent = ok || !input.value.trim() ? '' : 'Not a recognised time zone. Pick one from the list.';
      return ok;
    };
    const commit = value => {
      input.value = value; validate(); close();
      if (onChange) onChange(value);
    };
    const choose = n => { if (items[n]) commit(items[n].value); };

    input.addEventListener('focus', () => { render(); open(); setActive(-1); input.select(); });
    input.addEventListener('input', () => { render(); open(); status.textContent = ''; input.removeAttribute('aria-invalid'); if (onChange) onChange(input.value); });
    input.addEventListener('keydown', ev => {
      if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
        ev.preventDefault();
        if (list.hidden) { render(); open(); }
        const n = items.length; if (!n) return;
        setActive(ev.key === 'ArrowDown' ? (active + 1) % n : (active - 1 + n) % n);
      } else if (ev.key === 'Enter') {
        if (!list.hidden && active >= 0) { ev.preventDefault(); choose(active); }
      } else if (ev.key === 'Escape') {
        if (!list.hidden) { ev.preventDefault(); ev.stopPropagation(); close(); }
      } else if (ev.key === 'Tab' && !list.hidden && active >= 0 && input.value.trim() && !isValid(input.value)) {
        choose(active); // smart autofill: Tab accepts the best match for a partial entry
      }
    });
    input.addEventListener('blur', () => {
      // Snap a near-miss ("kolkatta", "ist", "+530") to the value it clearly means.
      const typed = input.value.trim();
      if (typed && !isValid(typed)) { const r = resolve(typed); if (r) { commit(r); return; } }
      validate(); close();
    });
    live.add({ input, list, place });
    return { validate, close };
  }
  // One listener for every picker: keep open lists under their input, drop removed ones.
  const live = new Set();
  function repositionAll() {
    for (const p of live) {
      if (!p.input.isConnected) { p.list.remove(); live.delete(p); }
      else if (!p.list.hidden) p.place();
    }
  }
  if (typeof window !== 'undefined' && typeof document !== 'undefined') {
    window.addEventListener('resize', repositionAll);
    document.addEventListener('scroll', repositionAll, true);
  }

  engine.attach = attach;
  root.OrisectTZ = engine;
  if (typeof module !== 'undefined' && module.exports) module.exports = engine;
})(typeof window !== 'undefined' ? window : globalThis);
