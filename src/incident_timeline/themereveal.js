/* ORISECT theme switch with the "water reveal" transition.
 *
 * The theme switch's reveal: the new mode spreads out from the button that
 * chose it like water across the page, a round front, irregular but smooth,
 * its edge gently swelling and receding as it grows, in the new mode's own
 * colours, until it has the whole screen.
 *
 * How: the View Transitions API snapshots the page, the mode is switched
 * underneath, and the new snapshot is uncovered through an animated
 * clip-path polygon (`revealFrames`). Where the API is missing, or the
 * reader asked for reduced motion, the mode simply changes.
 *
 * The theme itself is the data-theme attribute on <html> ("light"; absent
 * means the default dark theme), remembered in localStorage. Each page's
 * <head> applies the saved choice before first paint, so there is no flash.
 * Toggle buttons are any element with [data-theme-toggle].
 */
(function (root) {
  'use strict';

  var POINTS = 180;
  var FRAMES = 24;
  var STORAGE_KEY = 'orisect-theme';
  var THEME_COLORS = { dark: '#090c0a', light: '#f3f5f3' };

  /** A small deterministic generator, so a reveal's shape is stable across its frames. */
  function rng(seed) {
    var s = seed >>> 0 || 1;
    return function () {
      s ^= s << 13;
      s ^= s >>> 17;
      s ^= s << 5;
      return ((s >>> 0) % 100000) / 100000;
    };
  }

  /** The wobble of the front: a few slow, low harmonics, each drifting round as it spreads. */
  function waves(seed) {
    var r = rng(seed);
    return [2, 3, 4, 6].map(function (k, i) {
      return {
        k: k,
        amp: [0.07, 0.055, 0.035, 0.02][i] * (0.75 + r() * 0.5),
        phase: r() * Math.PI * 2,
        drift: (r() - 0.5) * 2.4
      };
    });
  }

  /** Starts gently from the button, spreads steadily, and eases into the corners. */
  function spread(t) { return 0.2 * t + 0.8 * ((1 - Math.cos(Math.PI * t)) / 2); }

  /**
   * The shape at progress `t` (0 to 1): like a drop of water spreading across
   * the page, a soft, round front whose edge swells and recedes in a few slow
   * waves that drift as it grows. The waves are strongest early, where the
   * drop is still finding its shape, and calm as it reaches the corners, so it
   * arrives as a full circle past every edge. Every bulge is wide and smooth:
   * no spikes.
   */
  function revealPolygon(cx, cy, reach, t, seed) {
    var ws = waves(seed);
    var radius = reach * 1.18 * spread(t);
    var calm = 1 - t * 0.85;
    var pts = [];
    for (var i = 0; i < POINTS; i++) {
      var a = (i / POINTS) * Math.PI * 2;
      var wobble = 0;
      for (var j = 0; j < ws.length; j++) wobble += ws[j].amp * Math.sin(ws[j].k * a + ws[j].phase + ws[j].drift * t);
      var r = Math.max(0, radius * (1 + wobble * calm));
      pts.push((cx + Math.cos(a) * r).toFixed(1) + 'px ' + (cy + Math.sin(a) * r).toFixed(1) + 'px');
    }
    return 'polygon(' + pts.join(', ') + ')';
  }

  /** Every frame of a reveal from (cx, cy) across a w × h screen. */
  function revealFrames(cx, cy, w, h, seed) {
    var reach = Math.max(Math.hypot(cx, cy), Math.hypot(w - cx, cy), Math.hypot(cx, h - cy), Math.hypot(w - cx, h - cy));
    var frames = [];
    for (var i = 0; i <= FRAMES; i++) frames.push(revealPolygon(cx, cy, reach, i / FRAMES, seed));
    return frames;
  }

  var revealing = false;

  /**
   * Switch the mode with the reveal, starting from `from` (the button). `apply`
   * changes the page (sets data-theme and remembers the choice). Returns false
   * when a reveal is already running and the request was ignored.
   */
  function revealTheme(from, apply, done) {
    if (revealing) return false;
    var finish = function () { if (done) done(); };
    var doc = document;
    var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (!doc.startViewTransition || reduce || !from) {
      apply();
      finish();
      return true;
    }
    var box = from.getBoundingClientRect();
    var cx = box.left + box.width / 2;
    var cy = box.top + box.height / 2;
    var frames = revealFrames(cx, cy, window.innerWidth, window.innerHeight, Math.floor(Math.random() * 1e9));
    revealing = true;
    document.documentElement.setAttribute('data-theme-reveal', '');
    var vt;
    try {
      vt = doc.startViewTransition(apply);
    } catch (err) {
      document.documentElement.removeAttribute('data-theme-reveal');
      revealing = false;
      apply();
      finish();
      return true;
    }
    vt.ready
      .then(function () {
        document.documentElement.animate(
          { clipPath: frames },
          { duration: 1400, easing: 'linear', pseudoElement: '::view-transition-new(root)' }
        );
      })
      .catch(function () {});
    vt.finished.catch(function () {}).then(function () {
      document.documentElement.removeAttribute('data-theme-reveal');
      revealing = false;
      finish();
    });
    return true;
  }

  /* ---------- ORISECT's theme state ---------- */
  function current() {
    return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  }

  function syncToggles() {
    var theme = current();
    var next = theme === 'light' ? 'dark' : 'light';
    var toggles = document.querySelectorAll('[data-theme-toggle]');
    for (var i = 0; i < toggles.length; i++) {
      toggles[i].setAttribute('aria-label', 'Switch to ' + next + ' theme');
      toggles[i].setAttribute('title', 'Switch to ' + next + ' theme');
    }
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', THEME_COLORS[theme]);
  }

  /** Change the DOM synchronously (the reveal snapshots it as this returns) and remember it. */
  function applyTheme(theme) {
    if (theme === 'light') document.documentElement.setAttribute('data-theme', 'light');
    else document.documentElement.removeAttribute('data-theme');
    try { localStorage.setItem(STORAGE_KEY, theme); } catch (e) { /* private mode: still switches */ }
    syncToggles();
  }

  // Clicks during a reveal aren't lost: they flip the theme the page should end
  // on, and one more reveal runs afterwards if that differs from where it landed.
  var heading = null, pending = null, pendingFrom = null;
  function toggle(from) {
    if (revealing) {
      pending = (pending || heading) === 'light' ? 'dark' : 'light';
      pendingFrom = from || pendingFrom;
      return;
    }
    var next = current() === 'light' ? 'dark' : 'light';
    heading = next;
    revealTheme(from || null, function () { applyTheme(next); }, function () {
      var want = pending; pending = null;
      if (want && want !== current()) toggle(pendingFrom);
    });
  }

  function bind() {
    var toggles = document.querySelectorAll('[data-theme-toggle]');
    for (var i = 0; i < toggles.length; i++) {
      if (toggles[i].dataset.themeBound) continue;
      toggles[i].dataset.themeBound = '1';
      toggles[i].addEventListener('click', function (ev) { toggle(ev.currentTarget); });
    }
    syncToggles();
  }

  var api = { revealPolygon: revealPolygon, revealFrames: revealFrames, revealTheme: revealTheme, applyTheme: applyTheme, toggle: toggle, current: current, bind: bind };
  root.OrisectTheme = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bind);
    else bind();
  }
})(typeof window !== 'undefined' ? window : globalThis);
