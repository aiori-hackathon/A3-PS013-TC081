# TRACEFUSE UI audit and redesign

Audit of the web UI at `24f62b0` (welcome page, demo picker, investigation dashboard, Engine Validation Lab), with what this branch changed. Evidence comes from the rendered pages at 1440px and 390px, axe-core 4.10 and the source.

**Brand kept:** graphite surfaces and the lime signal colour (`#d8ff63`) already used on every page. What changed is *how* lime is used: it now marks only the primary action, focus and selection.

**Workflows kept:** upload, demo cases, filters, original-line verification, JSON/PDF export, the triage time study, the Timeline Confidence Lab and the Engine lab. The same routes and APIs are used, and browser storage keys are unchanged.

## Design system

`src/incident_timeline/tracefuse.css` is now shared by every page (served at `/tracefuse.css`):

| Layer | Tokens / classes |
| --- | --- |
| Surfaces | `--tf-bg`, `--tf-surface`, `--tf-surface-2/3`, `--tf-sunken`, `--tf-border(-strong/-input)` |
| Text | `--tf-text`, `--tf-text-2`, `--tf-text-3` (all ≥ 5.6:1 on every surface) |
| Signal | `--tf-accent` (primary action, focus, selection only) |
| Semantic | `--tf-ok`, `--tf-warn`, `--tf-bad` (+ `-soft`) for outcomes, severity and integrity |
| Type | `--tf-font`, `--tf-mono` (evidence: times, IDs, hashes, line refs), scale `12 / 13 / 15 / 17 / 21 / 28 / 30–40px` |
| Buttons | `.tf-btn` + `--primary`, `--ghost`, `--sm`, `--lg`, `.tf-link`; disabled, `aria-busy` and `aria-pressed` states |
| Fields | `.tf-field`, `.tf-label`, `.tf-input`, `.tf-select`, `.tf-hint`, `.tf-check` |
| Containers | `.tf-panel` (single elevation), `.tf-well` (raw evidence), `.tf-note` (status), `.tf-badge` (status only), `.tf-disclosure` |
| Motion | Colour and border transitions only (140ms); `prefers-reduced-motion` removes them. |

## Findings

Severity: **high** = misleads, breaks a workflow or undermines credibility; **medium** = clearly generic or inconsistent; **low** = polish.

### Functional issues found during the audit

| Component / location | Existing | Why it matters | Change | Severity |
| --- | --- | --- | --- | --- |
| Demo investigations, `/case/CASE-…` (`web.py`) | Route required the case folder to sit directly under the cases root; demo cases are nested at `demo-scenarios/<id>/case`. | Every link on `/demo` returned `{"error": "Investigation not found"}`. The main demo path was broken. | Accept any case inside the cases root. Regression test added. | High |
| Dashboard, all pages | Backend computes findings, entities, custody and unparsed lines (`/api/insights`, `/api/custody`, `/api/gaps`). The UI never requested them, but the README described them. | The product's strongest, most distinctive evidence (explainable findings with ATT&CK references and source lines) was invisible. | Findings panel first, with **Show evidence** scoping the timeline (and JSON export) to cited lines. Added *Who and where*, *Chain of custody* and *Unparsed lines* panels. | High |
| Uploaded case title | Dashboard showed `CASE-30a5b91303da`; the investigation name the user typed was stored but never displayed. | Users can't recognise their own case. | `/api/summary` returns `case_name`; it becomes the title with the ID as context. | Medium |
| Engine lab "← Back to investigation" | Linked to `/` (the welcome page in app mode). | Label didn't match the destination. | "Home" by default; "Back to investigation" only when arriving from a case. | Low |

### 1. Layout

| Component / location | Existing | Why it feels generic or unnecessary | Recommended / implemented | Severity |
| --- | --- | --- | --- | --- |
| `dashboard.html`, whole file | 15 `<style>` blocks, each a full re-theme (navy → field-workbench → charcoal → "editorial console" → "award v2" → readability pass with `!important`…). Six scripts, several of which move sections, inject a section, delete it again and rewrite headings after load. | The final look came from cascade accidents, not decisions. 2,500 lines, impossible to maintain, and the layout shifted after load. | One stylesheet on shared tokens and one script. The final structure is written in the HTML. 2,515 → 1,155 lines, including the new findings, entity, custody and unparsed-line panels. | High |
| Dashboard header | Hero band plus four equal stat cards, the first filled lime. | Bento-style KPI cards; lime fill on "Timeline events" signals nothing. | Case title with an inline facts row (events, sources, unparsed lines, UTC window) and one integrity status block with semantic colour. | Medium |
| Dashboard page order | Timeline → triage benchmark (marketing heading) → time lab → "Curious how TRACEFUSE performs?" promo banner. | Synthetic-benchmark promotion inside a forensic case view; 11,000px tall on mobile. | Findings → timeline + context → Timeline Confidence Lab → triage study (collapsed by default). Promo replaced by an "Engine lab" link in the app bar. Mobile height ~7,600px. | Medium |
| Welcome page | Large headline over two symmetric choice cards with icon tiles and "01 / INVESTIGATE" / "02 / EXPLORE" labels; a "01 / 02 / 03" trust row. | Classic AI landing template: symmetric cards, numbered labels and abstract trust claims. | Two-column hero: concrete copy on the left; on the right, real engine output for synthetic scenario 01 (finding, ATT&CK ID, the four cited log lines, hash status). A three-step process with specifics replaces the trust row. | Medium |

### 2. Buttons

| Component / location | Existing | Why | Recommended / implemented | Severity |
| --- | --- | --- | --- | --- |
| All pages | Eight separate button styles (`.button`, `.btn`, `.smallbtn`, `.bench-timer`, `.bench-reset`, `.tlab-btn`, `.tlab-inspect-btn`, `.engine-test-cta-link`), each with different heights, radii and hover effects. | No system; the same action looked different in every section. | One `.tf-btn` with primary / secondary / ghost, `sm` / `lg`, and disabled, busy (spinner) and pressed states. `.tf-link` for inline text actions. | High |
| Hover behaviour | `translateY(-1…-3px)` lifts, glow shadows, an icon that rotates 180° on hover, GSAP pointer lifts on cards. | Decorative motion that adds no information. | Hover changes background and border only. | Medium |
| Arrows and glyph icons | `↗` on every welcome button (pushed to the far edge) and as list bullets; `▶ Run full suite`, `↓`, `↻`, `→`. | Repeated arrows read as template filler and emoji-like glyphs render inconsistently. | No trailing arrows. SVG icons only where they add meaning (download, refresh, close). | Medium |
| Action hierarchy | Up to four lime-filled elements in view at once (PDF export, first stat card, "Observed difference" card, "Explore the Engine Lab"). | Lime meant both "click here" and decoration, so nothing was clearly primary. | One primary per view: **PDF report** on the dashboard, **Start an investigation** on the welcome page, **Run full suite** in the lab. | High |
| Welcome buttons | Full-width card buttons. | Oversized controls with weak hierarchy. | Normal-width primary and secondary pair; full width only on mobile. | Low |

### 3. Cards and containers

| Component / location | Existing | Why | Recommended / implemented | Severity |
| --- | --- | --- | --- | --- |
| Timeline event | Each event was a card containing an "Original evidence · Line N" card that repeated the same help sentence and a bordered button. | Card within a card on every row; the repeated copy is noise. | Log-style rows: UTC time column on a rail, monospace action, outcome badge, key/value metadata, and a one-line `S001 · auth.log : line 4  View original line`. | Medium |
| Panels | Gradient fills, `backdrop-filter` glass, `:before` accent stripes on stats, rows and banners, a decorative concentric-circle ornament, mixed radii (9–20px) and shadows. | Meaningless accents and inconsistent elevation. | `.tf-panel` (one surface, 12px radius, no shadow), `.tf-well` for raw evidence, and dividers rather than nested boxes. Only the dialog has a shadow. | Medium |
| Decorative marks | Glyph tiles (`◫`, `◷`, `↗`) on metrics, "02" / "TL" / "03" kicker chips, "FIELD NOTE / TRIAGE STUDY" stamp, "NO SYNTHETIC CONFIDENCE SCORE" pill. | Ornament that carries no information. | Removed. | Low |

### 4. Typography

| Component / location | Existing | Why | Recommended / implemented | Severity |
| --- | --- | --- | --- | --- |
| Type scale | 8–10px uppercase tracked labels, later overridden to 13–15px with dozens of `!important` rules; headings at −0.055 to −0.065em tracking. | Illegible microcopy, then a patch on a patch. Over-tight display tracking is a stock "AI landing" look. | Token scale from 12 to 40px; sentence-case labels; heading tracking from −0.015 to −0.035em. | Medium |
| Evidence data | Timestamps, hashes and IDs in the proportional face. | Hard to scan or compare. | `--tf-mono` for times, actions, IPs, hashes and `source:line` references. | Medium |
| Accent words | Lime-highlighted halves of headings ("evidence.", "Prove the gain.", "Inspect the evidence."). | Repeated highlight-word trick. | Removed. | Low |

### 5. Colour

| Component / location | Existing | Why | Recommended / implemented | Severity |
| --- | --- | --- | --- | --- |
| Semantic colour | `--blue` was redefined to lime; lime also meant "success", the brand, the "assisted" chart series and decoration. | The success state was indistinguishable from the brand and from "clickable". | `--tf-ok`, `--tf-warn` and `--tf-bad` for outcomes, severity, integrity and chain status; lime reserved for action, focus and selection. | Medium |
| Glows | Blurred ambient blobs, radial body gradients, glow box-shadows on dots and bars. | Decorative glow. | Removed. | Low |

### 6. Components

| Component / location | Existing | Why | Recommended / implemented | Severity |
| --- | --- | --- | --- | --- |
| Upload modal | `div` modal, an Esc listener that fired even when closed, no focus containment or return, the native file input visible inside the drop zone, no drag-and-drop, no way to remove a file. | Fragile and unpolished at the most important first-run moment. | Native `<dialog>` (focus containment, Esc, focus return), drag-and-drop of files and folders, per-file Remove, size meter, inline validation, busy state. | Medium |
| Brand mark | `✳` (welcome), `T` gradient tile (dashboard), `◈` (demo), outlined `T` (lab). | Four marks for one product. | One SVG mark (three traces fusing into one line) on every page. | Low |
| Evidence sources | Hash shown with no copy action (the README promised one). | Missing utility. | Full hash in a mono well, with a **Copy** button. | Low |
| Keyboard search | README documents `/` to focus search and Esc to clear; neither existed. | Documented behaviour missing. | Implemented. | Low |

### 7. Animation

| Component / location | Existing | Why | Recommended / implemented | Severity |
| --- | --- | --- | --- | --- |
| Dashboard reveals | Three overlapping systems: an IntersectionObserver fade-up, a "tf-reveal" fallback, and GSAP ScrollTrigger with blur that **reversed when scrolling back up**. Also a breathing logo ring and a pulsing timeline line. | Content sat at `opacity: 0` until scrolled into view (blank in print and full-page capture). GSAP came from jsdelivr, which the server's own CSP blocks, so every load waited a 2.6s timeout. | Removed. No entrance animation; state changes use colour transitions only. | High |
| Welcome intro | GSAP staggered fade-up, a logo spin with `back.out` easing, scaling ambient blobs. | Stock intro motion. | Removed, and `https://cdnjs.cloudflare.com` dropped from the CSP `script-src`. | Low |

### 8. Content

| Component / location | Existing | Why | Recommended / implemented | Severity |
| --- | --- | --- | --- | --- |
| Headlines and CTAs | "Make sense of the evidence.", "Your workflow starts here.", "Measure the work. Prove the gain.", "Curious how TRACEFUSE performs?" | Generic SaaS phrasing; "Prove the gain" overclaims for a self-reported stopwatch study. | Concrete, checkable statements: what is hashed, what is normalized, what each finding cites. Triage study is named for what it is. | Medium |
| Visuals | None showed actual output. | Nothing demonstrated the product. | The welcome page shows real engine output from synthetic scenario 01, labelled as such. | Medium |
| README | Described an activity chart and findings UI that didn't exist. | Fabricated capability. | Findings UI built; activity-chart claims removed. | Medium |

### 9. Responsiveness and accessibility

| Area | Before | After | Severity |
| --- | --- | --- | --- |
| axe-core (WCAG 2.1 AA + best practice) | not run | 0 violations on welcome (dialog open), demo, dashboard (all disclosures open) and Engine lab | — |
| Mobile at 390px | Dashboard ~11,000px tall; per-event evidence boxes; 8–9px labels | ~7,600px; single-column rows; 12px minimum text; no horizontal overflow on any page | Medium |
| Keyboard | No skip link; div-based modal without focus handling; timers without pressed state | Skip link to the timeline; every control is a real button; `aria-pressed` on timers and finding scope; `aria-expanded` on original-line toggles | Medium |
| Loading and errors | Mixed styles; some failures only in the console | Every panel has a loading, empty and error state using `.tf-empty` / `.tf-note.is-error` | Low |
| Reduced motion | Partially honoured | Global rule in the design system | Low |

## Not addressed here

- `incident-timeline serve <folder>` fails with "case.json missing", although the README documents a multi-case picker. CLI work; tracked separately.
- The PDF export ignores a finding's evidence scope (`ids`); the JSON export honours it. The UI says so on the PDF button while a scope is active.
- Inter is named but not bundled, so rendering falls back to the system UI font. Bundling a WOFF2 locally (allowed by the existing `default-src 'self'` CSP) would make type consistent across machines.
