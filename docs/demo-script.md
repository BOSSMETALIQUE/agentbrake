# AgentBrake — 72-second Loom demo script

**Audience:** a senior backend / ML engineer who has shipped at least one agent to production and has been bitten (or has lost sleep about getting bitten) by runaway cost or unbounded loops.

**Promise of the demo:** show all three detectors (LOOP, BUDGET, ESCALATION) AND the remote human-validation UI in under 75 seconds.

**Tone:** silent capture, fast cuts, on-screen subtitles added in post. No music, no zoom-and-pan gimmicks. The product is the show.

---

## Storyboard

| Time     | Scene                         | Screen content                                                                                                                                                                          | Text overlay / typed command                                                                                                | Recording notes                                                                                                                                                                |
|----------|-------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0–5s     | HOOK                          | Full-screen black slide, white text, 64pt.                                                                                                                                              | `Your agent just looped for 3 hours overnight.`<br>`Bill: $237.`<br><br>`There's a better way.`                             | Static slide rendered as a PNG or a single .md file open in full-screen preview. Silent.                                                                                       |
| 5–12s    | SETUP — show the config       | VS Code, single file `examples/00_config_snippet.py` visible. Font 18pt. Sidebar hidden. Minimap off.                                                                                   | (already on screen)<br>`agentbrake.init(`<br>`    allowed_tools=["search"],`<br>`    mode="remote",`<br>`)`                 | Show only the 3 lines above. Budget cap is configured per-example for the demo, no need to expose it in the intro snippet. Pre-zoom VS Code to ~140% so the snippet fills the frame. |
| 12–17s   | DEMO 1 — LOOP, run it         | Switch to Terminal 1 (PowerShell, font 20pt, dark theme). Cursor blinking at prompt.                                                                                                    | Type live: `python examples/01_loop_detection.py`                                                                           | Use `Cmd+T`-style hotkey or pre-bound `python examples/01_loop_detection.py` recall. Do NOT mash Enter — let the viewer read the command.                                      |
| 17–22s   | DEMO 1 — LOOP, interrupt      | Terminal output streams. Three "search no-results" lines flash by, then the AgentBrake banner.                                                                                          | `🛑 AgentBrake stopped the agent: LOOP detected after 3 identical calls to 'search'`                                        | The terminal is already configured to surface the banner with a fat separator. No need to scroll.                                                                              |
| 22–27s   | DEMO 2 — BUDGET, run it       | Switch to Terminal 2 (already cleared).                                                                                                                                                 | Type live: `python examples/02_budget_runaway.py`                                                                           | Two terminals side-by-side is overkill — use one terminal with a fresh tab so the LOOP output above is gone.                                                                   |
| 27–32s   | DEMO 2 — BUDGET, interrupt    | Cost lines stream as the agent issues distinct queries: `$0.01 → $0.02 → $0.03`, then the banner.                                                                                       | `🛑 AgentBrake stopped the agent: BUDGET exceeded ($0.04 / $0.03)`                                                          | Pre-tune `BUDGET = 0.03` in the example so the trip happens fast.                                                                                                              |
| 32–37s   | DEMO 3 — ESCALATION, run it   | Same terminal, new tab.                                                                                                                                                                 | Type live: `python examples/03_privilege_escalation.py`                                                                     | Standard terminal cadence — no special framing.                                                                                                                                |
| 37–42s   | DEMO 3 — ESCALATION, trip     | Terminal shows ReAct steps, then ESCALATION banner with the validation URL.                                                                                                             | `🛑 ESCALATION detected. Validate or kill:`<br>`http://localhost:8000/interrupts/<uuid>`                                    | The URL must be visible long enough to read. Hover the mouse over it (most terminals auto-underline URLs) — adds visual anchor for the cut.                                    |
| 42–54s   | REMOTE — browser page         | Cmd+Tab to Chrome. Single tab, the validation URL already loaded but reloaded so it shows the new interrupt. Window is 1200×800.                                                        | (page content, no typing)<br>Red `ESCALATION` badge, `Tool: delete_database`, run id, full context block, recent calls, two large buttons. | The hardest beat to nail — this is the unique selling point. Pre-open Chrome at the right URL pattern. As soon as the terminal prints the new UUID, paste it manually in Chrome via a clipboard shortcut.<br><br>**Use the extra 4 seconds for a SLOW vertical scroll of the validation page. The viewer must see, in order:**<br>1. Red ESCALATION badge (1s)<br>2. Tool name `delete_database` (1s)<br>3. Full context JSON block (3s — most important, this is the unique selling point)<br>4. Recent calls list (2s)<br>5. Two large buttons (3s, mouse hover over "Kill the run" to set up the next beat)<br>6. Mouse click moves to button (1s)<br><br>Cursor speed: about 30% slower than normal. Use Windows Pointer Options → Motion → reduce speed temporarily, or just move slowly with intent. Every pixel of this page must be visible at least once. |
| 54–61s   | REMOTE — click Kill           | Cursor moves to the red "Kill the run" button. Click. The confirmation block fades in: `✗ Killed — the agent will stop.`                                                                | (no typing)                                                                                                                 | Hold the mouse for half a second over the button before clicking — viewers need the visual cue.                                                                                |
| 61–67s   | OUTRO — terminal closes loop  | Cmd+Tab back to the terminal. The agent has raised, traceback ends with `agentbrake.types.AgentBrakeInterrupt: escalation`.                                                             | (terminal already shows it)                                                                                                 | If the polling takes >2s, edit out the gap in post.                                                                                                                            |
| 67–72s   | OUTRO — closing slide         | Full-screen slide.                                                                                                                                                                      | `AgentBrake`<br>`MIT open source — 3 lines of code`<br>`github.com/BOSSMETALIQUE/agentbrake`                                | 5-second hold. Static slide, no animation. Last frame should be the GitHub URL clearly readable.                                                                               |

**Total: 72 seconds, 12 beats.**

---

## Setup before recording

### Files to pre-open in VS Code

- `examples/00_config_snippet.py` — a minimal file containing ONLY the `agentbrake.init(...)` call from the SETUP beat. Create this file before recording; do not show the full `01_loop_detection.py` (too noisy).
- Window state: sidebar collapsed (Ctrl+B), minimap off, breadcrumbs off, terminal panel closed, font size 18, color theme = a dark one with high contrast (e.g. *One Dark Pro* or *Default Dark+*).

### Terminals (PowerShell, dark theme, font 20)

Prepare three terminal "tabs" (Windows Terminal supports this natively). In each, pre-`cd` to the repo and pre-activate the venv:

- **Tab 1** — for `01_loop_detection.py`. Last line in history (press `↑` to recall): `python examples/01_loop_detection.py`
- **Tab 2** — for `02_budget_runaway.py`. Pre-edit `examples/02_budget_runaway.py` so `BUDGET = 0.03` (fast trip). History: `python examples/02_budget_runaway.py`
- **Tab 3** — for `03_privilege_escalation.py`. History: `python examples/03_privilege_escalation.py`

In a fourth terminal (off-screen, never shown), have uvicorn already running:

```
.\.venv\Scripts\python.exe -m uvicorn server.main:app --port 8000 --log-level warning
```

Verify with `curl http://localhost:8000/docs` before hitting record.

### Browser

- Chrome, single window, single tab, zoom 110%.
- Pre-open `http://localhost:8000/interrupts/PLACEHOLDER` — even a 404 is fine, the URL bar is what matters. During recording, you'll paste the real UUID from the terminal.
- Bookmarks bar hidden (Ctrl+Shift+B). Extensions toolbar collapsed.
- Window size: 1200×800. Use a window-snap tool (FancyZones) to dock it consistently between cuts.

### Windows settings

- Do Not Disturb ON (Focus Assist → Alarms only).
- Notifications, Slack, Discord all closed.
- Wallpaper: solid color or a neutral gradient. No personal photos.
- Mouse cursor scheme: large white cursor with shadow — easier to track on dark screens.

### Recording tool

- Loom or OBS. 1080p, 30fps minimum.
- **Microphone: OFF.** This is a silent v1. Also disable system audio capture so background noise doesn't leak in.
- Webcam OFF for this demo (the screen is the story, your face isn't).

---

## Recording flow (window switching choreography)

```
[Slide]              0–5s    ← black-slide PNG in full-screen image viewer
       (Alt+Tab to VS Code)
[VS Code]            5–12s   ← config snippet
       (Alt+Tab to Windows Terminal)
[Terminal Tab 1]    12–22s   ← LOOP demo
       (Ctrl+Tab inside Windows Terminal)
[Terminal Tab 2]    22–32s   ← BUDGET demo
       (Ctrl+Tab inside Windows Terminal)
[Terminal Tab 3]    32–42s   ← ESCALATION trigger, URL printed
       (Select URL with mouse, Ctrl+C, Alt+Tab to Chrome, Ctrl+L, Ctrl+V, Enter)
[Chrome]            42–61s   ← validation page (slow scroll), Kill click, confirmation
       (Alt+Tab back to Terminal Tab 3)
[Terminal Tab 3]    61–67s   ← traceback visible
       (Alt+Tab to Slide)
[Slide]             67–72s   ← outro
```

### Cuts allowed in post

- The polling delay between "Kill" click and the terminal showing the traceback can be up to ~2s. **Cut it.** The viewer should perceive the kill as instant.
- If you fumble a command (typo in the python invocation), retake just that beat — every scene is short and re-recordable.
- Do NOT cut the brief reading time on the slide beats (0–5s, 67–72s). Viewers need to absorb the text.

---

## On-screen subtitles

Compensates for the absence of a voice track. All subtitles are added in post via Loom's text overlay editor (or OBS source if recording in OBS). Hook and outro slides already carry their own copy — no overlay needed there.

**Style baseline:**

- Font: same sans-serif as the slides (system default, e.g. Segoe UI / SF Pro).
- Size: 36pt for lower third, 28pt for top-center "detector tags".
- Color: white on a 60%-opacity black pill background (`background-color: rgba(0,0,0,0.6); padding: 6px 14px; border-radius: 6px;`). Stays readable over any screen content.
- Fade in 200ms, hold, fade out 200ms. No slide-in animations.
- Position:
  - **Lower third** = bottom-center, ~18% margin from bottom edge.
  - **Top-center** = top-center, ~10% margin from top edge.

| Time      | Beat covered                  | Subtitle text                          | Position     | Hold | Notes                                                                                  |
|-----------|-------------------------------|----------------------------------------|--------------|------|----------------------------------------------------------------------------------------|
| 6–10s     | SETUP                         | `Allowlist + mode. The whole config.`    | Lower third  | 4s   | Fades in 1s after VS Code appears, so the viewer's eye lands on the code first.        |
| 12–15s    | DEMO 1 run                    | `Detector 1 — LOOP`                    | Top-center   | 3s   | Acts as a chapter marker. Reuse the same template for the other two detectors.         |
| 19–22s    | DEMO 1 interrupt              | `Stopped before the 4th call.`         | Lower third  | 3s   | Pairs with the 🛑 banner already on screen.                                            |
| 22–25s    | DEMO 2 run                    | `Detector 2 — BUDGET`                  | Top-center   | 3s   | Chapter marker.                                                                        |
| 28–32s    | DEMO 2 interrupt              | `Hard ceiling. 4th call never runs.`   | Lower third  | 4s   | Echoes the cost-line crescendo on screen.                                              |
| 32–35s    | DEMO 3 run                    | `Detector 3 — ESCALATION`              | Top-center   | 3s   | Chapter marker.                                                                        |
| 38–42s    | DEMO 3 trip                   | `Tool not in allowlist.`               | Lower third  | 4s   | Sets up the remote-mode reveal.                                                        |
| 43–47s    | REMOTE page (intro)           | `A human reviews. A human decides.`      | Top-center   | 4s   | This is the differentiator. Top placement gives it weight.                             |
| 48–53s    | REMOTE page (scroll body)     | `Full context sent to backend`         | Lower third  | 5s   | Holds while the slow scroll exposes the JSON block — viewer reads label + sees proof.  |
| 55–60s    | REMOTE Kill click             | `One click. Agent stops.`              | Lower third  | 5s   | Fades in as the cursor approaches the Kill button. Visual rhyme with the click.        |
| 62–66s    | Terminal traceback            | `Destructive call never runs.`         | Lower third  | 4s   | Last subtitle before the outro slide.                                                  |

**Authoring checklist (do this in Loom editor after upload):**

1. Drop the recording onto the timeline.
2. For each row above, add a text overlay at the start time, set the duration, type the exact text. Copy-paste reduces typo risk.
3. Apply the same style preset to every subtitle (Loom lets you save a style).
4. Preview at 1× speed end-to-end. If any subtitle overlaps an important UI element (the 🛑 banner, the Kill button), nudge it 5% up or shrink it one size.
5. Re-preview muted from start to finish — that's how 80% of viewers will watch it.
