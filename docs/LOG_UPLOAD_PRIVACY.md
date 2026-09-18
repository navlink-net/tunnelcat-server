# Log upload: what it is, why it exists, and the tradeoff it represents

## What gets collected

The client periodically uploads its own on-disk diagnostic log (see
`snc/core/log_upload.go`) to the arbiter, automatically, in the background,
without the user doing anything — this is separate from, and in addition
to, the manual "Share Logs" export a user can trigger themselves for
support.

That log is deliberately detailed. It includes, among other operational
detail, **every destination the user's traffic connects to** (`socks5:
CONNECT <host:port>` and similar lines in `snc/core/socks5.go`) — because
diagnosing "why doesn't site X work for this user" or "which real-world
targets does DPI provider Y actually interfere with" requires exactly that
level of detail. A redacted or aggregated log cannot answer those
questions.

Uploaded logs are stored on the arbiter **unmodified and unredacted**
(`snc-arbiter/log_store.go`) under a directory keyed by the uploading
account's own username, up to a 500 GB total cap (oldest evicted first —
there is currently no fixed per-account retention window shorter than
that). This is a deliberate, previously-made design choice: secure the
*channel* (the upload travels end-to-end over the user's own tunnel to the
arbiter, so no intermediate control/exit node ever sees plaintext), not the
*content* — see `snc-arbiter/log_upload_client_api.go`'s doc comment for the
reasoning.

## Why this is genuinely useful — not just "for debugging"

For a tool whose whole purpose is working around active network
interference, per-connection logs from real devices on real, live,
adversarial networks are close to the only way to actually learn what a
censor or a hostile ISP is doing right now: which destinations get reset,
which protocols get throttled, which fingerprints get flagged, in which
regions, on which providers, today — not in a lab, not in a synthetic test.
This project's own traffic-obfuscation and DPI-avoidance work has
repeatedly been informed by exactly this kind of field data. Turning connection-level
logging off entirely, for everyone, would blind the team to real,
currently-active blocking the moment it starts — which is also a real cost
to users, just a less visible one.

## Why this is also a genuine risk, worth stating plainly

This is a censorship-circumvention tool. For its users, "who connected to
what, when, under their real account name" is close to the single most
sensitive fact that could exist about them. Storing that, unredacted, tied
to a real username, at scale (up to 500 GB, no fixed TTL) creates real
exposure if the arbiter or its storage were ever compromised, subpoenaed,
or leaked — exactly the failure mode this class of tool exists to protect
people from in the first place. This is not a hypothetical: an earlier
version of the upload pipeline already leaked a real user's OAuth token in
cleartext through this exact mechanism (see the incident referenced in
`log_upload_client_api.go`'s doc comment), and the connection
history itself is at least as sensitive as any one token, if not more so.

## The actual tradeoff, and what this project does about it

**There is no version of this feature that is simultaneously maximally
useful for studying live blocking and maximally safe for users — those two
goals pull directly against each other, and this project does not pretend
otherwise.** The choice made here is to keep the data (unredacted, for
research value) but make participation controllable, at three levels:

1. **Global kill switch** (`system_settings.log_upload_global_enabled`,
   `snc-arbiter/db.go`'s `globalLogUploadEnabled`/`setGlobalLogUploadEnabled`)
   — turns automatic upload off fleet-wide, live, no rebuild or redeploy.
2. **Per-user self-service preference** (`users.log_upload_enabled`) — an
   individual can opt out of automatic upload for their own account via
   `GET`/`POST /api/log/client-upload/pref`, without affecting anyone else
   or losing local logging / manual Share Logs. Every client exposes this
   as a toggle in its own settings UI (all default to on, matching the
   server-side default — nothing changes for anyone until they flip it):

   (File paths below are in the client repository, not this one.)

   | Platform | Where the toggle lives |
   |---|---|
   | Windows | Settings tab → "Send diagnostic logs to support automatically" checkbox (`snc/win/windows/uiwindow.go`) |
   | macOS | Settings panel → Privacy section (`snc/mac/macos/window_darwin.go`) |
   | Linux | Settings panel → Privacy section (`snc/linux/linux/app_window_linux.go`) |
   | Android | Overflow menu → checkable "Send diagnostic logs…" item (`MainActivity.kt`, `menu_main.xml`) |
   | iOS | Navigation-bar menu → "Send diagnostic logs…" toggle (`ConnectionViewController.swift`) |

   The preference is stored per **account**, not per device, so flipping it
   on one device applies to that account's other devices too (each client
   re-reads it once per connect). It needs a live tunnel to change — the
   request goes to the arbiter over the client's own tunnel, same as the
   upload itself — so a toggle attempted while disconnected reverts with a
   "connect first" message rather than silently pretending to succeed. If
   an admin override or the global switch is what's actually stopping
   uploads, the toggle still shows the user's own preference; the API's
   `effective` field is what says whether uploads really happen.
3. **Per-user admin override** (`users.log_upload_admin_disabled`) — staff
   can force a specific account's uploads off (e.g. for a compliance
   request or an abuse investigation) regardless of that user's own
   setting; this cannot be re-enabled by the user themselves.

None of these three affect local on-device logging (still as detailed as
ever — a user who wants maximum local diagnostic detail keeps it) or a
manual Share-Logs export (still full detail, still the user's own explicit
action). They only govern the automatic background upload to the arbiter.

This is a real, live tradeoff between two legitimate goals — user safety
and the team's ability to see real blocking as it happens — being made
explicitly and adjustably, rather than resolved by pretending only one of
those goals matters.
