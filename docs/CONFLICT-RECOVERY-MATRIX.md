# Conflict and recovery matrix

What the sync promises in each situation, and the test that proves it.
Every row runs against the real Go server with real files on disk
(`plugin/test/conflict-recovery.test.ts`, numbered as here). The rule book
is `DESIGN.md` §6.5, §6.6 and §6.8; the invariant in every row is that
nothing a user wrote is lost: it is at its path, in a conflict sibling, or
in the server's history.

Random combinations of all of these, with three devices, are exercised by
`plugin/test/convergence.test.ts` (seeded, reproducible), which checks
byte-identical convergence and that every device's last write to every
path survives.

## Conflict shapes

| # | Situation | Outcome |
| --- | --- | --- |
| 1 | Same path created on two devices with different bytes, no shared base | First to sync wins at the path; the other's bytes become a sibling on every device |
| 2 | Same path created on two devices with identical bytes | Converges with no sibling; the blob is uploaded once |
| 3 | Both delete the same file; both edit a file to identical bytes | Converges, no sibling, no wasted ops |
| 4 | Three devices change the same line | Head plus two siblings; all three versions present on all three devices |
| 5 | Three devices change different parts of one text file | One clean three-way merge, identical everywhere |
| 6 | Binary file edited concurrently (3 MB) | Sibling with exact bytes; no merge attempted |
| 7 | Two conflicts on one file within the same minute | Two siblings; the second carries an ordinal instead of overwriting the first |
| 8 | Conflict on a file that is itself a conflict sibling | Resolved like any file; the nested name still matches the conflict pattern |
| 9 | CRLF text | Non-overlapping edits merge with CRLF preserved; overlapping ones make a sibling |
| 10 | Empty files | Empty vs empty converges; empty vs content makes a sibling |
| 11 | Renamed on one device, edited at the old name on another | Both files exist: the rename's copy and the edited original |
| 12 | Folder deleted on one device while another edits a file inside it | The edited file survives; the rest of the folder is deleted |
| 13 | Config JSON with the same key changed to different values | Sibling under the config dir; both values kept |
| 14 | Ten rapid alternating edits of one file | Converges; every version that lost a race is a sibling, every synced one is in history |
| 15 | Text content in a file without a text extension (`.pdf`) | Never merged; sibling |

Also covered in `plugin/test/e2e.test.ts`: non-overlapping merge and JSON
key merge; edit versus delete in both directions; a joining device adopting
the vault's config files while a hand-copied note gets a sibling; the
mass-deletion guard.

## Recovery paths

| # | Situation | Outcome |
| --- | --- | --- |
| 16 | Server restarts mid-session | Both devices carry on; no duplicate ops |
| 17 | Server down while a device edits | Status is offline, not error; everything lands when the server returns |
| 18 | Crash between blob upload and op post | After restart the blob is not re-uploaded and the op is posted |
| 19 | Disk error while applying a conflict | The op is skipped and reported; the next sync heals it; an identical sibling is reused, not duplicated |
| 20 | Both devices lose their sync state at once | Rebuilt by hashing: no uploads, no siblings |
| 21 | Server restored from an older backup | Devices detect the rewind, push back what the server forgot (blobs included), delete what was deleted; a new device sees the repaired vault; no siblings |
| 22 | Server restored from backup, then one device writes before the other reconciles | The post-restore write wins at the path; the other device's lost version is kept as a sibling |
| 23 | A blob file missing on the server | Reported and skipped on the reader; `Re-upload current file` on the author heals it |
| 24 | Key rotation while a device is offline with pending edits | It picks up the new key through the keybox and its edits land |
| 25 | A device is removed while holding unsynced edits | Its files and edits stay on its disk; it stops syncing |
| 26 | A device leaves and rejoins over the same files | Identical files adopt silently; a note edited while away gets a sibling; config adopts |
| 27 | Restore to a point in time, then both sides keep editing | Converges; both post-restore edits are kept |
| 28 | Garbage collection while a device is far behind | It ends on the right content; intermediate versions are not needed |
| 29 | Replayed ops (cursor rewound to zero) | No-ops: no siblings, no uploads beyond the real edit |
| 30 | Odd mtimes (zero, ten years ahead) | Sync once and stay quiet |
| 31 | A file whose on-disk name is NFD (a vault copied from a Mac) | One file per device, edits flow both ways, no NFC twin, no loop |

Also in `e2e.test.ts`: state loss on one device, an interrupted write with
partial bytes on disk, rotation locking out a removed device, recovery
passphrase join, restore to a point in time, a compromised member's crafted
paths being refused, an undecryptable blob being skipped and repaired.

## Extreme scenarios

| # | Situation | Outcome |
| --- | --- | --- |
| 32 | Thirty conflicts on one file inside one minute | Thirty numbered siblings; every losing version kept |
| 33 | Four key rotations while a device is offline with edits | It catches up through every epoch and its edits land |
| 34 | Server restored to a backup taken before a key rotation | Devices move back to the restored epoch key, re-encrypt what they push, repair the vault; a new device joins cleanly |
| 35 | 3,000 files, then 100 deleted on one side and 100 edited on the other | Converges; files deleted on one side but edited on the other survive |
| 36 | A 48 MB binary edited concurrently | Head and sibling both bit-exact |
| 37 | Twenty folders deep with a 196-character name | Syncs and conflicts like any file |
| 38 | Deleted and recreated on one side while the other edits the old content | Both versions kept |
| 39 | A local edit lands between the apply decision and the write (Obsidian saving a keystroke while a blob downloads) | The write is abandoned and the decision remade: merge or sibling, never an overwrite (found by the iOS rapid-edit scenario, run 8) |
| 40 | A local edit lands while a push is in flight and that push comes back as a conflict | The stale bytes resolve nothing (no sibling, no head written); the file stays dirty and the next round resolves against the real head with the real bytes (the iOS rapid-edit loss, runs 8 and 9: the iPhone's conflict copy was exactly one append behind its file) |

`plugin/test/convergence.test.ts` also runs two harsher configurations:
five devices on four files for 40 rounds (nearly every sync conflicts), and
three devices that sync only one round in five for 36 rounds (long offline
divergence before every reconciliation).

## Reset, renames and large files (0.2.1 to 1.0.1)

These rows have their own test files, named in each row, not
`conflict-recovery.test.ts`. All run against the real Go server.

| # | Situation | Outcome | Test |
| --- | --- | --- | --- |
| 41 | A device has drifted (local edits, a local deletion, local-only files, a file the server has since deleted) and the user runs **Reset this device to the server's copy** | The device ends byte-identical to the server; nothing is uploaded; every local version that was replaced, and every local-only file, is under `.trash/obsync-reset-<time>/` at its own path with exact bytes; no conflict copies; edits flow both ways again afterwards. On a device that already matches it is a no-op | `reset-to-server.test.ts` |
| 42 | A file is renamed, moved into a folder, or copied on another device | The receiving device writes the content from its own disk: zero blob downloads, bytes exact. A local file that changed since it was synced is not trusted as a source | `rename-no-download.test.ts` |
| 43 | A 12 MiB file is synced, then 100 bytes in its middle change | It travels as chunks; the edit uploads at most two chunks and the reader downloads at most two, taking the rest from the file it already has; the first version is still whole in history; a rename of it moves nothing | `chunks.test.ts` |
| 44 | A large binary edited on two devices at once | First to sync wins the path; the other's bytes are a sibling, both bit-exact on every device, as for any binary (row 6) | `chunks.test.ts` |
| 45 | The chunk list of a version arrives reordered, shortened or padded | Refused: nothing is written. With the honest list the file arrives intact | `chunks.test.ts` |
| 46 | A device is removed (key rotation, every chunk re-encrypted) while a large file exists; then the vault is restored to a time before that file's second version | A device that joins after the rotation reads the file; the restore brings the first version back on every device | `chunks.test.ts` |
| 47 | Garbage collection with no retention, with live and superseded chunked versions | Chunks of every live version survive and a fresh device reads the files; chunks only a superseded version used are dropped | `chunks.test.ts`, server `chunks_test.go` |
| 48 | An op lists a chunk that was never uploaded, or lists chunks on a deletion, or lists more than 4096 | Refused by the server, like an op whose blob is missing | server `chunks_test.go` |
| 49 | A version stops the app twice while being written (a phone killed for memory) | Skipped and reported from the next start; the rest of the vault syncs; a later version of the file is applied | `review14.test.ts` |
| 50 | A member or the server lists chunks the claimed size cannot hold, or pads an honest list | Refused before anything is fetched or allocated, or at the first chunk that overruns; nothing written | `review14.test.ts` |
| 51 | Disjoint concurrent edits of a note large enough to be stored as chunks | One clean three-way merge, no copy | `review14.test.ts` |
| 52 | A file named like a conflict copy, made by a vault member | The review dialog names the device that actually wrote it and will not replace an excluded or never-synced file | `review14.test.ts` |

A file name no device can carry (`? * : < > " | \` or a control character)
is not a conflict and not an error: the file stays where it is and the
plugin names it once in a notice. Before 0.2.1 it was skipped in silence.

Conflict copies are reviewed with **Show conflicts** (1.0.1): each copy
with the file it belongs to, the device and time, the differing lines, and
**Keep current**, **Keep other version** or **Open both**. Every choice is
an ordinary edit or delete. `conflict-review.test.ts` covers the name
parsing and the line comparison behind it; the dialog itself has not been
driven in real Obsidian by a test.

## Not covered by a test here

- Android beyond the emulator's twelve scenarios and the physical Pixel 7
  run (install, join, sync both ways, attachments, backgrounding). iOS is
  covered on physical devices, see the iOS section below.
- The device keychain method on Android and on an iPad. It is covered by
  `keychain-secret.test.ts` (against a transcription of Obsidian's secret
  storage), by a real-Obsidian desktop case in `obsidian-ui.test.ts`, and
  by one manual run on an iPhone (iOS section).
- Chunked files on a physical phone, and a file large enough to press on
  a phone's memory. Files are read whole into memory on every platform.
- The conflict review dialog and the ribbon status icon as rendered UI.

## macOS (plugin/test/obsidian-macos.test.ts, real Obsidian 1.14.5; Intel EC2 Mac on macOS 15.8, and Apple silicon on GitHub's macos-15 runner (macos-14 until GitHub retired that label on 2026-11-07) in CI)

| # | Situation | Outcome |
| --- | --- | --- |
| M1 | Case-only rename `Note.md` to `note.md` | Every device ends with exactly one file with the new casing (was: the peer kept the old casing for ever) |
| M2 | `A.md` and `a.md` from a case-sensitive device | First kept, second refused and reported; nothing overwritten |
| M3 | NFD-named `café.md` created, edited on the peer, back again | One file per side, NFC stored, edits flow both ways |
| M4 | OS keychain protection, plugin reload, Touch ID | Keys sealed, reload unlocks without a prompt; Touch ID offered only when the Mac can prompt for it (was: offered on a Mac mini with no sensor, and a reload could start the engine dead) |
| M5 | Shell edits while Obsidian is open (`echo >`, `mv`) | Put, then delete plus put, as expected |
| M6 | Server halted and resumed on the same port | Reconnects and catches up without a restart |

Bugs this run found and fixed: a case-only rename never produced its delete
because the adapter's stat answered for any casing (the fix is shared with
the Windows finding), a case twin could replace the other file's bytes,
Touch ID was offered on Macs without a sensor, and an unreadable state
file at start killed the engine (now a warning and a rescan). Three harness
problems specific to macOS were fixed too and are what makes the suites run
there at all.

## Windows (plugin/test/obsidian-windows.test.ts, real Obsidian on Windows Server 2022)

| # | Situation | Outcome |
| --- | --- | --- |
| W1 | Names NTFS refuses (`CON.md`, `aux.txt`, `NUL`, trailing dot or space, `:` `|` `?`) arrive from another device | Refused and reported through the skipped-op notice; nothing written under another name; sync continues |
| W2 | `Note.md` and `note.md` from a case-sensitive device | First kept, second skipped and reported; no overwrite; a Linux device keeps both |
| W3 | Case-only rename on Windows | Every device ends with exactly one file with the new casing, no sibling, no delete/put loop |
| W4 | 318- and 378-character absolute paths with the stock long-path policy | Sync cleanly |
| W5 | OS keychain (DPAPI) protection | Keys sealed, nothing sensitive in `data.json`, reload unlocks without a prompt |
| W6 | A note held open with an exclusive lock while a remote edit arrives | Reported once, nothing partial on disk, applied after the lock is released |
| W7 | CRLF on Windows, LF on Linux, concurrent edits | Merge cleanly; lines compare without their line ending |

Bugs this run found and fixed, all with regression tests that also run on
Linux: `ObsidianFS.stat` answered for the wrong case on case-insensitive
volumes; CRLF/LF re-saves conflicted on every line; a write refused because
the file was in use was skipped for good instead of retried; and, on every
platform, a plugin reload raced the previous engine's state flush so the
new engine could come up and never start.
- Simultaneous conflicting edits on the two halves of a plugin update
  (`main.js` and `manifest.json` from different versions): the files are
  independent and would merge or sibling individually; §7.3 atomicity covers
  a single device's reload, not two devices racing an update.

## iOS (plugin/test/ios-devices.test.ts, real Obsidian 1.15 on a physical iPhone 13 Pro, iOS 26.6, and iPad Pro 10.5", iPadOS 17.7; server on EC2 over HTTPS with a Let's Encrypt certificate; a Node engine on the Mac as the third device)

Driven over USB from a Mac with devicectl and pymobiledevice3, no
jailbreak, no UI automation (`docs/IOS-DEVICE-TESTING.md`). In-app edits
go through `obsidian://new`, which uses Obsidian's own vault API. Twenty
scenarios, all green on 2026-11-07 (runs 7 and 10; runs 8 and 9 found the
race recorded as scenarios 39 and 40):

| # | Situation | Outcome |
| --- | --- | --- |
| I1 | Join over HTTPS with a pre-enrolled identity; seed note and 8 MB binary | Both devices hold the seed within 8 s; roster shows mac, iphone, ipad |
| I2 | Note typed on the iPhone (vault API) | On the iPad and the Mac in 7 s |
| I3 | Note written while the iPad app was closed | Pushed on the next launch |
| I4 | Same new note on Mac, iPhone, iPad at once | One head, one copy per losing device, all three versions on all three devices |
| I5 | Different paragraphs edited on all three while the apps were closed | One clean merge, identical everywhere, no copy |
| I6 | Delete and rename on the Mac | Applied on both devices |
| I7 | iPhone writes while the server is down | Lands on the Mac and the iPad after the server returns |
| I8 | Force quit of the iPhone app seconds into a 12 MB download | File bit-exact on relaunch, on both devices |
| I9 | iPhone in the background (Safari in front) while the Mac writes | Caught up on return |
| I10 | Accented folder and file from the Mac; an NFD-spelled file written on the iPad | One spelling per file everywhere |
| I11 | `app.json` changed on the Mac | Applied in both devices' `.obsidian` |
| I12 | Server restored from a backup taken before notes from the iPhone and the Mac | All three devices notice; both notes come back, no copies; later writes flow |
| I13 | iPad removed (rotation + re-encryption), then re-joined with a new invite | Removed iPad receives nothing; iPhone continues; re-joined iPad catches up |
| I14 | Community plugin added on the Mac | Files and the enabled list arrive on the iPhone |
| I15 | Same line edited in-app on the iPhone and the iPad at the same moment | One head plus one copy, both versions kept everywhere |
| I16 | Renamed on the Mac while the iPad edited it at the old name | Both files on all three |
| I17 | 1 MB binary edited on both devices at once | Head and copy bit-exact on all three |
| I18 | Folder deleted on the Mac while the iPhone edited a note inside | Edited note survives everywhere, the other note is gone everywhere |
| I19 | Ten rapid alternating in-app appends from both devices | Every appended line present; head plus copies. Run 8 lost one line here: an append landed between the plugin's apply decision and its write of a remote version. Fixed in the engine (scenarios 39 and 40 above) |
| I20 | Byte-for-byte comparison | 25 files identical on the Mac, the iPhone and the iPad |

Then `plugin/test/linux-joins.test.ts`: real Obsidian 1.14.5 on Linux
(NixOS EC2 workstation, Xvfb) pasted the invite the run left into the
settings tab, received the vault with its conflict copies and the 12 MB
attachment, verified the three-way merged note, and wrote a note that
reached both devices: four platforms in one vault.

**Device keychain, checked by hand on 2026-11-23.** iPhone 18,1, iOS
27.0.1, Obsidian 1.15.1 from the App Store, plugin 0.2.2 installed through
BRAT, against the production server over HTTPS. The phone created a vault
from a create link scanned as a QR code and uploaded its first 9 ops;
Settings → obsync → Protect keys read "Device keychain"; Obsidian was
force-quit and reopened; a new note was created. The server recorded 4
more ops from the same device three minutes after the first batch, with
nothing typed on the phone, so the wrapping key had been written to the
iOS Keychain and read back on the next launch. This was not driven by the
USB harness: the phone would not pair with the Mac. The same phone then
joined the owner's real vault as its second device.

Driver problems this run found (not product bugs): WebCrypto refuses more
than 64 KB of random bytes per call; devicectl's app-container file domain
refuses App Store apps; `+` in an Obsidian URI is literal; iOS suspends the
app when the screen locks; sorting before NFC normalisation reorders
accented names. One product observation: Obsidian asks "Trust author and
enable plugins" once per vault when the plugin arrives from outside the
app, and the screen must stay on for sync to run, as on any phone.
