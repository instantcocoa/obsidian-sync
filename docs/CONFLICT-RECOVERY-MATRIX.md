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

`plugin/test/convergence.test.ts` also runs two harsher configurations:
five devices on four files for 40 rounds (nearly every sync conflicts), and
three devices that sync only one round in five for 36 rounds (long offline
divergence before every reconciliation).

## Not covered by a test here

- Only Intel macOS was run (an EC2 mac1 host; no Apple-silicon host had
  capacity). The plugin bundle is architecture-independent.

## macOS (plugin/test/obsidian-macos.test.ts, real Obsidian 1.14.5 on macOS 15.8, Intel)

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
