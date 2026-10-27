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

## Not covered by a test here

- Case-insensitive and normalising file systems (macOS, Windows): the
  engine's rules are tested on Linux; a run on those systems is part of the
  macOS brief (`plugin/.cache/agent-mac` report) and still pending for
  Windows.
- Simultaneous conflicting edits on the two halves of a plugin update
  (`main.js` and `manifest.json` from different versions): the files are
  independent and would merge or sibling individually; §7.3 atomicity covers
  a single device's reload, not two devices racing an update.
