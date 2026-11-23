/**
 * Content-defined chunking for large files (1.0, DESIGN.md §6.9).
 *
 * A file above CHUNK_THRESHOLD is stored as a sequence of chunks, each an
 * ordinary encrypted blob named by the keyed hash of its plaintext, so an
 * edit uploads only the chunks it touched and equal chunks are stored once
 * across versions and files. Cut points are chosen from the content (a gear
 * rolling hash), so inserting bytes early in a file moves one boundary, not
 * all of them.
 *
 * The gear table is derived from the vault key. Chunk sizes are visible to
 * the server; with a public table, someone holding a candidate file could
 * compute its boundaries and recognise it by its size sequence. With a
 * keyed table the boundaries of a known file are not predictable.
 */
export const CHUNK_THRESHOLD = 1024 * 1024; // files up to this size are one blob, as before
export const CHUNK_MIN = 256 * 1024;
export const CHUNK_MAX = 4 * 1024 * 1024;
/** Twenty high bits zero: one cut per MiB on average after the minimum. */
const CUT_MASK = 0xfffff000;
export const MAX_CHUNKS = 4096; // the server's bound

export function gearTable(seed: Uint8Array): Uint32Array {
  if (seed.length !== 1024) throw new Error("gear table seed must be 1024 bytes");
  const t = new Uint32Array(256);
  const v = new DataView(seed.buffer, seed.byteOffset, seed.byteLength);
  for (let i = 0; i < 256; i++) t[i] = v.getUint32(i * 4, true);
  return t;
}

/** End offsets of each chunk of `data` (the last is data.length). */
export function cutPoints(data: Uint8Array, table: Uint32Array): number[] {
  const out: number[] = [];
  const n = data.length;
  let start = 0;
  while (start < n) {
    const hardEnd = Math.min(start + CHUNK_MAX, n);
    let end = hardEnd;
    if (n - start > CHUNK_MIN) {
      let h = 0;
      // The hash only "sees" its last 32 bytes, so start it just before the
      // first position a cut is allowed.
      for (let i = start + CHUNK_MIN - 32; i < hardEnd; i++) {
        h = ((h << 1) + table[data[i]]) >>> 0;
        if (i >= start + CHUNK_MIN && (h & CUT_MASK) === 0) {
          end = i + 1;
          break;
        }
      }
    }
    out.push(end);
    start = end;
  }
  return out;
}

export function split(data: Uint8Array, table: Uint32Array): Uint8Array[] {
  const parts: Uint8Array[] = [];
  let start = 0;
  for (const end of cutPoints(data, table)) {
    parts.push(data.subarray(start, end));
    start = end;
  }
  return parts;
}
