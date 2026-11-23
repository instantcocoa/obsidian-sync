/**
 * A rename or copy made on one device costs the others no download: the
 * content id is a keyed hash of the plaintext, so a device that already
 * holds those bytes under another name writes them from its own disk
 * (found by the comparison report: the renaming device uploaded 0 bytes but
 * every receiver fetched the 5 MiB again).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TestServer, Device } from "./harness";
import { createVault, createInviteLink, joinWithLink } from "../src/core/admin";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

describe("content already on the device is not downloaded again", () => {
  it("rename, move into a folder, and copy: zero blob downloads on the receiver, bytes exact", async () => {
    const sa = await createVault(await srv.createLink(), "laptop");
    const sb = await joinWithLink(await createInviteLink(sa), "phone");
    const a = await new Device("laptop", sa).start();
    const b = await new Device("phone", sb).start();
    let gets = 0;
    const orig = sb.client.getBlob.bind(sb.client);
    sb.client.getBlob = async (v: string, id: string) => {
      gets++;
      return orig(v, id);
    };
    const big = new Uint8Array(3 * 1024 * 1024).map((_, i) => (i * 2654435761) >>> 24);
    await a.write("pic.bin", big, 1_700_000_000_000);
    await a.write("note.md", "text\n", 1_700_000_001_000);
    await a.sync();
    await b.sync();
    expect(gets).toBe(2);

    // Rename on A: delete + put of the same content.
    await a.write("renamed.bin", big, 1_700_000_000_000);
    await a.remove("pic.bin");
    // Move a note into a folder, and copy the big file as well.
    await a.write("folder/note.md", "text\n", 1_700_000_001_000);
    await a.remove("note.md");
    await a.write("copy of renamed.bin", big, 1_700_000_002_000);
    await a.sync();
    gets = 0;
    await b.sync();
    expect(gets).toBe(0);
    expect(await b.files()).toEqual(["copy of renamed.bin", "folder/note.md", "renamed.bin"]);
    expect(Buffer.compare(await b.readBytes("renamed.bin"), big)).toBe(0);
    expect(Buffer.compare(await b.readBytes("copy of renamed.bin"), big)).toBe(0);
    expect(await b.read("folder/note.md")).toBe("text\n");

    // A local file that changed since it was synced is not trusted as a source.
    await b.write("renamed.bin", new Uint8Array(10));
    await a.write("third.bin", big, 1_700_000_003_000);
    await a.sync();
    gets = 0;
    await b.engine.sync(); // no scan: b's state still says renamed.bin holds the big content
    expect(Buffer.compare(await b.readBytes("third.bin"), big)).toBe(0);
    await a.cleanup();
    await b.cleanup();
  });
});
