/**
 * "Reset this device to the server's copy": the one-way recovery. Every other
 * path in the engine preserves a local difference (merge or sibling); this
 * one parks it under .trash/obsync-reset-<time>/ and takes the server's
 * head, uploading nothing. Against the real Go server.
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

async function pair(): Promise<[Device, Device]> {
  const sa = await createVault(await srv.createLink(), "laptop");
  const sb = await joinWithLink(await createInviteLink(sa), "phone");
  return [await new Device("laptop", sa).start(), await new Device("phone", sb).start()];
}

describe("reset to the server's copy", () => {
  it("makes the device identical to the server, parks every local difference, uploads nothing", async () => {
    const [a, b] = await pair();
    const png = new Uint8Array(50_000).map((_, i) => (i * 31) & 0xff);
    await a.write("keep.md", "same everywhere\n", 1_700_000_000_000);
    await a.write("edited.md", "server version\n", 1_700_000_001_000);
    await a.write("deleted-here.md", "server still has this\n", 1_700_000_002_000);
    await a.write("gone-on-server.md", "a will delete this\n", 1_700_000_003_000);
    await a.write("pic.png", png, 1_700_000_004_000);
    await a.write(".obsidian/app.json", '{"theme":"obsidian"}\n', 1_700_000_005_000);
    await a.sync();
    await b.sync();
    expect(await b.files()).toEqual([".obsidian/app.json", "deleted-here.md", "edited.md", "gone-on-server.md", "keep.md", "pic.png"]);

    // The server moves on: A deletes a file and edits the config.
    await a.remove("gone-on-server.md");
    await a.write(".obsidian/app.json", '{"theme":"moonstone"}\n');
    await a.sync();

    // B drifts without syncing: an edit, a deletion, a local-only file, a
    // local edit of a file A deleted, a changed binary.
    await b.write("edited.md", "phone version, never uploaded\n");
    await b.remove("deleted-here.md");
    await b.write("only-here.md", "exists on the phone only\n");
    await b.write("gone-on-server.md", "edited on the phone after A deleted it\n");
    const png2 = new Uint8Array(50_000).map((_, i) => (i * 17) & 0xff);
    await b.write("pic.png", png2);
    await b.write("notes/deep/local.md", "local, nested\n");
    await b.write(".obsidian/workspace.json", '{"excluded":"stays"}');

    const uploads = b.uploads;
    const posts = b.posts;
    const moved = await b.engine.resetToServer();
    expect(b.uploads).toBe(uploads);
    expect(b.posts).toBe(posts);

    // Vault paths as the server has them; the reset folder is under .trash and excluded, so files() does not list it as synced content.
    const synced = (await b.files()).filter((p) => !p.startsWith(".trash/"));
    expect(synced).toEqual([".obsidian/app.json", ".obsidian/workspace.json", "deleted-here.md", "edited.md", "keep.md", "pic.png"]);
    expect(await b.read("edited.md")).toBe("server version\n");
    expect(await b.read("deleted-here.md")).toBe("server still has this\n");
    expect(await b.read(".obsidian/app.json")).toBe('{"theme":"moonstone"}\n');
    expect(Buffer.compare(await b.readBytes("pic.png"), png)).toBe(0);
    expect(await b.read(".obsidian/workspace.json")).toBe('{"excluded":"stays"}');

    // Everything the server's copy replaced is in the reset folder, byte for
    // byte: the stale app.json too, since "differs from the server" is the
    // only question a reset asks.
    const parked = [".obsidian/app.json", "edited.md", "gone-on-server.md", "notes/deep/local.md", "only-here.md", "pic.png"];
    expect(moved.sort()).toEqual(parked);
    const dirs = (await b.fs.list()).map((f) => f.path).filter((p) => p.startsWith(".trash/obsync-reset-"));
    const dir = dirs[0].split("/").slice(0, 2).join("/");
    expect(dirs.map((p) => p.slice(dir.length + 1)).sort()).toEqual(parked);
    expect(await b.read(`${dir}/.obsidian/app.json`)).toBe('{"theme":"obsidian"}\n');
    expect(await b.read(`${dir}/edited.md`)).toBe("phone version, never uploaded\n");
    expect(await b.read(`${dir}/gone-on-server.md`)).toBe("edited on the phone after A deleted it\n");
    expect(await b.read(`${dir}/only-here.md`)).toBe("exists on the phone only\n");
    expect(Buffer.compare(await b.readBytes(`${dir}/pic.png`), png2)).toBe(0);
    expect(b.conflicts).toEqual([]);

    // Afterwards the device is an ordinary member: a sync uploads nothing and A sees nothing new.
    await b.sync();
    expect(b.uploads).toBe(uploads);
    expect(b.posts).toBe(posts);
    const aFiles = await a.files();
    await a.sync();
    expect(await a.files()).toEqual(aFiles);
    expect(await a.exists("only-here.md")).toBe(false);
    expect(await a.read("edited.md")).toBe("server version\n");

    // And edits after the reset flow both ways again.
    await b.write("edited.md", "phone, after the reset\n");
    await b.sync();
    await a.sync();
    expect(await a.read("edited.md")).toBe("phone, after the reset\n");
    await a.cleanup();
    await b.cleanup();
  });

  it("is a no-op on a device that matches the server, and survives a restart", async () => {
    const [a, b] = await pair();
    await a.write("n.md", "x\n");
    await a.sync();
    await b.sync();
    const before = await b.files();
    expect(await b.engine.resetToServer()).toEqual([]);
    expect(await b.files()).toEqual(before);
    expect((await b.fs.list()).some((f) => f.path.startsWith(".trash/"))).toBe(false);
    await b.restart();
    await b.sync();
    expect(await b.read("n.md")).toBe("x\n");
    expect(b.uploads).toBe(0);
    await a.cleanup();
    await b.cleanup();
  });
});
