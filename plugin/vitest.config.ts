import { defineConfig } from "vitest/config";
import { resolve } from "node:path";
export default defineConfig({
  // `obsidian` is types only (Obsidian supplies the runtime); unit tests of the
  // Obsidian-facing modules get a stub instead.
  resolve: { alias: { obsidian: resolve(__dirname, "test/stubs/obsidian.ts") } },
  test: {
    include: ["test/**/*.test.ts"],
    globalSetup: ["test/global-setup.ts"],
    testTimeout: 60_000,
    hookTimeout: 60_000,
    // The real-Obsidian files each launch two Electron instances; running
    // three such files at once starves them and turns 45 s propagation
    // waits into timeouts. Unit and Node suites are fast enough sequentially.
    fileParallelism: false,
  },
});
