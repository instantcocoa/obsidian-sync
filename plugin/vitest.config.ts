import { defineConfig } from "vitest/config";
export default defineConfig({
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
