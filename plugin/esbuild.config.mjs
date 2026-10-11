// Builds src/obsidian/main.ts into main.js for Obsidian. `production` minifies.
import esbuild from "esbuild";
import process from "node:process";
import { copyFileSync, existsSync } from "node:fs";

const prod = process.argv[2] === "production";

const ctx = await esbuild.context({
  entryPoints: ["src/obsidian/main.ts"],
  bundle: true,
  external: ["obsidian", "electron", "@codemirror/*", "@lezer/*"],
  format: "cjs",
  target: "es2022",
  platform: "browser",
  logLevel: "info",
  sourcemap: prod ? false : "inline",
  minify: prod,
  treeShaking: true,
  outfile: "main.js",
  banner: { js: "/* obsync — https://github.com/ (see DESIGN.md) */" },
});

if (prod) {
  await ctx.rebuild();
  // Optional: copy the built plugin into a test vault listed in OBSYNC_TEST_VAULT.
  const vault = process.env.OBSYNC_TEST_VAULT;
  if (vault && existsSync(vault)) {
    for (const f of ["main.js", "manifest.json", "styles.css"]) {
      if (existsSync(f)) copyFileSync(f, `${vault}/.obsidian/plugins/obsync/${f}`);
    }
  }
  process.exit(0);
} else {
  await ctx.watch();
}
