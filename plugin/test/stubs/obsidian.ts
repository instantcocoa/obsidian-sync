/**
 * Stand-in for the `obsidian` package in unit tests. The real one has no
 * runtime entry (types only; Obsidian supplies it at load), so Vite cannot
 * resolve it. vitest.config.ts aliases "obsidian" here; tests that need
 * specific behaviour mock it with vi.mock("obsidian", factory) on top.
 */
export class TFile {}
export class TFolder {}
export class Notice {
  constructor(_message: string, _timeout?: number) {}
}
export const Platform = { isMobile: false, isDesktop: true, isIosApp: false, isAndroidApp: false, isMacOS: false };
export const normalizePath = (p: string): string => p.replace(/\\/g, "/").replace(/\/+/g, "/").replace(/^\/|\/$/g, "");
