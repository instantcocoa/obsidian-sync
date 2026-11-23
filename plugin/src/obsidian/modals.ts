/** Small modals used by settings and commands. No framework, plain Obsidian API. */
import { App, Modal, Notice, Setting, TFile } from "obsidian";
import { conflictOrigin, isTextPath, lineDiff } from "../core/paths";
import qrcode from "qrcode-generator";

/** True when `url` is https or loopback, else after the person accepts an unencrypted connection. */
export async function confirmPlainHttp(app: App, url: string): Promise<boolean> {
  const u = url.trim();
  if (!/^http:\/\//i.test(u)) return true;
  if (/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/i.test(u)) return true;
  return ConfirmModal.ask(
    app,
    "Use an unencrypted connection?",
    "This server URL starts with http://, not https://. Your notes stay end-to-end encrypted, but the device token travels in the clear and anyone on the network path could use it to read the encrypted vault or post data. Only do this on a network you trust.",
    "Use http anyway",
  );
}

export class ConfirmModal extends Modal {
  private resolved = false;
  constructor(
    app: App,
    private title: string,
    private body: string | string[],
    private okLabel: string,
    private resolve: (ok: boolean) => void,
  ) {
    super(app);
  }
  override onOpen(): void {
    this.titleEl.setText(this.title);
    const lines = Array.isArray(this.body) ? this.body : [this.body];
    for (const l of lines) this.contentEl.createEl("p", { text: l });
    new Setting(this.contentEl)
      .addButton((b) => b.setButtonText("Cancel").onClick(() => this.close()))
      .addButton((b) =>
        b
          .setButtonText(this.okLabel)
          .setWarning()
          .onClick(() => {
            this.resolved = true;
            this.resolve(true);
            this.close();
          }),
      );
  }
  override onClose(): void {
    if (!this.resolved) this.resolve(false);
    this.contentEl.empty();
  }
  static ask(app: App, title: string, body: string | string[], okLabel = "Continue"): Promise<boolean> {
    return new Promise((res) => new ConfirmModal(app, title, body, okLabel, res).open());
  }
}

/** Shows a secret (invite link) with a copy button and a warning. */
export class ShowSecretModal extends Modal {
  constructor(
    app: App,
    private title: string,
    private secret: string,
    private note: string,
  ) {
    super(app);
  }
  override onOpen(): void {
    this.titleEl.setText(this.title);
    this.contentEl.createEl("p", { text: this.note });
    const ta = this.contentEl.createEl("textarea", { text: this.secret });
    ta.readOnly = true;
    ta.style.width = "100%";
    ta.style.height = "6em";
    new Setting(this.contentEl).addButton((b) =>
      b
        .setButtonText("Copy")
        .setCta()
        .onClick(async () => {
          await navigator.clipboard.writeText(this.secret);
          new Notice("Copied");
        }),
    );
  }
  override onClose(): void {
    this.contentEl.empty();
  }
}

export class PromptModal extends Modal {
  private value = "";
  private done = false;
  constructor(
    app: App,
    private title: string,
    private fields: { name: string; placeholder?: string; secret?: boolean; multiline?: boolean; optional?: boolean }[],
    private resolve: (values: string[] | null) => void,
    private confirmText = "OK",
  ) {
    super(app);
  }
  private values: string[] = [];
  override onOpen(): void {
    this.titleEl.setText(this.title);
    this.values = this.fields.map(() => "");
    this.fields.forEach((f, i) => {
      const s = new Setting(this.contentEl).setName(f.name);
      if (f.multiline) s.addTextArea((t) => t.setPlaceholder(f.placeholder ?? "").onChange((v) => (this.values[i] = v)));
      else
        s.addText((t) => {
          t.setPlaceholder(f.placeholder ?? "").onChange((v) => (this.values[i] = v));
          if (f.secret) t.inputEl.type = "password";
        });
    });
    new Setting(this.contentEl).addButton((b) =>
      b
        .setButtonText(this.confirmText)
        .setCta()
        .onClick(() => {
          const values = this.values.map((v) => v.trim());
          const missing = this.fields.filter((f, i) => !f.optional && !values[i]).map((f) => f.name);
          if (missing.length) {
            new Notice(`obsync: please fill in ${missing.join(", ")}.`);
            return;
          }
          this.done = true;
          this.resolve(values);
          this.close();
        }),
    );
  }
  override onClose(): void {
    if (!this.done) this.resolve(null);
    this.contentEl.empty();
  }
  static ask(app: App, title: string, fields: PromptModal["fields"], confirmText = "OK"): Promise<string[] | null> {
    return new Promise((res) => new PromptModal(app, title, fields, res, confirmText).open());
  }
}

export class ListModal extends Modal {
  constructor(
    app: App,
    private title: string,
    private items: { label: string; detail?: string; action?: { label: string; warning?: boolean; run: () => Promise<void> } }[],
    private empty = "Nothing here.",
  ) {
    super(app);
  }
  override onOpen(): void {
    this.titleEl.setText(this.title);
    if (this.items.length === 0) this.contentEl.createEl("p", { text: this.empty });
    for (const it of this.items) {
      const s = new Setting(this.contentEl).setName(it.label).setDesc(it.detail ?? "");
      if (it.action) {
        const a = it.action;
        s.addButton((b) => {
          b.setButtonText(a.label).onClick(async () => {
            b.setDisabled(true);
            try {
              await a.run();
              this.close();
            } catch (e) {
              new Notice(`obsync: ${(e as Error).message}`);
              b.setDisabled(false);
            }
          });
          if (a.warning) b.setWarning();
        });
      }
    }
  }
  override onClose(): void {
    this.contentEl.empty();
  }
}

/**
 * The invite link as a QR code plus the text. The QR encodes an
 * `obsidian://obsync-join?link=…` URL, which a phone's camera opens in
 * Obsidian (the OS knows `obsidian://`, not `obsync://`); the plugin there
 * asks before joining. Same link, same single use, same one hour.
 */
export class InviteModal extends Modal {
  constructor(
    app: App,
    private link: string,
    private scanUrl: string,
  ) {
    super(app);
  }
  override onOpen(): void {
    this.titleEl.setText("Invite another device");
    this.contentEl.createEl("p", {
      text: "On the other device, install obsync first, then scan this with its camera, or copy the link and paste it into Settings → obsync → Join. Valid for one hour, single use; a key rotation ends it early. It contains the vault keys: show or send it only where you would a password.",
    });
    const qr = qrcode(0, "M");
    qr.addData(this.scanUrl);
    qr.make();
    const img = this.contentEl.createEl("img", { attr: { src: qr.createDataURL(6, 8), alt: "QR code of the invite link" } });
    img.style.display = "block";
    img.style.margin = "0 auto 1em";
    img.style.maxWidth = "min(100%, 320px)";
    img.style.imageRendering = "pixelated";
    const ta = this.contentEl.createEl("textarea", { text: this.link });
    ta.readOnly = true;
    ta.style.width = "100%";
    ta.style.height = "6em";
    new Setting(this.contentEl).addButton((b) =>
      b
        .setButtonText("Copy link")
        .setCta()
        .onClick(async () => {
          await navigator.clipboard.writeText(this.link);
          new Notice("Copied");
        }),
    );
  }
  override onClose(): void {
    this.contentEl.empty();
  }
}

/**
 * Review conflict copies (DESIGN.md §6.6). A conflict never overwrites: the
 * losing version is kept beside the file as "name (conflict device date)".
 * This lists every such copy with what differs and lets the user settle it:
 * keep the current file (the copy is deleted), keep the copy (it replaces
 * the current file, whose content stays in the server's history), or open
 * both. Every choice is an ordinary edit or delete, so it syncs like one.
 */
export class ConflictModal extends Modal {
  constructor(
    app: App,
    private paths: string[],
  ) {
    super(app);
  }

  override onOpen(): void {
    void this.render();
  }

  private file(path: string): TFile | null {
    const f = this.app.vault.getAbstractFileByPath(path);
    return f instanceof TFile ? f : null;
  }

  private async render(): Promise<void> {
    const el = this.contentEl;
    el.empty();
    this.titleEl.setText("Conflict copies");
    const live = this.paths.filter((p) => this.file(p));
    if (live.length === 0) {
      el.createEl("p", { text: "No conflict copies. Every device agrees." });
      return;
    }
    el.createEl("p", { text: `${live.length} file${live.length === 1 ? " was" : "s were"} changed in two places at once. Both versions were kept. Choose what to keep for each.` });
    for (const path of live) await this.row(el, path);
  }

  private async row(el: HTMLElement, path: string): Promise<void> {
    const copy = this.file(path)!;
    const origin = conflictOrigin(path);
    const current = origin ? this.file(origin.original) : null;
    const box = el.createDiv({ cls: "obsync-conflict" });
    box.createEl("h4", { text: origin?.original ?? path });
    box.createEl("div", { cls: "setting-item-description", text: origin ? `Other version from ${origin.device}, ${origin.when}` : "Conflict copy" });
    if (current && isTextPath(path) && copy.stat.size < 2_000_000 && current.stat.size < 2_000_000) {
      const [a, b] = await Promise.all([this.app.vault.read(current), this.app.vault.read(copy)]);
      const d = lineDiff(a, b);
      if (d.onlyA.length === 0 && d.onlyB.length === 0) box.createEl("div", { cls: "setting-item-description", text: "The two versions have the same lines (they differ only in order or line endings)." });
      else {
        const det = box.createEl("details");
        det.createEl("summary", { text: `${d.onlyA.length} line${d.onlyA.length === 1 ? "" : "s"} only in the current file, ${d.onlyB.length} only in the other version` });
        const show = (title: string, lines: string[]) => {
          if (lines.length === 0) return;
          det.createEl("div", { cls: "setting-item-description", text: title });
          det.createEl("pre", { cls: "obsync-diff", text: lines.slice(0, 40).join("\n") + (lines.length > 40 ? `\n… ${lines.length - 40} more` : "") });
        };
        show("Only in the current file:", d.onlyA);
        show("Only in the other version:", d.onlyB);
      }
    } else if (current) {
      box.createEl("div", { cls: "setting-item-description", text: `Current file ${current.stat.size} bytes, other version ${copy.stat.size} bytes.` });
    } else {
      box.createEl("div", { cls: "setting-item-description", text: "The original file no longer exists; this copy is the only version here." });
    }
    const act = async (fn: () => Promise<void>, done: string) => {
      try {
        await fn();
        new Notice(`obsync: ${done}`);
        await this.render();
      } catch (e) {
        new Notice(`obsync: ${(e as Error).message}`, 8000);
      }
    };
    const s = new Setting(box);
    s.addButton((b) =>
      b.setButtonText("Open both").onClick(async () => {
        if (current) await this.app.workspace.getLeaf("tab").openFile(current);
        await this.app.workspace.getLeaf("split").openFile(copy);
        this.close();
      }),
    );
    if (current) {
      s.addButton((b) => b.setButtonText("Keep current").onClick(() => act(() => this.app.fileManager.trashFile(copy), "kept the current file; the other version was removed")));
      s.addButton((b) =>
        b
          .setButtonText("Keep other version")
          .setWarning()
          .onClick(() =>
            act(async () => {
              await this.app.vault.modifyBinary(current, await this.app.vault.readBinary(copy));
              await this.app.fileManager.trashFile(copy);
            }, "the other version is now the file; the previous content is in its history"),
          ),
      );
    } else if (origin) {
      s.addButton((b) => b.setButtonText("Restore as the file").onClick(() => act(() => this.app.fileManager.renameFile(copy, origin.original), "restored")));
    }
  }

  override onClose(): void {
    this.contentEl.empty();
  }
}
