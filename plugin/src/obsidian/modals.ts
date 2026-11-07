/** Small modals used by settings and commands. No framework, plain Obsidian API. */
import { App, Modal, Notice, Setting } from "obsidian";
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
 * asks before joining. Same link, same single use, same 24 hours.
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
      text: "On the other device, install obsync first, then scan this with its camera, or copy the link and paste it into Settings → obsync → Join. Valid for 24 hours, single use. It contains the vault keys: show or send it only where you would a password.",
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
