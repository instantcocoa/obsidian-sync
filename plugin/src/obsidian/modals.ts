/** Small modals used by settings and commands. No framework, plain Obsidian API. */
import { App, Modal, Notice, Setting } from "obsidian";

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
