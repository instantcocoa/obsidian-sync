/** The settings tab: enrolment when not joined, status and options when joined. */
import { Notice, PluginSettingTab, Setting } from "obsidian";
import type ObsyncPlugin from "./main";
import { DEFAULT_EXCLUSIONS } from "../core/paths";
import { ConfirmModal, PromptModal } from "./modals";

export class ObsyncSettingTab extends PluginSettingTab {
  constructor(private plugin: ObsyncPlugin) {
    super(plugin.app, plugin);
  }

  override display(): void {
    const { containerEl: el } = this;
    el.empty();
    const s = this.plugin.settings;
    if (this.plugin.locked) {
      el.createEl("h3", { text: "Locked" });
      new Setting(el)
        .setName("Vault keys are locked on this device")
        .setDesc(s.sealed?.method === "pin" ? "Enter your PIN to start syncing." : "Unlock with your OS keychain to start syncing.")
        .addButton((b) =>
          b
            .setButtonText("Unlock")
            .setCta()
            .onClick(() => this.run(() => this.plugin.unlock())),
        );
      return;
    }
    if (!s.identity) this.renderJoin(el);
    else this.renderJoined(el);
  }

  private renderJoin(el: HTMLElement): void {
    el.createEl("h3", { text: "Connect this vault" });
    el.createEl("p", { text: "Paste an invite link from a device that is already syncing, or create a new vault on your server." });

    let link = "";
    new Setting(el)
      .setName("Join with invite link")
      .setDesc("obsync://join#… from another device's “Generate invite link”. The link contains the vault keys; discard it after use.")
      .addText((t) => t.setPlaceholder("obsync://join#…").onChange((v) => (link = v.trim())))
      .addButton((b) =>
        b
          .setButtonText("Join")
          .setCta()
          .onClick(() => this.run(() => this.plugin.joinWithLink(link))),
      );

    new Setting(el)
      .setName("Join with recovery passphrase")
      .setDesc("Needs the server URL, the vault id, and the recovery passphrase set on another device.")
      .addButton((b) =>
        b.setButtonText("Join…").onClick(async () => {
          const v = await PromptModal.ask(
            this.app,
            "Join with recovery passphrase",
            [
              { name: "Server URL", placeholder: "https://sync.example.com" },
              { name: "Vault id", placeholder: "32 hex characters, shown under Status on a connected device" },
              { name: "Recovery passphrase", secret: true },
            ],
            "Join",
          );
          if (v && (await this.plainHttpOk(v[0]))) await this.run(() => this.plugin.joinWithPassphrase(v[0], v[1], v[2]));
        }),
      );

    new Setting(el)
      .setName("Create a new vault")
      .setDesc("First device only. Needs the server's admin token (printed when the server first started).")
      .addButton((b) =>
        b.setButtonText("Create…").onClick(async () => {
          const v = await PromptModal.ask(
            this.app,
            "Create a new vault",
            [
              { name: "Server URL", placeholder: "https://sync.example.com" },
              { name: "Admin token", placeholder: "printed by the server on first start; also in <data>/admin-token", secret: true },
            ],
            "Create",
          );
          if (v && (await this.plainHttpOk(v[0]))) await this.run(() => this.plugin.createVault(v[0], v[1]));
        }),
      );

    new Setting(el)
      .setName("Device name")
      .setDesc("How this device appears in Manage devices on every device, and in conflict file names. Pick something you will recognise; it can be changed later.")
      .addText((t) => t.setValue(this.plugin.settings.deviceName).onChange((v) => (this.plugin.settings.deviceName = v.trim() || "device")));
  }

  private renderJoined(el: HTMLElement): void {
    const s = this.plugin.settings;
    const id = s.identity!;
    el.createEl("h3", { text: "Status" });
    const st = this.plugin.engine?.getStatus();
    const statusName = st ? `${st.phase}${st.pending ? `, ${st.pending} pending` : ""}` : "stopped";
    new Setting(el)
      .setName(statusName)
      .setDesc(st?.message ?? `Server: ${id.server}`)
      .addButton((b) => b.setButtonText("Sync now").onClick(() => this.plugin.engine?.kick(0)));
    new Setting(el)
      .setName("Vault id")
      .setDesc(`${id.vaultId}\nNeeded, with the server URL and the recovery passphrase, to join from a device that has no invite link. Keep a copy somewhere safe.`)
      .addButton((b) =>
        b.setButtonText("Copy").onClick(async () => {
          await navigator.clipboard.writeText(id.vaultId);
          new Notice("obsync: vault id copied.");
        }),
      );
    new Setting(el)
      .setName("This device")
      .setDesc(`${id.deviceName} (${id.deviceId.slice(0, 8)}). Shown on every device in Manage devices and used in conflict file names.`)
      .addButton((b) =>
        b.setButtonText("Rename…").onClick(async () => {
          const v = await PromptModal.ask(this.app, "Rename this device", [{ name: "Device name", placeholder: id.deviceName }], "Rename");
          if (v) await this.run(() => this.plugin.renameDevice(v[0]));
        }),
      );

    el.createEl("h3", { text: "Devices" });
    new Setting(el)
      .setName("Generate invite link")
      .setDesc("For another device. Valid 24 hours, single use. Send it over a channel you trust and delete it afterwards.")
      .addButton((b) => b.setButtonText("Generate").onClick(() => this.plugin.cmdInvite()));
    new Setting(el)
      .setName("Manage devices")
      .setDesc("List devices. Removing one rotates the vault keys and re-encrypts, so the removed device can read nothing new.")
      .addButton((b) => b.setButtonText("Open").onClick(() => this.plugin.cmdDevices()));
    const rec = new Setting(el)
      .setName("Recovery passphrase")
      .setDesc("Optional. Lets a new device join with only the server URL, vault id, and this passphrase. Setting it again replaces the old one.")
      .addButton((b) => b.setButtonText("Set…").onClick(() => this.plugin.cmdSetRecovery()));
    void this.plugin
      .devices()
      .then((ds) => {
        if (ds.some((d) => d.recovery && !d.revoked_at)) rec.setDesc("A passphrase is set. Lets a new device join with only the server URL, vault id, and the passphrase. Setting it again replaces the old one.");
      })
      .catch(() => {});

    el.createEl("h3", { text: "What to sync" });
    new Setting(el)
      .setName("Sync the config folder (" + this.app.vault.configDir + ")")
      .setDesc("Settings, themes, snippets, hotkeys, plugins and their data. Workspace layout files are always kept per device.")
      .addToggle((t) =>
        t.setValue(s.syncConfig).onChange(async (v) => {
          s.syncConfig = v;
          await this.plugin.saveSettings();
          this.plugin.applyExclusions();
        }),
      );
    new Setting(el)
      .setName("Exclusions (this device)")
      .setDesc("One gitignore-style pattern per line, matched against vault paths with the config folder written as $CONFIG. Defaults cover workspace files, trash and OS junk.")
      .addTextArea((t) => {
        t.setValue(s.exclusions.join("\n")).onChange(async (v) => {
          s.exclusions = v.split("\n").map((x) => x.trim()).filter(Boolean);
          await this.plugin.saveSettings();
          this.plugin.applyExclusions();
        });
        t.inputEl.rows = 8;
        t.inputEl.style.width = "100%";
      })
      .addExtraButton((b) =>
        b.setIcon("reset").setTooltip("Restore defaults").onClick(async () => {
          s.exclusions = [...DEFAULT_EXCLUSIONS];
          await this.plugin.saveSettings();
          this.plugin.applyExclusions();
          this.display();
        }),
      );

    el.createEl("h3", { text: "Keys on this device" });
    const current = s.protection.method;
    new Setting(el)
      .setName("Protect keys")
      .setDesc(
        "How the vault keys are stored on this device. None: in data.json, safe only if the disk is encrypted. PIN: asked at every launch; someone with the file can try PINs offline, so a short PIN only slows them down and a long one stops them. OS keychain: unlocked by your login session; resists anyone with the file but not your session. Touch ID (macOS) adds a prompt before the keychain is used.",
      )
      .addDropdown((d) => {
        for (const o of this.plugin.protectionOptions()) if (o.available || o.method === current) d.addOption(o.method, o.label);
        d.setValue(current).onChange(async (v) => {
          try {
            if (v === "pin") {
              const r = await PromptModal.ask(this.app, "Set a PIN", [
                { name: "PIN (6+ characters; longer is better)", secret: true },
                { name: "Repeat", secret: true },
              ]);
              if (!r) return this.display();
              if (r[0] !== r[1]) throw new Error("PINs differ");
              await this.plugin.setProtection("pin", { pin: r[0] });
            } else await this.plugin.setProtection(v as "none" | "safe", { touchId: s.protection.touchId });
            new Notice("obsync: key protection updated.");
          } catch (e) {
            new Notice(`obsync: ${(e as Error).message}`, 8000);
          }
          this.display();
        });
      });
    if (current === "safe" && this.plugin.touchIdAvailable()) {
      new Setting(el)
        .setName("Require Touch ID to unlock")
        .setDesc("Prompts before the keychain entry is used at launch.")
        .addToggle((t) => t.setValue(s.protection.touchId).onChange((v) => this.run(() => this.plugin.setProtection("safe", { touchId: v }))));
    }

    el.createEl("h3", { text: "Advanced" });
    new Setting(el)
      .setName("Compress text before encrypting")
      .setDesc("Smaller uploads for notes at some CPU cost. Safe to toggle at any time.")
      .addToggle((t) => t.setValue(s.compress).onChange(async (v) => ((s.compress = v), await this.plugin.saveSettings(), this.plugin.restartEngine())));
    new Setting(el)
      .setName("Pad file sizes")
      .setDesc("Rounds encrypted sizes up to 4 KiB so the server cannot infer exact note lengths. Costs storage.")
      .addToggle((t) => t.setValue(s.pad).onChange(async (v) => ((s.pad = v), await this.plugin.saveSettings(), this.plugin.restartEngine())));
    new Setting(el)
      .setName("Typing debounce (ms)")
      .setDesc("How long after the last edit before it is uploaded.")
      .addText((t) =>
        t.setValue(String(s.debounceMs)).onChange(async (v) => {
          const n = Number(v);
          if (Number.isFinite(n) && n >= 200) ((s.debounceMs = n), await this.plugin.saveSettings(), this.plugin.restartEngine());
        }),
      );
    new Setting(el)
      .setName("Rebuild local state")
      .setDesc("Forgets what this device thinks it has synced and re-derives it by hashing every file. Safe; uploads nothing that already matches.")
      .addButton((b) => b.setButtonText("Rebuild").onClick(() => this.run(() => this.plugin.engine!.rebuildState())));
    new Setting(el)
      .setName("Leave this vault")
      .setDesc("Stops syncing and forgets the keys and token on this device. Files stay on disk. Remove this device from another device afterwards to rotate keys.")
      .addButton((b) =>
        b
          .setButtonText("Leave")
          .setWarning()
          .onClick(async () => {
            if (await ConfirmModal.ask(this.app, "Leave vault?", "This device will stop syncing. Your files are not deleted.", "Leave")) {
              await this.plugin.leaveVault();
              this.display();
            }
          }),
      );
  }

  /**
   * Plain http is fine on localhost or a private network you trust; over the
   * internet it hands your device token to every network in between. Ask.
   */
  private async plainHttpOk(url: string): Promise<boolean> {
    if (!/^http:\/\//i.test(url.trim())) return true;
    if (/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/i.test(url.trim())) return true;
    return ConfirmModal.ask(
      this.app,
      "Use an unencrypted connection?",
      "This server URL starts with http://, not https://. Your notes stay end-to-end encrypted, but the device token travels in the clear and anyone on the network path could use it to read the encrypted vault or post data. Only do this on a network you trust.",
      "Use http anyway",
    );
  }

  private async run(fn: () => Promise<unknown>): Promise<void> {
    try {
      await fn();
      this.display();
    } catch (e) {
      console.error("obsync", e);
      new Notice(`obsync: ${(e as Error).message}`, 8000);
    }
  }
}
