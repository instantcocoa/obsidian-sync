/** The settings tab: enrolment when not joined, status and options when joined. */
import { parseInviteLink, parseCreateLink, isCreateLink } from "../core/crypto";
import { Notice, PluginSettingTab, Setting } from "obsidian";
import type ObsyncPlugin from "./main";
import { DEFAULT_EXCLUSIONS } from "../core/paths";
import { ConfirmModal, PromptModal, confirmPlainHttp } from "./modals";

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
    el.createEl("p", { text: "Paste an invite link from a device that is already syncing, or a create link from your server to start a new vault." });

    let link = "";
    new Setting(el)
      .setName("Join or create with a link")
      .setDesc("obsync://join#… from another device's “Generate invite link” (it contains the vault keys; discard it after use), or obsync://create#… printed by `obsync vault create` on the server or by its admin page.")
      .addText((t) => t.setPlaceholder("obsync://join#… or obsync://create#…").onChange((v) => (link = v.trim())))
      .addButton((b) =>
        b
          .setButtonText("Connect")
          .setCta()
          .onClick(async () => {
            // The link names the server; an http:// one needs the same consent as the other entry points.
            const create = isCreateLink(link);
            let server = "";
            try {
              server = create ? parseCreateLink(link).server : parseInviteLink(link).server;
            } catch {
              /* the join/create call reports the malformed link */
            }
            if (!server || (await this.plainHttpOk(server))) await this.run(() => (create ? this.plugin.createVault(link) : this.plugin.joinWithLink(link)));
          }),
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
      .setDesc("First device only. On the server run `obsync vault create`, or sign in to https://<server>/admin with your security key and press Create link; then scan the QR code with this device's camera, or paste the obsync://create#… link above. The vault keys are made on this device; the server never sees them.");

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
      .setDesc("For another device. Valid for one hour, single use, and a key rotation ends it early. Show the QR code to the device, or send the link over a channel you trust.")
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
                { name: "PIN (8+ characters; letters and digits)", secret: true },
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
    // Rendered from the value the plugin fetched at engine start. Updating
    // this row's description after display() wedged Obsidian's renderer in
    // the headless suite (deterministically, and only for this row); the
    // static form is also simply correct, since display() reruns on open.
    const hasAuth = this.plugin.vaultHasAuth;
    new Setting(el)
      .setName("Write protection (vault authority)")
      .setDesc(
        hasAuth === false
          ? "Off: this vault was created by an older server version, so the server cannot yet tell key-holding devices from anyone with a token, and accepts no changes until it can. Copy the command below and run it on the server as the admin, replacing <data-dir> with the server's --data directory, then sync again."
          : hasAuth === true
            ? "On. The server only accepts changes from devices that hold this vault's keys, so a stolen device token alone cannot modify or delete anything. You only need the command below if the plugin reports that this vault was created by an older server."
            : "Not checked yet (the server was not reachable at startup).",
      )
      .addButton((b) =>
        b.setButtonText("Copy command").onClick(async () => {
          const tok = await this.plugin.vaultAuthorityToken();
          await navigator.clipboard.writeText(`obsync vault auth --data <data-dir> ${id.vaultId} ${tok}`);
          new Notice(hasAuth === false ? "obsync: command copied. Run it on the server, replace <data-dir>, then sync again." : "obsync: command copied. Only needed if the plugin asked for it.");
        }),
      );
    new Setting(el)
      .setName("Sync notices")
      .setDesc("Show a notice when sync resolves a conflict or applies settings from another device. Errors, anything that needs your decision, and a synced plugin being enabled or reloaded on this device (code from another device starting to run) are always shown.")
      .addToggle((t) => t.setValue(s.syncNotices).onChange(async (v) => ((s.syncNotices = v), await this.plugin.saveSettings())));
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
      .setName("Reset this device to the server's copy")
      .setDesc("One-way: this device's files become exactly what the server has; nothing is uploaded. Local edits the server lacks and files that exist only here are moved to .trash/obsync-reset-<time>/, not deleted.")
      .addButton((b) =>
        b
          .setButtonText("Reset…")
          .setWarning()
          .onClick(() => this.run(() => this.plugin.cmdResetToServer())),
      );
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
  private plainHttpOk(url: string): Promise<boolean> {
    return confirmPlainHttp(this.app, url);
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
