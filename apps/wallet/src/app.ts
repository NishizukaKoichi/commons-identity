import { icon } from "./icons";
import type { WalletStore } from "./state";
import type {
  ConsentReceipt,
  Credential,
  Device,
  Persona,
  ScreenId,
  WalletState,
} from "./types";
import { escapeHtml, validateRecoveryPassphrase } from "./validation";

interface NavigationItem {
  id: ScreenId;
  label: string;
  icon: Parameters<typeof icon>[0];
}

const primaryNavigation: NavigationItem[] = [
  { id: "identity", label: "Personas", icon: "identity" },
  { id: "presentation", label: "Share request", icon: "presentation" },
  { id: "devices", label: "Devices", icon: "devices" },
  { id: "recovery", label: "Recovery", icon: "recovery" },
  { id: "receipts", label: "Receipts", icon: "receipts" },
];

const secondaryNavigation: NavigationItem[] = [
  { id: "settings", label: "Settings & export", icon: "settings" },
  { id: "onboarding", label: "Vault setup", icon: "onboarding" },
];

const screenTitles: Record<ScreenId, { eyebrow: string; title: string }> = {
  identity: { eyebrow: "Identity vault", title: "Personas & credentials" },
  presentation: { eyebrow: "Consent required", title: "Share request" },
  devices: { eyebrow: "Vault access", title: "Trusted devices" },
  recovery: { eyebrow: "Recovery", title: "Plan for loss" },
  receipts: { eyebrow: "Private history", title: "Consent receipts" },
  settings: { eyebrow: "Wallet", title: "Settings & export" },
  onboarding: { eyebrow: "First run", title: "Create your vault" },
};

export function mountWallet(root: HTMLElement, store: WalletStore): () => void {
  let lastScreen: ScreenId | null = null;
  let lastPersonaId: string | null = null;
  let dialogReturnDeviceId: string | null = null;

  const render = (state: Readonly<WalletState>) => {
    const initial = lastScreen === null;
    const screenChanged = !initial && lastScreen !== state.screen;
    const personaChanged =
      lastPersonaId !== null && lastPersonaId !== state.selectedPersonaId;
    lastScreen = state.screen;
    lastPersonaId = state.selectedPersonaId;
    root.innerHTML = renderWallet(state, {
      initial,
      screenChanged,
      personaChanged,
    });

    if (screenChanged) {
      queueMicrotask(() =>
        root.querySelector<HTMLElement>(".screen-title")?.focus(),
      );
    }
    if (state.dialog) {
      queueMicrotask(() =>
        root.querySelector<HTMLElement>("[data-dialog-focus]")?.focus(),
      );
    }
  };

  const unsubscribe = store.subscribe(render);

  const closeDialogAndRestoreFocus = () => {
    const deviceId = dialogReturnDeviceId;
    dialogReturnDeviceId = null;
    store.closeDialog();
    queueMicrotask(() => {
      const triggers = root.querySelectorAll<HTMLElement>(
        '[data-action="open-revoke"]',
      );
      [...triggers].find((item) => item.dataset.value === deviceId)?.focus();
    });
  };

  const clickHandler = (event: MouseEvent) => {
    if (!(event.target instanceof Element)) return;
    const trigger = event.target.closest<HTMLElement>("[data-action]");
    if (!trigger) return;

    const action = trigger.dataset.action;
    const value = trigger.dataset.value ?? "";

    if (
      action === "close-dialog" &&
      trigger.classList.contains("dialog-backdrop") &&
      event.target !== trigger
    ) {
      return;
    }

    switch (action) {
      case "navigate":
        store.navigate(value as ScreenId);
        break;
      case "select-persona":
        store.selectPersona(value);
        break;
      case "select-credential":
        store.selectCredential(value);
        break;
      case "select-receipt":
        store.selectReceipt(value);
        break;
      case "approve-presentation": {
        const review = root.querySelector<HTMLInputElement>("#consent-review");
        if (review?.checked) store.approvePresentation();
        break;
      }
      case "open-revoke":
        dialogReturnDeviceId = value;
        store.openRevokeDialog(value);
        break;
      case "close-dialog":
        closeDialogAndRestoreFocus();
        break;
      case "confirm-revoke":
        dialogReturnDeviceId = null;
        store.confirmDeviceRevocation();
        queueMicrotask(() =>
          root.querySelector<HTMLElement>(".screen-title")?.focus(),
        );
        break;
      case "advance-onboarding":
        store.advanceOnboarding();
        break;
      case "restart-onboarding":
        store.restartOnboarding();
        break;
      case "simulate-archive-export":
        store.simulateArchiveExport();
        break;
      case "dismiss-toast":
        store.dismissToast();
        break;
    }
  };

  const changeHandler = (event: Event) => {
    if (!(event.target instanceof HTMLInputElement)) return;
    if (event.target.id === "consent-review") {
      const approve = root.querySelector<HTMLButtonElement>(
        "#approve-presentation",
      );
      if (approve) approve.disabled = !event.target.checked;
    }
  };

  const submitHandler = (event: SubmitEvent) => {
    if (!(event.target instanceof HTMLFormElement)) return;
    event.preventDefault();

    if (event.target.id === "recovery-export-form") {
      submitRecoveryForm(event.target, store);
    }

    if (event.target.id === "vault-create-form") {
      const data = new FormData(event.target);
      store.completeOnboarding(String(data.get("vault-label") ?? ""));
    }
  };

  const keyHandler = (event: KeyboardEvent) => {
    if (!store.getState().dialog) return;

    if (event.key === "Escape") {
      closeDialogAndRestoreFocus();
      return;
    }

    if (event.key !== "Tab") return;
    const dialog = root.querySelector<HTMLElement>('[role="dialog"]');
    if (!dialog) return;
    const focusable = [
      ...dialog.querySelectorAll<HTMLElement>(
        'button:not([disabled]), input:not([disabled]), [href], [tabindex]:not([tabindex="-1"])',
      ),
    ];
    const first = focusable[0];
    const last = focusable.at(-1);
    if (!first || !last) return;

    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    } else if (!dialog.contains(document.activeElement)) {
      event.preventDefault();
      first.focus();
    }
  };

  root.addEventListener("click", clickHandler);
  root.addEventListener("change", changeHandler);
  root.addEventListener("submit", submitHandler);
  document.addEventListener("keydown", keyHandler);

  return () => {
    unsubscribe();
    root.removeEventListener("click", clickHandler);
    root.removeEventListener("change", changeHandler);
    root.removeEventListener("submit", submitHandler);
    document.removeEventListener("keydown", keyHandler);
  };
}

function submitRecoveryForm(form: HTMLFormElement, store: WalletStore): void {
  const passphrase = form.elements.namedItem("recovery-passphrase");
  const confirmation = form.elements.namedItem("recovery-confirmation");
  const error = form.querySelector<HTMLElement>("#recovery-error");

  if (!(passphrase instanceof HTMLInputElement)) return;
  if (!(confirmation instanceof HTMLInputElement)) return;

  const validation = validateRecoveryPassphrase(
    passphrase.value,
    confirmation.value,
  );
  passphrase.value = "";
  confirmation.value = "";

  if (!validation.valid) {
    if (error) {
      error.textContent = validation.message;
      error.hidden = false;
    }
    passphrase.focus();
    return;
  }

  store.simulateRecoveryExport();
}

interface RenderMotion {
  initial: boolean;
  screenChanged: boolean;
  personaChanged: boolean;
}

const settledMotion: RenderMotion = {
  initial: false,
  screenChanged: false,
  personaChanged: false,
};

export function renderWallet(
  state: Readonly<WalletState>,
  motion: RenderMotion = settledMotion,
): string {
  const title = screenTitles[state.screen];
  const modeClass =
    state.runtime.mode === "browser-preview" ? "is-preview" : "is-desktop";
  const motionClasses = [
    motion.initial ? "is-initial" : "",
    motion.screenChanged ? "is-screen-changing" : "",
    motion.personaChanged ? "is-persona-changing" : "",
  ]
    .filter(Boolean)
    .join(" ");

  return `
    <a class="skip-link" href="#main-content">Skip to content</a>
    <div class="wallet-shell ${modeClass} ${motionClasses}">
      ${renderSidebar(state)}
      <div class="workspace">
        ${renderRuntimeNotice(state)}
        <header class="workspace-header">
          <div>
            <p class="eyebrow">${title.eyebrow}</p>
            <h1 class="screen-title" tabindex="-1">${title.title}</h1>
          </div>
          <div class="protocol-mark" aria-label="Protocol version">
            <span class="protocol-dot" aria-hidden="true"></span>
            commons-identity/1
          </div>
        </header>
        <main class="screen" id="main-content">
          ${renderScreen(state)}
        </main>
      </div>
      ${state.toast ? renderToast(state.toast) : ""}
      ${state.dialog ? renderRevokeDialog(state) : ""}
    </div>
  `;
}

function renderSidebar(state: Readonly<WalletState>): string {
  return `
    <aside class="sidebar">
      <div class="brand-lockup">
        <div class="brand-seal" aria-hidden="true"><span>CI</span></div>
        <div>
          <strong>Commons Wallet</strong>
          <span>Held by you</span>
        </div>
      </div>

      <nav class="navigation" aria-label="Wallet navigation">
        <div class="nav-group">
          <span class="nav-label">Your identity</span>
          ${primaryNavigation.map((item) => renderNavigationItem(item, state.screen)).join("")}
        </div>
        <div class="nav-group nav-group-secondary">
          <span class="nav-label">Wallet</span>
          ${secondaryNavigation.map((item) => renderNavigationItem(item, state.screen)).join("")}
        </div>
      </nav>

      <footer class="sidebar-footer">
        <span class="quiet-status"><i></i> Local-first shell</span>
        <span>Reference implementation · 0.1.0-preview.2</span>
      </footer>
    </aside>
  `;
}

function renderNavigationItem(
  item: NavigationItem,
  activeScreen: ScreenId,
): string {
  const active = item.id === activeScreen;
  return `
    <button
      class="nav-item${active ? " is-active" : ""}"
      type="button"
      data-action="navigate"
      data-value="${item.id}"
      ${active ? 'aria-current="page"' : ""}
    >
      ${icon(item.icon)}
      <span>${item.label}</span>
    </button>
  `;
}

function renderRuntimeNotice(state: Readonly<WalletState>): string {
  if (state.runtime.mode === "browser-preview") {
    return `
      <section class="runtime-notice" role="status" aria-label="Preview safety notice">
        <strong>Safe interactive preview</strong>
        <span>Developer Preview · seeded fictional data only. No keys are created, uploaded, or saved.</span>
        <span class="runtime-mode">Browser mode</span>
      </section>
    `;
  }

  return `
    <section class="runtime-notice" role="status" aria-label="Desktop prototype notice">
      <strong>Desktop prototype</strong>
      <span>The native shell is running; secure Core commands are not connected yet.</span>
      <span class="runtime-mode">Tauri 2</span>
    </section>
  `;
}

function renderScreen(state: Readonly<WalletState>): string {
  switch (state.screen) {
    case "identity":
      return renderIdentity(state);
    case "presentation":
      return renderPresentation();
    case "devices":
      return renderDevices(state.devices);
    case "recovery":
      return renderRecovery();
    case "receipts":
      return renderReceipts(state);
    case "settings":
      return renderSettings(state);
    case "onboarding":
      return renderOnboarding(state);
  }
}

function renderIdentity(state: Readonly<WalletState>): string {
  const persona =
    state.personas.find((item) => item.id === state.selectedPersonaId) ??
    state.personas[0];
  if (!persona)
    return renderEmpty(
      "No personas yet",
      "Create a vault to add your first persona.",
    );

  const credential =
    persona.credentials.find(
      (item) => item.id === state.selectedCredentialId,
    ) ?? persona.credentials[0];

  return `
    <section class="screen-intro">
      <div>
        <p class="section-kicker">Context boundaries</p>
        <h2>One vault. Separate relationships.</h2>
        <p>Each community sees only the persona and credentials you use with it.</p>
      </div>
      <div class="privacy-legend">
        <span class="boundary-symbol" aria-hidden="true"></span>
        Boundaries never merge automatically
      </div>
    </section>

    <div class="persona-switcher" role="group" aria-label="Choose a community persona">
      ${state.personas.map((item) => renderPersonaButton(item, persona.id)).join("")}
    </div>

    <section class="persona-boundary" aria-labelledby="persona-heading">
      <header class="persona-heading">
        <div>
          <span class="boundary-caption">Active boundary</span>
          <h2 id="persona-heading">${escapeHtml(persona.community)}</h2>
          <p>${escapeHtml(persona.name)} · ${escapeHtml(persona.localSubjectHint)}</p>
        </div>
        <div class="boundary-assurance">
          <span>${String(persona.credentialCount).padStart(2, "0")}</span>
          <small>credentials in this boundary</small>
        </div>
      </header>

      <div class="credential-workspace">
        <div class="credential-list" aria-label="Credentials">
          <div class="list-heading">
            <h3>Credentials</h3>
            <span>Current</span>
          </div>
          ${persona.credentials.map((item) => renderCredentialRow(item, credential?.id ?? "")).join("")}
        </div>
        ${credential ? renderCredentialDetail(credential) : ""}
      </div>
    </section>
  `;
}

function renderPersonaButton(persona: Persona, selectedId: string): string {
  const selected = persona.id === selectedId;
  return `
    <button
      class="persona-tab${selected ? " is-selected" : ""}"
      type="button"
      data-action="select-persona"
      data-value="${escapeHtml(persona.id)}"
      aria-pressed="${String(selected)}"
    >
      <span class="persona-index">${persona.community.slice(0, 1)}</span>
      <span>
        <strong>${escapeHtml(persona.name)}</strong>
        <small>${persona.credentialCount} credentials</small>
      </span>
    </button>
  `;
}

function renderCredentialRow(
  credential: Credential,
  selectedId: string,
): string {
  const selected = credential.id === selectedId;
  return `
    <button
      class="credential-row${selected ? " is-selected" : ""}"
      type="button"
      data-action="select-credential"
      data-value="${escapeHtml(credential.id)}"
      aria-pressed="${String(selected)}"
    >
      <span class="credential-kind">${escapeHtml(credential.type)}</span>
      <span class="credential-name">${escapeHtml(credential.label)}</span>
      <span class="credential-validity">Until ${escapeHtml(credential.validUntil)}</span>
      ${icon("chevron")}
    </button>
  `;
}

function renderCredentialDetail(credential: Credential): string {
  return `
    <aside class="credential-detail" aria-label="Selected credential detail">
      <div class="detail-status"><i></i> ${escapeHtml(credential.status)}</div>
      <p class="section-kicker">${escapeHtml(credential.type)} credential</p>
      <h3>${escapeHtml(credential.label)}</h3>
      <dl class="detail-ledger">
        <div><dt>Issuer</dt><dd>${escapeHtml(credential.issuer)}</dd></div>
        <div><dt>Valid until</dt><dd>${escapeHtml(credential.validUntil)}</dd></div>
        <div><dt>Policy</dt><dd>${escapeHtml(credential.policy)}</dd></div>
      </dl>
      <div class="scope-list">
        <span>What it permits</span>
        <ul>${credential.scopes.map((scope) => `<li>${icon("check")}${escapeHtml(scope)}</li>`).join("")}</ul>
      </div>
      <p class="detail-note">This instance is bound only to this device key and community persona.</p>
    </aside>
  `;
}

function renderPresentation(): string {
  return `
    <section class="consent-composition" aria-labelledby="consent-heading">
      <div class="consent-primary">
        <p class="section-kicker">Request 08 · awaiting you</p>
        <h2 id="consent-heading">Share two facts?</h2>
        <p class="consent-lede">Example Research Archive needs proof before opening a protected document.</p>

        <div class="request-ledger">
          ${renderRequestRow("Who", "Example Research Archive", "Verified service in your research community")}
          ${renderRequestRow("Why", "Open a protected research document", "Purpose declared by the verifier")}
          ${renderRequestRow("Retained", "5 minutes", "Presentation token deleted after verification")}
          ${renderRequestRow("Shared onward", "No", "The verifier declares no third-party sharing")}
          ${renderRequestRow("Linkability", "Community boundary", "CI-Core can be correlated inside this community")}
        </div>

        <div class="consent-check">
          <label for="consent-review">
            <input id="consent-review" type="checkbox" />
            <span>
              <strong>I reviewed who receives these facts and why.</strong>
              <small>This preview records consent locally; it sends nothing.</small>
            </span>
          </label>
        </div>

        <div class="button-row">
          <button class="button button-secondary" type="button" data-action="navigate" data-value="identity">Not now</button>
          <button class="button button-primary" id="approve-presentation" type="button" data-action="approve-presentation" disabled>
            Approve preview ${icon("arrow")}
          </button>
        </div>
      </div>

      <aside class="consent-inspector" aria-label="Facts to be shared">
        <p class="section-kicker">Only these facts</p>
        <ol class="claim-list">
          <li><span>01</span><div><strong>Current member</strong><small>Example Research Community</small></div>${icon("check")}</li>
          <li><span>02</span><div><strong>Can read archive documents</strong><small>Scope: archive:read</small></div>${icon("check")}</li>
        </ol>

        <div class="not-shared">
          <span>Not shared</span>
          <p>Name · email · phone · other communities · credential inventory</p>
        </div>

        <div class="core-limit">
          <span>CI-Core privacy limit</span>
          <p>Services inside this community may correlate this presentation. <code>none</code> and verifier-domain pseudonyms require the future CI-Private-BBS profile and are unavailable here.</p>
        </div>

        <div class="linkability-diagram" aria-label="Community linkability boundary">
          <div><i>R</i><span>Research persona</span></div>
          <span class="link-line"><small>community context</small></span>
          <div><i>C</i><span>Community services</span></div>
        </div>
        <p class="inspector-note">Keys remain separate from every other community, but CI-Core does not promise unlinkability between services in this one.</p>
      </aside>
    </section>
  `;
}

function renderRequestRow(label: string, value: string, note: string): string {
  return `<div><span>${label}</span><strong>${value}</strong><small>${note}</small></div>`;
}

function renderDevices(deviceItems: Device[]): string {
  const activeCount = deviceItems.filter(
    (device) => device.status !== "revoked",
  ).length;
  return `
    <section class="screen-intro">
      <div>
        <p class="section-kicker">Device-bound credentials</p>
        <h2>${activeCount} devices can open this vault.</h2>
        <p>Each device has its own key. Revoking one leaves every other device intact.</p>
      </div>
      <div class="count-mark"><strong>${String(activeCount).padStart(2, "0")}</strong><span>trusted</span></div>
    </section>

    <section class="device-register" aria-label="Device register">
      <div class="register-heading">
        <span>Device</span><span>Key & activity</span><span>Credentials</span><span>Action</span>
      </div>
      ${deviceItems.map(renderDeviceRow).join("")}
    </section>

    <aside class="plain-note">
      <span class="note-number">i</span>
      <p><strong>Lost a device?</strong> Revocation targets that device key and its credential instances. Persona secrets can then be rotated separately.</p>
    </aside>
  `;
}

function renderDeviceRow(device: Device): string {
  return `
    <article class="device-row${device.status === "revoked" ? " is-revoked" : ""}">
      <div class="device-name">
        <span class="device-glyph">${icon("devices")}</span>
        <div><strong>${escapeHtml(device.name)}</strong><small>${escapeHtml(device.kind)}</small></div>
      </div>
      <div class="device-activity">
        <strong>${escapeHtml(device.lastSeen)}</strong>
        <small>${escapeHtml(device.location)} · ${escapeHtml(device.keyHint)}</small>
      </div>
      <div class="device-count"><strong>${device.credentials}</strong><small>instances</small></div>
      <div class="device-action">
        ${
          device.status === "current"
            ? '<span class="current-marker">This device</span>'
            : device.status === "revoked"
              ? '<span class="revoked-marker">Revoked</span>'
              : `<button class="text-button danger-action" type="button" data-action="open-revoke" data-value="${escapeHtml(device.id)}">Revoke</button>`
        }
      </div>
    </article>
  `;
}

function renderRecovery(): string {
  return `
    <section class="recovery-layout">
      <div class="recovery-kit">
        <p class="section-kicker">Encrypted Recovery Kit</p>
        <h2>Keep one copy away from this Mac.</h2>
        <p>The final kit uses Argon2id and XChaCha20-Poly1305. Its passphrase must be stored separately.</p>

        <form class="secure-form" id="recovery-export-form" novalidate>
          <div class="field-group">
            <label for="recovery-passphrase">Temporary preview passphrase</label>
            <input
              id="recovery-passphrase"
              name="recovery-passphrase"
              type="password"
              minlength="12"
              autocomplete="new-password"
              aria-describedby="passphrase-help recovery-error"
              required
            />
            <small id="passphrase-help">Checked in this page only, cleared immediately, never persisted.</small>
          </div>
          <div class="field-group">
            <label for="recovery-confirmation">Confirm passphrase</label>
            <input
              id="recovery-confirmation"
              name="recovery-confirmation"
              type="password"
              minlength="12"
              autocomplete="new-password"
              required
            />
          </div>
          <p class="field-error" id="recovery-error" role="alert" hidden></p>
          <button class="button button-primary" type="submit">Test Recovery Kit export ${icon("arrow")}</button>
        </form>

        <div class="encryption-facts" aria-label="Recovery Kit encryption settings">
          <div><span>KDF</span><strong>Argon2id</strong></div>
          <div><span>Memory</span><strong>256 MiB</strong></div>
          <div><span>Cipher</span><strong>XChaCha20</strong></div>
        </div>
      </div>

      <aside class="guardian-panel" aria-labelledby="guardian-heading">
        <p class="section-kicker">Guardian recovery · planned design</p>
        <h2 id="guardian-heading">Future 3-of-5 recovery.</h2>
        <p>If implemented and audited, Guardians would hold encrypted shares without seeing your vault or community memberships. This preview does not create or distribute shares.</p>
        <div class="guardian-threshold" aria-label="Three of five guardians required">
          ${["A", "B", "C", "D", "E"].map((label, index) => `<div class="guardian${index < 3 ? " is-quorum" : ""}"><span>${label}</span><small>Guardian ${label}</small></div>`).join("")}
        </div>
        <div class="threshold-rule">
          <span>Planned normal policy</span><strong>3 approvals</strong><small>Proposed 72-hour safety delay</small>
        </div>
        <div class="threshold-rule">
          <span>Planned emergency policy</span><strong>4 approvals</strong><small>Proposed 24-hour safety delay</small>
        </div>
        <button class="text-button" type="button" disabled>Guardian setup joins Core in the next milestone</button>
      </aside>
    </section>
  `;
}

function renderReceipts(state: Readonly<WalletState>): string {
  const selected =
    state.receipts.find((receipt) => receipt.id === state.selectedReceiptId) ??
    state.receipts[0];
  if (!selected)
    return renderEmpty(
      "No receipts yet",
      "Your consent history stays in this vault.",
    );

  return `
    <section class="screen-intro compact-intro">
      <div>
        <p class="section-kicker">Visible only to you</p>
        <h2>What you shared, and why.</h2>
        <p>Receipts are private records inside your vault—not a public activity log.</p>
      </div>
      <div class="count-mark"><strong>${String(state.receipts.length).padStart(2, "0")}</strong><span>receipts</span></div>
    </section>

    <div class="receipt-workspace">
      <div class="receipt-list" aria-label="Consent receipts">
        ${state.receipts.map((receipt) => renderReceiptRow(receipt, selected.id)).join("")}
      </div>
      ${renderReceiptDetail(selected)}
    </div>
  `;
}

function renderReceiptRow(receipt: ConsentReceipt, selectedId: string): string {
  const selected = receipt.id === selectedId;
  return `
    <button
      type="button"
      class="receipt-row${selected ? " is-selected" : ""}"
      data-action="select-receipt"
      data-value="${escapeHtml(receipt.id)}"
      aria-pressed="${String(selected)}"
    >
      <span class="receipt-date">${escapeHtml(receipt.createdAt)}</span>
      <strong>${escapeHtml(receipt.verifier)}</strong>
      <small>${escapeHtml(receipt.purpose)}</small>
      ${icon("chevron")}
    </button>
  `;
}

function renderReceiptDetail(receipt: ConsentReceipt): string {
  return `
    <article class="receipt-paper" aria-label="Selected consent receipt">
      <header>
        <span class="receipt-stamp">Consent receipt</span>
        <span>${escapeHtml(receipt.createdAt)}</span>
      </header>
      <h2>${escapeHtml(receipt.verifier)}</h2>
      <p>${escapeHtml(receipt.purpose)}</p>
      <dl class="receipt-ledger">
        <div><dt>Facts disclosed</dt><dd>${receipt.claims.map(escapeHtml).join("<br />")}</dd></div>
        <div><dt>Linkability</dt><dd>${escapeHtml(receipt.linkability)}</dd></div>
        <div><dt>Retention until</dt><dd>${escapeHtml(receipt.retentionUntil)}</dd></div>
        <div><dt>Onward sharing</dt><dd>${receipt.onwardSharing ? "Declared" : "None declared"}</dd></div>
        ${receipt.nymDomain ? `<div><dt>Pseudonym domain</dt><dd>${escapeHtml(receipt.nymDomain)}</dd></div>` : ""}
      </dl>
      <footer><span>Request fingerprint</span><code>${escapeHtml(receipt.requestHash)}</code></footer>
    </article>
  `;
}

function renderSettings(state: Readonly<WalletState>): string {
  return `
    <section class="settings-layout">
      <div class="settings-section archive-export">
        <p class="section-kicker">Commons Identity Archive</p>
        <h2>Leave with the whole vault.</h2>
        <p>An encrypted <code>.cia</code> archive is designed for import into any compatible wallet without operator permission.</p>
        <ul class="archive-contents">
          <li>${icon("check")} Encrypted identity vault and personas</li>
          <li>${icon("check")} Credential formats and schema snapshots</li>
          <li>${icon("check")} Device records and recovery configuration</li>
          <li>${icon("check")} Consent receipts and integrity manifest</li>
        </ul>
        <button class="button button-primary" type="button" data-action="simulate-archive-export">Test .cia archive export ${icon("arrow")}</button>
        <small class="action-caveat">Preview only—no file is written until secure Core export is connected.</small>
      </div>

      <div class="settings-column">
        <section class="settings-section">
          <div class="settings-heading"><div><p class="section-kicker">Privacy defaults</p><h2>Minimise first.</h2></div><span class="locked-setting">Protocol baseline</span></div>
          <dl class="settings-list">
            <div><dt>Presentation retention</dt><dd>5 minutes</dd></div>
            <div><dt>Derived claims retention</dt><dd>0 seconds</dd></div>
            <div><dt>Onward sharing</dt><dd>Off</dd></div>
            <div><dt>CI-Core linkability</dt><dd>Community</dd></div>
            <div><dt>Private-BBS modes</dt><dd>Unavailable</dd></div>
          </dl>
        </section>

        <section class="settings-section runtime-section">
          <p class="section-kicker">Runtime</p>
          <h2>${state.runtime.mode === "browser-preview" ? "Safe browser preview" : "Tauri desktop prototype"}</h2>
          <dl class="settings-list">
            <div><dt>Protocol</dt><dd>${escapeHtml(state.runtime.protocol)}</dd></div>
            <div><dt>Core connected</dt><dd>${state.runtime.coreConnected ? "Yes" : "Not yet"}</dd></div>
            <div><dt>Secret persistence</dt><dd>None</dd></div>
            <div><dt>Browser storage</dt><dd>Never used</dd></div>
          </dl>
          <button class="text-button" type="button" data-action="restart-onboarding">Review vault setup preview</button>
        </section>
      </div>
    </section>
  `;
}

function renderOnboarding(state: Readonly<WalletState>): string {
  if (state.onboardingStep === 0) {
    return `
      <section class="onboarding-page">
        <div class="onboarding-copy">
          <span class="folio">01 / 03</span>
          <p class="section-kicker">Before any community</p>
          <h2>Create a vault that stays yours.</h2>
          <p>Your Recovery Root never becomes an account number, never signs a credential, and never leaves the vault.</p>
          <button class="button button-primary" type="button" data-action="advance-onboarding">Begin safe preview ${icon("arrow")}</button>
        </div>
        <div class="vault-illustration" aria-label="Vault structure illustration">
          <div class="vault-ring ring-outer"><span>Recovery boundary</span></div>
          <div class="vault-ring ring-middle"><span>Device keys</span></div>
          <div class="vault-ring ring-inner"><strong>YOU</strong><span>root held locally</span></div>
          <div class="orbit-label orbit-one">Research</div>
          <div class="orbit-label orbit-two">Community</div>
          <div class="orbit-label orbit-three">Studio</div>
        </div>
      </section>
      ${renderOnboardingSteps(0)}
    `;
  }

  if (state.onboardingStep === 1) {
    return `
      <section class="onboarding-form-page">
        <div class="onboarding-copy">
          <span class="folio">02 / 03</span>
          <p class="section-kicker">Local preparation</p>
          <h2>Name this vault.</h2>
          <p>The name stays on this device. The browser preview generates no Recovery Root, key, or credential.</p>
        </div>
        <form class="vault-create-form" id="vault-create-form">
          <div class="field-group">
            <label for="vault-label">Vault label</label>
            <input id="vault-label" name="vault-label" type="text" maxlength="48" value="${escapeHtml(state.vaultLabel)}" autocomplete="off" />
            <small>This is a local label, not a global identifier.</small>
          </div>
          <div class="creation-summary">
            <div><span>Recovery Root</span><strong>256-bit random</strong><small>Native Core only</small></div>
            <div><span>Device signing</span><strong>Ed25519</strong><small>Per-device key</small></div>
            <div><span>Key agreement</span><strong>X25519</strong><small>Per-device key</small></div>
          </div>
          <label class="setup-acknowledgement">
            <input type="checkbox" required />
            <span>I understand this browser flow is a non-secret preview.</span>
          </label>
          <button class="button button-primary" type="submit">Prepare preview vault ${icon("arrow")}</button>
        </form>
      </section>
      ${renderOnboardingSteps(1)}
    `;
  }

  return `
    <section class="onboarding-complete">
      <div class="completion-seal">${icon("check")}</div>
      <span class="folio">03 / 03</span>
      <p class="section-kicker">Preview ready</p>
      <h2>${escapeHtml(state.vaultLabel)}</h2>
      <p>The interface is ready to explore with fictional credentials. No root secret or private key exists in this preview.</p>
      <div class="next-boundaries">
        <div><span>Next</span><strong>Review separated personas</strong></div>
        <div><span>Then</span><strong>Inspect a consent request</strong></div>
      </div>
      <button class="button button-primary" type="button" data-action="navigate" data-value="identity">Open personas ${icon("arrow")}</button>
    </section>
    ${renderOnboardingSteps(2)}
  `;
}

function renderOnboardingSteps(current: number): string {
  const labels = [
    "Understand the boundary",
    "Prepare this device",
    "Explore safely",
  ];
  return `<ol class="onboarding-steps" aria-label="Vault setup progress">${labels
    .map(
      (label, index) =>
        `<li class="${index === current ? "is-current" : ""}${index < current ? " is-complete" : ""}"><span>${String(index + 1).padStart(2, "0")}</span><strong>${label}</strong></li>`,
    )
    .join("")}</ol>`;
}

function renderRevokeDialog(state: Readonly<WalletState>): string {
  const device = state.devices.find(
    (item) => item.id === state.dialog?.deviceId,
  );
  if (!device) return "";

  return `
    <div class="dialog-backdrop" data-action="close-dialog">
      <section class="dialog" role="dialog" aria-modal="true" aria-labelledby="revoke-title" aria-describedby="revoke-description">
        <button class="dialog-close" type="button" data-action="close-dialog" aria-label="Close dialog">${icon("close")}</button>
        <span class="dialog-mark">Device revocation</span>
        <h2 id="revoke-title">Revoke ${escapeHtml(device.name)}?</h2>
        <p id="revoke-description">This preview marks only this device and its ${device.credentials} credential instances as revoked.</p>
        <div class="dialog-impact">
          <div><span>Will change</span><strong>${escapeHtml(device.name)}</strong></div>
          <div><span>Will stay</span><strong>Other devices and personas</strong></div>
        </div>
        <p class="dialog-caveat">Interactive preview only. No signed revocation request is sent.</p>
        <div class="button-row">
          <button class="button button-secondary" type="button" data-action="close-dialog" data-dialog-focus>Keep device</button>
          <button class="button button-danger" type="button" data-action="confirm-revoke">Revoke in preview</button>
        </div>
      </section>
    </div>
  `;
}

function renderToast(message: string): string {
  return `
    <div class="toast" role="status" aria-live="polite">
      <span class="toast-icon">${icon("check")}</span>
      <p>${escapeHtml(message)}</p>
      <button type="button" data-action="dismiss-toast" aria-label="Dismiss message">${icon("close")}</button>
    </div>
  `;
}

function renderEmpty(title: string, message: string): string {
  return `<section class="empty-state"><div class="brand-seal"><span>CI</span></div><h2>${escapeHtml(title)}</h2><p>${escapeHtml(message)}</p></section>`;
}
