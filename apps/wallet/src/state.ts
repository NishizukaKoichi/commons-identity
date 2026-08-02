import { createSeedState } from "./data";
import type { RuntimeInfo, ScreenId, WalletState } from "./types";

type Listener = (state: Readonly<WalletState>) => void;
type Clock = () => Date;

/**
 * UI-only, in-memory preview state. Secret material is deliberately excluded and
 * no browser storage API is used here. Production vault state will live in Rust.
 */
export class WalletStore {
  private state: WalletState;
  private readonly listeners = new Set<Listener>();
  private readonly clock: Clock;

  constructor(
    initialState = createSeedState(),
    clock: Clock = () => new Date(),
  ) {
    this.state = initialState;
    this.clock = clock;
  }

  getState(): Readonly<WalletState> {
    return this.state;
  }

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    listener(this.state);
    return () => this.listeners.delete(listener);
  }

  navigate(screen: ScreenId): void {
    this.patch({ screen, dialog: null, toast: null });
  }

  selectPersona(personaId: string): void {
    const persona = this.state.personas.find((item) => item.id === personaId);
    if (!persona) return;

    this.patch({
      selectedPersonaId: persona.id,
      selectedCredentialId: persona.credentials[0]?.id ?? "",
    });
  }

  selectCredential(credentialId: string): void {
    const persona = this.state.personas.find(
      (item) => item.id === this.state.selectedPersonaId,
    );
    if (!persona?.credentials.some((item) => item.id === credentialId)) return;
    this.patch({ selectedCredentialId: credentialId });
  }

  selectReceipt(receiptId: string): void {
    if (!this.state.receipts.some((receipt) => receipt.id === receiptId))
      return;
    this.patch({ selectedReceiptId: receiptId });
  }

  approvePresentation(): void {
    const now = this.clock();
    const retention = new Date(now.getTime() + 5 * 60 * 1000);
    const id = `receipt-preview-${now.getTime()}`;
    const receipt = {
      id,
      verifier: "Example Research Archive",
      purpose: "Open a protected research document",
      claims: ["Active membership", "Archive read permission"],
      createdAt: this.formatReceiptTime(now),
      retentionUntil: this.formatReceiptTime(retention),
      onwardSharing: false,
      linkability: "community" as const,
      requestHash: "sha256 · preview-only",
    };

    this.patch({
      receipts: [receipt, ...this.state.receipts],
      selectedReceiptId: id,
      toast: "Preview approved. A local consent receipt was added.",
    });
  }

  openRevokeDialog(deviceId: string): void {
    const device = this.state.devices.find((item) => item.id === deviceId);
    if (!device || device.status === "current" || device.status === "revoked") {
      return;
    }
    this.patch({ dialog: { kind: "revoke-device", deviceId } });
  }

  closeDialog(): void {
    this.patch({ dialog: null });
  }

  confirmDeviceRevocation(): void {
    const deviceId = this.state.dialog?.deviceId;
    if (!deviceId) return;

    const devices = this.state.devices.map((device) =>
      device.id === deviceId && device.status !== "current"
        ? { ...device, status: "revoked" as const, credentials: 0 }
        : device,
    );
    this.patch({
      devices,
      dialog: null,
      toast:
        "Preview revocation recorded. Other device credentials are unchanged.",
    });
  }

  advanceOnboarding(): void {
    const nextStep = Math.min(2, this.state.onboardingStep + 1) as 0 | 1 | 2;
    this.patch({ onboardingStep: nextStep });
  }

  restartOnboarding(): void {
    this.patch({ screen: "onboarding", onboardingStep: 0, toast: null });
  }

  completeOnboarding(vaultLabel: string): void {
    const safeLabel = vaultLabel.trim().slice(0, 48) || "My identity vault";
    this.patch({
      onboardingStep: 2,
      vaultLabel: safeLabel,
      toast: "Preview vault prepared. No key material was generated.",
    });
  }

  simulateRecoveryExport(): void {
    this.patch({
      toast: "Recovery Kit preview complete. No file or secret was created.",
    });
  }

  simulateArchiveExport(): void {
    this.patch({
      toast:
        "Archive export preview complete. Core export will produce an encrypted .cia file.",
    });
  }

  dismissToast(): void {
    this.patch({ toast: null });
  }

  setRuntime(runtime: RuntimeInfo): void {
    this.patch({ runtime });
  }

  private patch(next: Partial<WalletState>): void {
    this.state = { ...this.state, ...next };
    for (const listener of this.listeners) listener(this.state);
  }

  private formatReceiptTime(date: Date): string {
    return new Intl.DateTimeFormat("en-AU", {
      day: "numeric",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
      timeZone: "Australia/Sydney",
    })
      .format(date)
      .replace(",", " ·");
  }
}
