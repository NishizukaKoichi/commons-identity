export type ScreenId =
  | "identity"
  | "presentation"
  | "devices"
  | "recovery"
  | "receipts"
  | "settings"
  | "onboarding";

export type CredentialStatus = "active" | "superseded" | "revoked";
export type DeviceStatus = "current" | "trusted" | "revoked";

export interface Credential {
  id: string;
  type: "Membership" | "Role" | "Capability" | "Qualification";
  label: string;
  issuer: string;
  validUntil: string;
  status: CredentialStatus;
  scopes: string[];
  policy: string;
}

export interface Persona {
  id: string;
  name: string;
  community: string;
  localSubjectHint: string;
  credentialCount: number;
  credentials: Credential[];
}

export interface Device {
  id: string;
  name: string;
  kind: string;
  location: string;
  lastSeen: string;
  addedAt: string;
  keyHint: string;
  credentials: number;
  status: DeviceStatus;
}

export interface ConsentReceipt {
  id: string;
  verifier: string;
  purpose: string;
  claims: string[];
  createdAt: string;
  retentionUntil: string;
  onwardSharing: boolean;
  linkability: "none" | "verifier-domain" | "community";
  nymDomain?: string;
  requestHash: string;
}

export interface RuntimeInfo {
  mode: "browser-preview" | "desktop-prototype";
  protocol: string;
  appVersion: string;
  seededData: boolean;
  secretPersistence: "none";
  coreConnected: boolean;
}

export interface DialogState {
  kind: "revoke-device";
  deviceId: string;
}

export interface WalletState {
  screen: ScreenId;
  runtime: RuntimeInfo;
  personas: Persona[];
  selectedPersonaId: string;
  selectedCredentialId: string;
  devices: Device[];
  receipts: ConsentReceipt[];
  selectedReceiptId: string;
  onboardingStep: 0 | 1 | 2;
  vaultLabel: string;
  dialog: DialogState | null;
  toast: string | null;
}
