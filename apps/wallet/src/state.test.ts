import { createSeedState } from "./data";
import { WalletStore } from "./state";

describe("WalletStore", () => {
  it("switches persona and keeps credential selection inside that boundary", () => {
    const store = new WalletStore();

    store.selectPersona("persona-neighbourhood");

    expect(store.getState().selectedPersonaId).toBe("persona-neighbourhood");
    expect(store.getState().selectedCredentialId).toBe("cred-resident");
    store.selectCredential("cred-membership");
    expect(store.getState().selectedCredentialId).toBe("cred-resident");
  });

  it("adds a local receipt when the presentation preview is approved", () => {
    const now = new Date("2026-08-02T00:00:00Z");
    const store = new WalletStore(createSeedState(), () => now);
    const previousCount = store.getState().receipts.length;

    store.approvePresentation();

    expect(store.getState().receipts).toHaveLength(previousCount + 1);
    expect(store.getState().receipts[0]?.verifier).toBe(
      "Example Research Archive",
    );
    expect(store.getState().receipts[0]?.linkability).toBe("community");
    expect(store.getState().toast).toContain("Preview approved");
  });

  it("cannot revoke the current device but isolates another revocation", () => {
    const store = new WalletStore();

    store.openRevokeDialog("device-mac");
    expect(store.getState().dialog).toBeNull();

    store.openRevokeDialog("device-phone");
    store.confirmDeviceRevocation();

    expect(
      store.getState().devices.find((device) => device.id === "device-phone")
        ?.status,
    ).toBe("revoked");
    expect(
      store.getState().devices.find((device) => device.id === "device-laptop")
        ?.status,
    ).toBe("trusted");
  });

  it("sanitises the non-secret local vault label", () => {
    const store = new WalletStore();
    store.completeOnboarding("   A small local vault   ");
    expect(store.getState().vaultLabel).toBe("A small local vault");
    expect(store.getState().onboardingStep).toBe(2);
  });
});
