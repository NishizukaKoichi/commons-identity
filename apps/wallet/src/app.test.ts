import { mountWallet } from "./app";
import { WalletStore } from "./state";

describe("wallet interface", () => {
  let root: HTMLDivElement;

  beforeEach(() => {
    root = document.createElement("div");
    document.body.append(root);
  });

  afterEach(() => {
    document.body.innerHTML = "";
  });

  it("marks browser mode as a safe non-secret preview", () => {
    const destroy = mountWallet(root, new WalletStore());

    expect(
      root.querySelector('[aria-label="Preview safety notice"]')?.textContent,
    ).toContain("Safe interactive preview");
    expect(root.textContent).toContain(
      "No keys are created, uploaded, or saved",
    );
    destroy();
  });

  it("navigates to the consent surface and enables approval only after review", () => {
    const destroy = mountWallet(root, new WalletStore());
    const nav = root.querySelector<HTMLButtonElement>(
      '[data-value="presentation"]',
    );
    nav?.click();

    const approve = root.querySelector<HTMLButtonElement>(
      "#approve-presentation",
    );
    const review = root.querySelector<HTMLInputElement>("#consent-review");
    expect(root.textContent).toContain("Share two facts?");
    expect(root.textContent).toContain(
      "Services inside this community may correlate this presentation",
    );
    expect(approve?.disabled).toBe(true);

    if (review) {
      review.checked = true;
      review.dispatchEvent(new Event("change", { bubbles: true }));
    }
    expect(approve?.disabled).toBe(false);
    destroy();
  });

  it("never writes preview state or passphrases to localStorage", () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const store = new WalletStore();
    const destroy = mountWallet(root, store);

    store.navigate("recovery");
    const passphrase = root.querySelector<HTMLInputElement>(
      "#recovery-passphrase",
    );
    const confirmation = root.querySelector<HTMLInputElement>(
      "#recovery-confirmation",
    );
    const form = root.querySelector<HTMLFormElement>("#recovery-export-form");
    if (passphrase && confirmation && form) {
      passphrase.value = "temporary-preview-only";
      confirmation.value = "temporary-preview-only";
      form.dispatchEvent(
        new SubmitEvent("submit", { bubbles: true, cancelable: true }),
      );
    }

    expect(storageSpy).not.toHaveBeenCalled();
    expect(passphrase?.value).toBe("");
    expect(confirmation?.value).toBe("");
    destroy();
  });

  it("keeps keyboard focus inside revocation confirmation and restores it", async () => {
    const destroy = mountWallet(root, new WalletStore());
    root.querySelector<HTMLButtonElement>('[data-value="devices"]')?.click();
    const revoke = root.querySelector<HTMLButtonElement>(
      '[data-action="open-revoke"][data-value="device-phone"]',
    );
    revoke?.click();
    await Promise.resolve();

    const destructiveAction = root.querySelector<HTMLButtonElement>(
      '[data-action="confirm-revoke"]',
    );
    destructiveAction?.focus();
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Tab" }));
    expect(document.activeElement?.getAttribute("aria-label")).toBe(
      "Close dialog",
    );

    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    await Promise.resolve();
    expect(root.querySelector('[role="dialog"]')).toBeNull();
    expect(document.activeElement?.getAttribute("data-value")).toBe(
      "device-phone",
    );
    destroy();
  });
});
