import { escapeHtml, validateRecoveryPassphrase } from "./validation";

describe("recovery validation", () => {
  it("requires a sufficiently long matching passphrase", () => {
    expect(validateRecoveryPassphrase("short", "short").valid).toBe(false);
    expect(
      validateRecoveryPassphrase("long-enough-passphrase", "different-value")
        .valid,
    ).toBe(false);
    expect(
      validateRecoveryPassphrase(
        "long-enough-passphrase",
        "long-enough-passphrase",
      ).valid,
    ).toBe(true);
  });

  it("escapes user-controlled display text", () => {
    expect(escapeHtml('<img src=x onerror="bad">')).toBe(
      "&lt;img src=x onerror=&quot;bad&quot;&gt;",
    );
  });
});
