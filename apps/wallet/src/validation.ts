export interface PassphraseValidation {
  valid: boolean;
  message: string;
}

export function validateRecoveryPassphrase(
  passphrase: string,
  confirmation: string,
): PassphraseValidation {
  if (passphrase.length < 12) {
    return {
      valid: false,
      message: "Use at least 12 characters for this preview check.",
    };
  }

  if (passphrase !== confirmation) {
    return { valid: false, message: "The passphrases do not match." };
  }

  return { valid: true, message: "" };
}

export function escapeHtml(value: string): string {
  return value.replace(
    /[&<>'"]/g,
    (character) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        "'": "&#039;",
        '"': "&quot;",
      })[character] ?? character,
  );
}
