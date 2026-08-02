import { invoke } from "@tauri-apps/api/core";

import { browserRuntime } from "./data";
import type { RuntimeInfo } from "./types";

function isTauriRuntime(): boolean {
  return "__TAURI_INTERNALS__" in window;
}

export async function getRuntimeInfo(): Promise<RuntimeInfo> {
  if (!isTauriRuntime()) return browserRuntime;

  try {
    return await invoke<RuntimeInfo>("runtime_info");
  } catch {
    return {
      ...browserRuntime,
      mode: "desktop-prototype",
    };
  }
}
