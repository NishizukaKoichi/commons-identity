import "./styles.css";

import { mountWallet } from "./app";
import { getRuntimeInfo } from "./runtime";
import { WalletStore } from "./state";

const root = document.querySelector<HTMLElement>("#app");

if (!root) {
  throw new Error("Wallet root element was not found");
}

const store = new WalletStore();
mountWallet(root, store);

void getRuntimeInfo().then((runtime) => {
  store.setRuntime(runtime);
});
