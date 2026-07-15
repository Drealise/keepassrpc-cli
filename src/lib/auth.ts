import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import type { StoredAuth } from "./types.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const AUTH_FILE = path.join(__dirname, "keepassrpc-cli.auth");

export function loadStoredAuth(): StoredAuth | null {
  try {
    if (fs.existsSync(AUTH_FILE)) {
      const data = JSON.parse(fs.readFileSync(AUTH_FILE, "utf8"));
      if (data.username && data.secretKey) return data;
    }
  } catch {
    // corrupted file, ignore
  }
  return null;
}

export function saveStoredAuth(auth: StoredAuth): void {
  fs.writeFileSync(AUTH_FILE, JSON.stringify(auth, null, 2), "utf8");
  console.log(`Auth key saved to ${AUTH_FILE}`);
}

export function deleteStoredAuth(): void {
  try { fs.unlinkSync(AUTH_FILE); } catch { /* ignore */ }
}
