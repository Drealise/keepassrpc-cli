import * as fs from "fs";
import * as path from "path";
import type { StoredAuth } from "./types.js";

export function createAuthStore(dir: string) {
  const authFile = path.join(dir, "keepassrpc-cli.auth");

  return {
    load(): StoredAuth | null {
      try {
        if (fs.existsSync(authFile)) {
          const data = JSON.parse(fs.readFileSync(authFile, "utf8"));
          if (data.username && data.secretKey) return data;
        }
      } catch {
        // corrupted file, ignore
      }
      return null;
    },

    save(auth: StoredAuth): void {
      fs.writeFileSync(authFile, JSON.stringify(auth, null, 2), "utf8");
      console.log(`Auth key saved to ${authFile}`);
    },

    delete(): void {
      try { fs.unlinkSync(authFile); } catch { /* ignore */ }
    },
  };
}
