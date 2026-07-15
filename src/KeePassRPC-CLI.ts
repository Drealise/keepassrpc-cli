#!/usr/bin/env node

import WebSocket from "ws";
import * as crypto from "crypto";
import * as readline from "readline";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

// ─── Protocol Types ─────────────────────────────────────────────────────────────
interface SetupPayload {
  stage: string;
  I?: string;
  A?: string;
  M?: string;
  securityLevel?: number;
}

interface KeySetupPayload {
  username?: string;
  securityLevel?: number;
  cc?: string;
  cr?: string;
}

interface OutgoingSetupMessage {
  protocol: "setup";
  srp: SetupPayload | null;
  key: KeySetupPayload | null;
  version: number;
  features?: string[];
  clientTypeId?: string;
  clientDisplayName?: string;
  clientDisplayDescription?: string;
}

interface IncomingSetupMessage {
  protocol: "setup";
  srp?: { stage: string; s?: string; B?: string; M2?: string; securityLevel?: number };
  key?: { sc?: string; sr?: string; username?: string; securityLevel?: number; cc?: string; cr?: string };
  error?: { code: string | number; messageParams?: string[] };
}

interface EncryptedPayload {
  message: string;
  iv: string;
  hmac: string;
}

interface JSONRPCMessage {
  protocol: "jsonrpc";
  jsonrpc: string | EncryptedPayload;
  encryptionNotRequired?: boolean;
  error?: { code: string | number; message?: string; messageParams?: string[] };
  version?: number;
}

interface JSONRPCResponse {
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
  id?: number;
}

interface LoginEntry {
  title?: string;
  uN?: string;
  usernameValue?: string;
  uRLs?: string[];
  matchAccuracy?: number | string;
  formFieldList?: Array<{
    type: string;
    name?: string;
    displayName?: string;
    value?: string;
  }>;
}

// ─── SRP Constants ──────────────────────────────────────────────────────────────
const N = BigInt(
  "0xd4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43"
);
const g = 2n;
const k = BigInt("0xb7867f1299da8cc24ab93e08986ebc4d6a478ad0");

// ─── Crypto Helpers ─────────────────────────────────────────────────────────────
function sha256Hex(data: string): string {
  return crypto.createHash("sha256").update(data, "utf8").digest("hex");
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  base = ((base % modulus) + modulus) % modulus;
  while (exponent > 0n) {
    if (exponent & 1n) {
      result = (result * base) % modulus;
    }
    exponent >>= 1n;
    if (exponent > 0n) {
      base = (base * base) % modulus;
    }
  }
  return result;
}

function randomBigInt(byteCount: number): bigint {
  const bytes = crypto.randomBytes(byteCount);
  return BigInt("0x" + bytes.toString("hex"));
}

function hexStringToByteArray(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function versionAsInt([major, minor, patch]: number[]): number {
  return (major << 16) | (minor << 8) | patch;
}

function newGUID(): string {
  const bytes = crypto.randomBytes(16);
  const hex = bytes.toString("hex");
  return (
    hex.slice(0, 8) +
    "-" +
    hex.slice(8, 12) +
    "-" +
    "4" + hex.slice(13, 16) +
    "-" +
    ((parseInt(hex.slice(16, 18), 16) & 0x3f) | 0x80).toString(16) + hex.slice(18, 20) +
    "-" +
    hex.slice(20, 32)
  );
}

// ─── SRP Client ─────────────────────────────────────────────────────────────────
class SRPc {
  public Astr: string;
  private A: bigint;
  private a: bigint;
  private S: bigint = 0n;
  private K: string = "";
  public M: string = "";
  private M2: string = "";
  public p: string = "";
  public I: string = "";
  public authenticated = false;

  constructor() {
    this.a = randomBigInt(32);
    this.A = modPow(g, this.a, N);
    while (this.A % N === 0n) {
      this.a = randomBigInt(32);
      this.A = modPow(g, this.a, N);
    }
    this.Astr = this.A.toString(16).toUpperCase();
  }

  setup(username: string) {
    this.I = username;
  }

  async receiveSalts(s: string, Bstr: string): Promise<void> {
    if (!this.p) throw new Error("password not set");
    const B = BigInt("0x" + Bstr);

    const [uHash, xHash] = await Promise.all([
      sha256Hex(this.Astr + Bstr).toUpperCase(),
      sha256Hex(s + this.p).toUpperCase(),
    ]);

    const u = BigInt("0x" + uHash);
    const x = BigInt("0x" + xHash);

    const kgx = k * modPow(g, x, N);
    const aux = this.a + u * x;
    this.S = modPow(B - kgx, aux, N);

    const Mstr =
      this.A.toString(16).toUpperCase() +
      B.toString(16).toUpperCase() +
      this.S.toString(16).toUpperCase();
    this.M = await sha256Hex(Mstr);

    this.M2 = await sha256Hex(
      this.A.toString(16).toUpperCase() + this.M + this.S.toString(16).toUpperCase()
    );
  }

  confirmAuthentication(M2server: string): boolean {
    if (M2server.toLowerCase() === this.M2.toLowerCase()) {
      this.authenticated = true;
      return true;
    }
    return false;
  }

  async key(): Promise<string> {
    if (this.authenticated) {
      this.K = sha256Hex(this.S.toString(16).toUpperCase());
      return this.K;
    }
    return "";
  }
}

// ─── Encryption / Decryption ────────────────────────────────────────────────────
function encryptAesCbc(
  secretKeyHex: string,
  plaintext: string
): { message: string; iv: string; hmac: string } {
  const secretKeyBytes = hexStringToByteArray(secretKeyHex);
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv("aes-256-cbc", secretKeyBytes, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);

  const keyHash = crypto.createHash("sha1").update(secretKeyBytes).digest();
  const hmacData = Buffer.concat([keyHash, encrypted, iv]);
  const hmac = crypto.createHash("sha1").update(hmacData).digest("base64");

  return {
    message: encrypted.toString("base64"),
    iv: iv.toString("base64"),
    hmac,
  };
}

function decryptAesCbc(
  secretKeyHex: string,
  enc: { message: string; iv: string; hmac: string }
): string {
  const secretKeyBytes = hexStringToByteArray(secretKeyHex);
  const messageBytes = new Uint8Array(Buffer.from(enc.message, "base64"));
  const ivBytes = new Uint8Array(Buffer.from(enc.iv, "base64"));

  const keyHash = crypto.createHash("sha1").update(secretKeyBytes).digest();
  const hmacData = Buffer.concat([keyHash, Buffer.from(messageBytes), Buffer.from(ivBytes)]);
  const expectedHmac = crypto.createHash("sha1").update(hmacData).digest("base64");

  if (expectedHmac !== enc.hmac) {
    throw new Error("HMAC verification failed");
  }

  const decipher = crypto.createDecipheriv("aes-256-cbc", secretKeyBytes, ivBytes);
  const decrypted = Buffer.concat([decipher.update(messageBytes), decipher.final()]);
  return decrypted.toString("utf8");
}

// ─── Auth Key Persistence ───────────────────────────────────────────────────────
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const AUTH_FILE = path.join(__dirname, "keepassrpc-cli.auth");

interface StoredAuth {
  username: string;
  secretKey: string;
}

function loadStoredAuth(): StoredAuth | null {
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

function saveStoredAuth(auth: StoredAuth): void {
  fs.writeFileSync(AUTH_FILE, JSON.stringify(auth, null, 2), "utf8");
  console.log(`Auth key saved to ${AUTH_FILE}`);
}

// ─── CLI ────────────────────────────────────────────────────────────────────────
const CLIENT_VERSION = [2, 0, 0];
const CLIENT_TYPE_ID = "keefox";
const CLIENT_DISPLAY_NAME = "Kee CLI";
const CLIENT_DISPLAY_DESCRIPTION = "Command-line KeePassRPC client";
const SECURITY_LEVEL = 2;

const FEATURE_FLAGS_OFFERED = [
  "KPRPC_FEATURE_VERSION_1_6",
  "KPRPC_FEATURE_WARN_USER_WHEN_FEATURE_MISSING",
  "KPRPC_FEATURE_BROWSER_HOSTED",
  "BROWSER_SETTINGS_SYNC",
];

function prompt(question: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

function buildSetupMessage(srp?: SetupPayload, key?: KeySetupPayload): OutgoingSetupMessage {
  const msg: OutgoingSetupMessage = {
    protocol: "setup",
    srp: srp || null,
    key: key || null,
    version: versionAsInt(CLIENT_VERSION),
    features: FEATURE_FLAGS_OFFERED,
    clientTypeId: CLIENT_TYPE_ID,
    clientDisplayName: CLIENT_DISPLAY_NAME,
    clientDisplayDescription: CLIENT_DISPLAY_DESCRIPTION,
  };
  return msg;
}

async function main() {
  const url = process.argv[2] || null;
  const port = parseInt(process.argv[3] || "12546", 10);

  while (true) {
    const storedAuth = loadStoredAuth();
    if (storedAuth) {
      console.log("Found stored auth key. Attempting key-based authentication...");
    } else {
      console.log("No valid auth key stored. Will use SRP password authentication.");
    }

    console.log(`Connecting to KeePassRPC on ws://127.0.0.1:${port}...\n`);

    const ws = new WebSocket(`ws://127.0.0.1:${port}`, [], {
      perMessageDeflate: false,
      headers: { Origin: "chrome-extension://keepassrpc-cli" },
    });

    let secretKey: string | null = null;
    let nextRequestId = 1;
    let srpClient: SRPc | null = null;
    let shouldReconnect = false;
    let keyChallengeParams: { sc: string; cc: string } | null = null;

    function sendMessage(data: object) {
      ws.send(JSON.stringify(data));
    }

    function sendEncryptedRPC(method: string, params: unknown[]): void {
      if (!secretKey) throw new Error("Not authenticated");

      const rpcPayload = JSON.stringify({
        jsonrpc: "2.0",
        method,
        params,
        id: nextRequestId++,
      });

      const enc = encryptAesCbc(secretKey, rpcPayload);

      sendMessage({
        protocol: "jsonrpc",
        srp: null,
        key: null,
        error: null,
        jsonrpc: enc,
        version: versionAsInt(CLIENT_VERSION),
      });
    }

    function handleMessage(raw: string) {
      try {
        const data: Record<string, unknown> = JSON.parse(raw);
        switch (data.protocol) {
          case "setup":
            handleSetup(data as unknown as IncomingSetupMessage).catch((err) => {
              console.error("Error during setup:", err);
              ws.close();
            });
            break;
          case "jsonrpc":
            handleJSONRPC(data as unknown as JSONRPCMessage);
            break;
          case "error":
            console.error("Server error:", (data.error as Record<string, unknown>)?.code, (data.error as Record<string, unknown>)?.messageParams);
            ws.close();
            break;
        }
      } catch (err: unknown) {
        console.error("Failed to process message:", (err as Error).message);
        ws.close();
      }
    }

    async function handleSetup(data: IncomingSetupMessage) {
      if (data.error) {
        const errorCode = String(data.error.code).toUpperCase();
        const isAuthError = errorCode === "AUTH_FAILED" || errorCode === "AUTH_EXPIRED";
        if (storedAuth && isAuthError) {
          console.error("Stored key is invalid or expired. Falling back to SRP authentication...");
          shouldReconnect = true;
          try { fs.unlinkSync(AUTH_FILE); } catch { /* ignore */ }
          ws.close();
          return;
        }
        console.error("Setup error:", data.error.code, data.error.messageParams);
        ws.close();
        return;
      }

      if (data.key) {
        const activeKey = storedAuth?.secretKey || secretKey;
        if (!activeKey) {
          console.error("Server sent key challenge but no key is available.");
          ws.close();
          return;
        }

        if (data.key.sc) {
          console.log("Received server challenge. Responding...");
          const cc = randomBigInt(32).toString(16).toLowerCase();
          const cr = sha256Hex(
            "1" + activeKey + data.key.sc + cc
          ).toLowerCase();

          keyChallengeParams = { sc: data.key.sc, cc };

          sendMessage({
            protocol: "setup",
            key: {
              cc,
              cr,
              securityLevel: SECURITY_LEVEL,
            },
            version: versionAsInt(CLIENT_VERSION),
          });
          return;
        }

        if (data.key.sr && keyChallengeParams) {
          const expectedSr = sha256Hex(
            "0" + activeKey + keyChallengeParams.sc + keyChallengeParams.cc
          ).toLowerCase();

          if (expectedSr !== data.key.sr.toLowerCase()) {
            console.error("Key authentication FAILED: server proof mismatch.");
            console.error("Stored key may be revoked. Remove the auth file and re-authenticate.");
            ws.close();
            return;
          }

          secretKey = activeKey;
          console.log("Key authentication successful!\n");
          if (url) {
            console.log(`Querying logins for: ${url}\n`);
            sendEncryptedRPC("FindLogins", [
              [url],
              null,
              null,
              "LSTnoForms",
              false,
              null,
              null,
              null,
              null,
            ]);
          } else {
            console.log("No URL specified. Returning all stored logins.\n");
            sendEncryptedRPC("GetAllEntries", []);
          }
          return;
        }
      }

      if (data.srp) {
        if (data.srp.stage === "identifyToClient") {
          if (!srpClient) {
            console.error("Received SRP challenge but client not initialized.");
            ws.close();
            return;
          }
          console.log("KeePass is requesting authentication.");
          console.log(
            "Please enter the KeePassRPC connection password\n"
          );

          const password = await prompt("Password: ");

          srpClient.p = password;

          await srpClient.receiveSalts(data.srp.s ?? "", data.srp.B ?? "");

          sendMessage(
            buildSetupMessage({
              stage: "proofToServer",
              M: srpClient.M,
              securityLevel: SECURITY_LEVEL,
            })
          );
          return;
        }

        if (data.srp.stage === "proofToClient") {
          if (!srpClient) {
            console.error("Received proof but SRP client not initialized.");
            ws.close();
            return;
          }

          if (srpClient.confirmAuthentication(data.srp.M2 ?? "")) {
            console.log("SRP authentication successful!");
            secretKey = await srpClient.key();

            saveStoredAuth({
              username: srpClient.I,
              secretKey,
            });

            shouldReconnect = true;
            console.log("Key saved. Reconnecting with stored key...");
            ws.close();
          } else {
            console.error("Authentication FAILED: server proof mismatch.");
            ws.close();
          }
          return;
        }

        return;
      }
    }

    function handleJSONRPC(data: JSONRPCMessage) {
      if (data.encryptionNotRequired) {
        const obj: JSONRPCResponse = typeof data.jsonrpc === "string" ? JSON.parse(data.jsonrpc) : data.jsonrpc;
        printResult(obj);
      } else if (secretKey) {
        try {
          const decrypted = decryptAesCbc(secretKey, data.jsonrpc as EncryptedPayload);
          const obj: JSONRPCResponse = JSON.parse(decrypted);
          printResult(obj);
        } catch (e: unknown) {
          console.error("Decryption failed:", (e as Error).message);
        }
      }
    }

    function printResult(obj: JSONRPCResponse) {
      if (obj.error) {
        console.error("RPC Error:", JSON.stringify(obj.error, null, 2));
      } else if (obj.result !== undefined) {
        const results = obj.result;
        if (Array.isArray(results) && results.length === 0) {
          console.log("No matching logins found.");
        } else if (Array.isArray(results)) {
          console.log(`Found ${results.length} login(s):\n`);
          for (const entry of results) {
            const login = entry as LoginEntry;
            const title = login.title || "(untitled)";
            const username = login.uN || login.usernameValue || "(no username)";
            const urls = (login.uRLs || []).join(", ") || "(no URLs)";
            const matchAccuracy = login.matchAccuracy || "?";
            const fields = login.formFieldList || [];

            console.log(`  Title:            ${title}`);
            console.log(`  Username:         ${username}`);
            console.log(`  URLs:             ${urls}`);
            console.log(`  Match Accuracy:   ${matchAccuracy}`);
            if (fields.length > 0) {
              console.log(`  Fields:`);
              for (const f of fields) {
                const val = f.type === "FFTpassword" ? "********" : f.value;
                console.log(`    - ${f.displayName || f.name}: ${val}`);
              }
            }
            console.log();
          }
        } else {
          console.log("Result:", JSON.stringify(obj.result, null, 2));
        }
      }
      ws.close();
    }

    ws.on("open", () => {
      if (storedAuth) {
        console.log("Sending key-based auth request...");
        sendMessage(
          buildSetupMessage(undefined, {
            username: storedAuth.username,
            securityLevel: SECURITY_LEVEL,
          })
        );
      } else {
        const username = newGUID();
        srpClient = new SRPc();
        srpClient.setup(username);
        console.log("Initiating SRP authentication...");
        sendMessage(
          buildSetupMessage({
            stage: "identifyToServer",
            I: srpClient.I,
            A: srpClient.Astr,
            securityLevel: SECURITY_LEVEL,
          })
        );
      }
    });

    ws.on("message", (data) => {
      handleMessage(data.toString());
    });

    ws.on("error", (err) => {
      console.error("WebSocket error:", err.message);
      process.exit(1);
    });

    await new Promise<void>((resolve) => {
      ws.on("close", () => resolve());
    });

    if (shouldReconnect) {
      console.log("");
      continue;
    }
    break;
  }
}

main();
