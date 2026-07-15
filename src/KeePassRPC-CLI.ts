#!/usr/bin/env node

import WebSocket from "ws";
import * as readline from "readline";

import type {
  SetupPayload,
  KeySetupPayload,
  OutgoingSetupMessage,
  IncomingSetupMessage,
  EncryptedPayload,
  JSONRPCMessage,
  JSONRPCResponse,
  LoginEntry,
} from "./lib/types.js";
import { sha256Hex, randomBigInt, versionAsInt, newGUID, SRPc } from "./lib/crypto.js";
import { encryptAesCbc, decryptAesCbc } from "./lib/encryption.js";
import { loadStoredAuth, saveStoredAuth, deleteStoredAuth } from "./lib/auth.js";

// ─── CLI Constants ──────────────────────────────────────────────────────────────
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
          deleteStoredAuth();
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
