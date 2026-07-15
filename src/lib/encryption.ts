import * as crypto from "crypto";
import { hexStringToByteArray } from "./crypto.js";
import type { EncryptedPayload } from "./types.js";

export function encryptAesCbc(
  secretKeyHex: string,
  plaintext: string
): EncryptedPayload {
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

export function decryptAesCbc(
  secretKeyHex: string,
  enc: EncryptedPayload
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
