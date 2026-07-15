import * as crypto from "crypto";

// ─── SRP Constants ──────────────────────────────────────────────────────────────
const N = BigInt(
  "0xd4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43"
);
const g = 2n;
const k = BigInt("0xb7867f1299da8cc24ab93e08986ebc4d6a478ad0");

// ─── Crypto Helpers ─────────────────────────────────────────────────────────────
export function sha256Hex(data: string): string {
  return crypto.createHash("sha256").update(data, "utf8").digest("hex");
}

export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
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

export function randomBigInt(byteCount: number): bigint {
  const bytes = crypto.randomBytes(byteCount);
  return BigInt("0x" + bytes.toString("hex"));
}

export function hexStringToByteArray(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

export function versionAsInt([major, minor, patch]: number[]): number {
  return (major << 16) | (minor << 8) | patch;
}

export function newGUID(): string {
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
export class SRPc {
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
