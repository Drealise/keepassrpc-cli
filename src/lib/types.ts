export interface SetupPayload {
  stage: string;
  I?: string;
  A?: string;
  M?: string;
  securityLevel?: number;
}

export interface KeySetupPayload {
  username?: string;
  securityLevel?: number;
  cc?: string;
  cr?: string;
}

export interface OutgoingSetupMessage {
  protocol: "setup";
  srp: SetupPayload | null;
  key: KeySetupPayload | null;
  version: number;
  features?: string[];
  clientTypeId?: string;
  clientDisplayName?: string;
  clientDisplayDescription?: string;
}

export interface IncomingSetupMessage {
  protocol: "setup";
  srp?: { stage: string; s?: string; B?: string; M2?: string; securityLevel?: number };
  key?: { sc?: string; sr?: string; username?: string; securityLevel?: number; cc?: string; cr?: string };
  error?: { code: string | number; messageParams?: string[] };
}

export interface EncryptedPayload {
  message: string;
  iv: string;
  hmac: string;
}

export interface JSONRPCMessage {
  protocol: "jsonrpc";
  jsonrpc: string | EncryptedPayload;
  encryptionNotRequired?: boolean;
  error?: { code: string | number; message?: string; messageParams?: string[] };
  version?: number;
}

export interface JSONRPCResponse {
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
  id?: number;
}

export interface LoginEntry {
  title?: string;
  uN?: string;
  usernameValue?: string;
  uRLs?: string[];
  matchAccuracy?: number | string;
  expires?: boolean;
  expiryTime?: string;
  formFieldList?: Array<{
    type: string;
    name?: string;
    displayName?: string;
    value?: string;
  }>;
}

export interface StoredAuth {
  username: string;
  secretKey: string;
}
