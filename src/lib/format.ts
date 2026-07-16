import type { LoginEntry } from "./types.js";

export type OutputFormat = "list" | "table" | "json" | "raw";

function formField(entry: LoginEntry, type: string): string | undefined {
  return entry.formFieldList?.find((f) => f.type === type)?.value;
}

function otherFields(entry: LoginEntry): Array<{ label: string; value: string }> {
  return (entry.formFieldList || [])
    .filter((f) => f.type !== "FFTusername" && f.type !== "FFTpassword")
    .map((f) => ({ label: f.displayName || f.name || f.type, value: f.value || "" }));
}

function formatExpiry(iso: string): string {
  return iso.replace("T", " ").replace(/\.\d{7}.*$/, "");
}

function expiryLabel(entry: LoginEntry): string {
  if (!entry.expires) return "";
  if (!entry.expiryTime) return "expires";
  return formatExpiry(entry.expiryTime);
}

function expiryShort(entry: LoginEntry): string {
  if (!entry.expires) return "";
  if (!entry.expiryTime) return "yes";
  return formatExpiry(entry.expiryTime);
}

export function formatList(results: LoginEntry[]): string {
  const lines: string[] = [`Found ${results.length} login(s):\n`];
  for (const login of results) {
    const title = login.title || "(untitled)";
    const username = login.uN || login.usernameValue || formField(login, "FFTusername") || "(no username)";
    const password = formField(login, "FFTpassword");
    const urls = (login.uRLs || []).join(", ") || "(no URLs)";
    const matchAccuracy = login.matchAccuracy || "?";
    const fields = otherFields(login);

    lines.push(`  Title:            ${title}`);
    lines.push(`  Username:         ${username}`);
    lines.push(`  Password:         ${password ? "********" : "(none)"}`);
    lines.push(`  URLs:             ${urls}`);
    lines.push(`  Match Accuracy:   ${matchAccuracy}`);
    if (login.expires) {
      lines.push(`  Expires:          ${expiryLabel(login)}`);
    }
    if (fields.length > 0) {
      lines.push(`  Fields:`);
      for (const f of fields) {
        lines.push(`    - ${f.label}: ${f.value}`);
      }
    }
    lines.push("");
  }
  return lines.join("\n");
}

export function formatTable(results: LoginEntry[]): string {
  if (results.length === 0) return "No matching logins found.";

  const rows = results.map((login) => ({
    title: login.title || "(untitled)",
    username: login.uN || login.usernameValue || formField(login, "FFTusername") || "(no username)",
    password: formField(login, "FFTpassword") ? "********" : "(none)",
    urls: (login.uRLs || []).join(", ") || "(no URLs)",
    match: String(login.matchAccuracy || "?"),
    expires: expiryShort(login),
  }));

  const cols = {
    title: Math.max(5, ...rows.map((r) => r.title.length)),
    username: Math.max(8, ...rows.map((r) => r.username.length)),
    password: Math.max(8, ...rows.map((r) => r.password.length)),
    urls: Math.max(4, ...rows.map((r) => r.urls.length)),
    match: Math.max(5, ...rows.map((r) => r.match.length)),
    expires: Math.max(7, ...rows.map((r) => r.expires.length)),
  };

  const sep = (n: number) => "─".repeat(n);
  const header =
    `${"Title".padEnd(cols.title)}  ` +
    `${"Username".padEnd(cols.username)}  ` +
    `${"Password".padEnd(cols.password)}  ` +
    `${"URLs".padEnd(cols.urls)}  ` +
    `${"Match".padEnd(cols.match)}  ` +
    `${"Expires".padEnd(cols.expires)}`;
  const divider =
    `${sep(cols.title)}  ` +
    `${sep(cols.username)}  ` +
    `${sep(cols.password)}  ` +
    `${sep(cols.urls)}  ` +
    `${sep(cols.match)}  ` +
    `${sep(cols.expires)}`;

  const lines: string[] = [
    `Found ${results.length} login(s):\n`,
    header,
    divider,
  ];

  for (const r of rows) {
    lines.push(
      `${r.title.padEnd(cols.title)}  ` +
      `${r.username.padEnd(cols.username)}  ` +
      `${r.password.padEnd(cols.password)}  ` +
      `${r.urls.padEnd(cols.urls)}  ` +
      `${r.match.padEnd(cols.match)}  ` +
      `${r.expires.padEnd(cols.expires)}`
    );
  }

  return lines.join("\n");
}

export function formatJSON(results: LoginEntry[]): string {
  return JSON.stringify(results, null, 2);
}

export function formatRaw(obj: unknown): string {
  return JSON.stringify(obj);
}
