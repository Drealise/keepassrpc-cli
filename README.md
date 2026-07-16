# KeePassRPC-CLI

Command-line client for [KeePassRPC](https://github.com/kee-org/keepassrpc). Queries logins from KeePass databases over a local WebSocket connection.

## Prerequisites

KeePassRPC plugin must be installed and running in KeePass:

1. Open KeePass
2. Go to **Tools > KeePassRPC options**
3. Ensure the WebSocket server is enabled (default port: `12546`)

On first connection, KeePass will display a pop-up with a randomly generated connection password. You will be prompted to enter this password into the CLI.

## Installation

```bash
git clone https://github.com/Drealise/keepassrpc-cli.git
cd keepassrpc-cli
npm install
```

For global usage:

```bash
npm run build
npm link
```

## Usage

### Query logins by URL

```bash
keepassrpc-cli https://github.com/login
# or
npm run start -- https://github.com/login
```

### Return all stored logins

```bash
keepassrpc-cli
# or
npm run start
```

### Specify a custom port

```bash
keepassrpc-cli https://github.com/login 12547
# or
npm run start -- https://github.com/login 12547
```

### First run

On first run, you will be prompted for the KeePassRPC connection password. The session key is saved automatically for future use.  
Then the query results are returned.

### Subsequent runs

After the first run, the stored session key is used automatically — no password prompt.  
Then the query results are returned.

### Expired or invalid session key

If the stored session key expires or becomes invalid, or the file contents become invalid or corrupted, the tool automatically falls back to SRP authentication, then reconnects using the new key.  
Then the query results are returned.

## Command Line Arguments

```bash
keepassrpc-cli [url] [port] [--format <format>] [--exclude-expired]
# or
npm run start -- [url] [port] [--format <format>] [--exclude-expired]
```

| Argument | Description | Default |
|----------|-------------|---------|
| `url` | URL to query logins for. Omit to return all stored logins. | none |
| `port` | KeePassRPC WebSocket port | `12546` |
| `--format`, `-f` | Output format: `raw`, `list`, `table`, or `json` | `raw` |
| `--exclude-expired`, `-e` | Omit entries where `expires=true` and `expiryTime` is in the past | off |

### Output Formats

- **`raw`** — Full RPC response as a single-line JSON string (default)
- **`list`** — Verbose per-entry display with labeled fields
- **`table`** — Compact columnar view with headers
- **`json`** — Pretty-printed JSON array of login entries

```bash
keepassrpc-cli https://example.com -f table
keepassrpc-cli https://example.com -f json
keepassrpc-cli https://example.com -f list
```

## Session Key File

After the first successful authentication, a session key is saved to `<scriptname>.auth` in the same directory as the script. For the built bundle this is `dist/KeePassRPC-CLI.auth`; when running from source via `esno`, it is `src/KeePassRPC-CLI.auth`.

**Note**: This file contains sensitive session data. It is listed in `.gitignore` by default.

## Test Database

A test KeePass database (with zero-length master password) is included with the following entries:

| Title | Username | URLs | Expires |
|-------|----------|------|---------|
| Github (active) | aaaaa@aaa.aa | https://github.com/login | — |
| Github (active 2) | bbbbb@bbb.bb | https://github.com/login | — |
| Github (expired) | xxxxx@xxx.xx | https://github.com/login | 2026-03-04 |
| Github (expired 2) | zzzzz@zzz.zz | https://github.com/ | 2026-07-15 |
| Other site | randomUser | https://www.othersite.com | — |

To query all entries:

```bash
keepassrpc-cli -f list
```

## Development

```bash
npm run dev        # Run in development mode
npm run typecheck  # Type check
npm run build      # Build for production
```

## License

This project is licensed under a custom FOSS license with non-commercial and share-alike terms.

You are free to:

- **Fork** and modify the code
- **Use** it for personal and commercial purposes (see restrictions below)

Under the following terms:

- **Attribution** — Credit must be given when repurposing or redistributing this work or derivative works.
- **Non-Commercial** — This software may not be used for commercial purposes without permission.
- **Share-Alike** — Derivative works must be distributed under the same license terms.

For questions about commercial use, please open an issue.

## Further Reading

[Technical Details](README-TECH.md) — protocol flow, encryption, and SRP parameters.
