# @sitecmd/cli

The [SiteCMD](https://sitecmd.com) scanner CLI: Web Scan against a live URL, the complete local Code Scan against a source checkout, and CI quality gates, all from one self-contained binary with no account required for local commands.

```bash
npx @sitecmd/cli scan --url https://example.com
```

Or pin it as a dev dependency so CI and git hooks get the exact version your lockfile names:

```bash
npm install --save-dev @sitecmd/cli
npx sitecmd audit .
```

The binary itself ships in a platform-specific optional dependency (`@sitecmd/cli-darwin-universal`, `@sitecmd/cli-linux-x64`, `@sitecmd/cli-linux-arm64`, or `@sitecmd/cli-win32-x64`); npm installs only the one matching your machine, and there are no install scripts. The macOS and Windows binaries are code-signed, and every release is also published with signed checksums at [releases.sitecmd.com](https://releases.sitecmd.com/) for the standalone installer.

Full reference: [sitecmd.com/docs/cli](https://sitecmd.com/docs/cli)
