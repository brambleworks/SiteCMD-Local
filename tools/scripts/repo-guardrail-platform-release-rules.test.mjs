import fs from "node:fs";
import { describe, expect, it } from "vitest";
import { realRead, rules } from "./guardrail-test-support.mjs";

const {
  ciCostSafetyFailures,
  confirmDeadlineFailures,
  releaseWorkflowSafetyFailures,
  ungrantedIpcCommandFailures,
  updaterTrustFailures,
} = rules;

describe("ungrantedIpcCommandFailures reads the ACL the way Tauri does", () => {
  const clean = {
    "apps/desktop/src-tauri/src/lib.rs":
      ".invoke_handler(tauri::generate_handler![\n            commands::ping,\n            commands::license::get_license_status,\n            commands::run_data_admin_command,\n        ])",
    "apps/desktop/src-tauri/capabilities/default.json": JSON.stringify({
      windows: ["main"],
      permissions: ["default"],
    }),
    "apps/desktop/src-tauri/capabilities/data-admin.json": JSON.stringify({
      windows: ["data-admin"],
      permissions: ["allow-run-data-admin-command"],
    }),
    "apps/desktop/src-tauri/permissions/default.toml":
      '[default]\npermissions = [\n    "allow-ping",\n    "allow-get-license-status"\n]\n',
    "apps/desktop/src-tauri/build.rs":
      'const APP_COMMANDS: &[&str] = &["ping", "get_license_status", "run_data_admin_command"];',
    "apps/desktop/src/lib/tauri-invoke.ts":
      'const PRIVILEGED_BROKER_COMMANDS = new Map([["clear_scan_history", "run_data_admin_command"]] as const);',
  };
  const run = (overrides = {}) => {
    const sources = { ...clean, ...overrides };
    return ungrantedIpcCommandFailures(
      (relativePath) => {
        const source = sources[relativePath];
        if (source === undefined) throw new Error(`unexpected read: ${relativePath}`);
        return source;
      },
      (dir) => Object.keys(sources).filter((file) => file.startsWith(`${dir}/`)),
    );
  };

  it("passes the clean fixture, so the mutations below mean something", () => {
    expect(run()).toEqual([]);
  });

  it("catches a deny that overrides its own allow", () => {
    expect(
      run({
        "apps/desktop/src-tauri/permissions/default.toml":
          '[default]\npermissions = [\n    "allow-ping",\n    "allow-get-license-status",\n    "deny-get-license-status"\n]\n',
      }).join("\n"),
    ).toContain("get_license_status");
  });

  it("catches a handler entry commented out with a block comment", () => {
    expect(
      run({
        "apps/desktop/src-tauri/src/lib.rs":
          ".invoke_handler(tauri::generate_handler![\n            commands::ping,\n/*\n            commands::license::get_license_status,\n*/\n            commands::run_data_admin_command,\n        ])",
      }).join("\n"),
    ).toContain("get_license_status");
  });

  it("does not treat a webviews-scoped capability as a main-window grant", () => {
    expect(
      run({
        "apps/desktop/src-tauri/permissions/default.toml":
          '[default]\npermissions = [\n    "allow-ping"\n]\n',
        "apps/desktop/src-tauri/capabilities/analyzer.json": JSON.stringify({
          webviews: ["analyzer-preview"],
          permissions: ["allow-get-license-status"],
        }),
      }).join("\n"),
    ).toContain("get_license_status");
  });

  it("does not treat a platform-restricted capability as a grant everywhere", () => {
    expect(
      run({
        "apps/desktop/src-tauri/permissions/default.toml":
          '[default]\npermissions = [\n    "allow-ping"\n]\n',
        "apps/desktop/src-tauri/capabilities/mac-only.json": JSON.stringify({
          windows: ["main"],
          platforms: ["macOS"],
          permissions: ["allow-get-license-status"],
        }),
      }).join("\n"),
    ).toContain("get_license_status");
  });

  it("does not let a tuple in a comment buy a broker exemption", () => {
    const withComment =
      clean["apps/desktop/src/lib/tauri-invoke.ts"] +
      '\n// old sketch: ["unused", "get_license_status"]';
    expect(
      run({
        "apps/desktop/src-tauri/permissions/default.toml":
          '[default]\npermissions = [\n    "allow-ping"\n]\n',
        "apps/desktop/src-tauri/capabilities/data-admin.json": JSON.stringify({
          windows: ["data-admin"],
          permissions: ["allow-run-data-admin-command", "allow-get-license-status"],
        }),
        "apps/desktop/src/lib/tauri-invoke.ts": withComment,
      }).join("\n"),
    ).toContain("get_license_status");
  });

  it("still exempts a real broker entrypoint", () => {
    expect(run()).toEqual([]);
  });
});

describe("confirmDeadlineFailures", () => {
  const sources = (nativeSecs, bridgeMs) => ({
    "apps/desktop/src-tauri/src/constants.rs": `pub const SENSITIVE_CONFIRM_TIMEOUT: Duration = Duration::from_secs(${nativeSecs});`,
    "apps/desktop/src/lib/privileged-command-bridge.ts": `const HUMAN_CONFIRMATION_TIMEOUT_MS = ${bridgeMs};`,
  });
  const run = (nativeSecs, bridgeMs) => {
    const files = sources(nativeSecs, bridgeMs);
    return confirmDeadlineFailures((file) => files[file]);
  };

  it("accepts a native deadline that expires first", () => {
    expect(run(150, 180_000)).toEqual([]);
  });

  it("catches the 300s-over-180s ordering that shipped", () => {
    expect(run(300, 180_000).join("\n")).toContain("must expire BEFORE");
  });

  it("catches deadlines that expire together, which is still a race", () => {
    expect(run(180, 180_000).join("\n")).toContain("must expire BEFORE");
  });

  it("reads the bridge constant written as a product", () => {
    const files = {
      "apps/desktop/src-tauri/src/constants.rs":
        "pub const SENSITIVE_CONFIRM_TIMEOUT: Duration = Duration::from_secs(150);",
      "apps/desktop/src/lib/privileged-command-bridge.ts":
        "const HUMAN_CONFIRMATION_TIMEOUT_MS = 3 * 60_000;",
    };
    expect(confirmDeadlineFailures((file) => files[file])).toEqual([]);
  });

  it("pins the real files, not just the fixtures", () => {
    expect(confirmDeadlineFailures(realRead)).toEqual([]);
  });
});

describe("updaterTrustFailures", () => {
  it("rejects unsupported key-transition mechanisms in the incident runbook", () => {
    const runbook = `${realRead("docs/engineering/release-signing-key-rotation.md")}\nupdater.pubkeyNext\n`;
    const failures = updaterTrustFailures(
      (file) =>
        file === "docs/engineering/release-signing-key-rotation.md" ? runbook : realRead(file),
      () => true,
    );

    expect(failures.join("\n")).toContain("unsupported updater transition");
  });
});

describe("release pipeline probe and CRLF rules", () => {
  const run = (mutate = (_file, source) => source) =>
    releaseWorkflowSafetyFailures((file) => mutate(file, realRead(file)));

  it("passes the real repository", () => {
    expect(run()).toEqual([]);
  });

  it("catches a publisher that stopped uploading the signed checksum manifest", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace("          add_upload payload/SHA256SUMS.minisig SHA256SUMS.minisig\n", "")
        : source,
    );
    expect(failures.join("\n")).toContain("release-wide SHA256SUMS");
  });

  it("catches a verifier that stopped checking the checksum manifest signature", () => {
    const failures = run((file, source) =>
      file.endsWith("verify-signed-payload.sh")
        ? source.replace(
            '"$verifier" updater-public-key.pub payload/SHA256SUMS checksum-signature.sig',
            "true",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("release-wide SHA256SUMS");
  });

  it("catches a verifier that stopped binding the CLI archive to the manifest", () => {
    const failures = run((file, source) =>
      file.endsWith("verify-signed-payload.sh")
        ? source.replace('verify_listed "$dir/$cli_archive"\n', "")
        : source,
    );
    expect(failures.join("\n")).toContain("release-wide SHA256SUMS");
  });

  it("catches a verifier that stopped binding the updater bundle to the manifest", () => {
    const failures = run((file, source) =>
      file.endsWith("verify-signed-payload.sh")
        ? source.replace('verify_listed "$dir/$filename"\n', "")
        : source,
    );
    expect(failures.join("\n")).toContain("release-wide SHA256SUMS");
  });

  it("catches a verifier that stopped binding the DMG to the manifest", () => {
    const failures = run((file, source) =>
      file.endsWith("verify-signed-payload.sh")
        ? source.replace('if [ -n "$dmg_name" ]; then verify_listed "$dir/$dmg_name"; fi\n', "")
        : source,
    );
    expect(failures.join("\n")).toContain("release-wide SHA256SUMS");
  });

  it("catches a verify_listed whose body no longer reads the manifest", () => {
    const failures = run((file, source) =>
      file.endsWith("verify-signed-payload.sh")
        ? source.replace(/verify_listed\(\) \{[\s\S]*?\n\}/, "verify_listed() {\n  :\n}")
        : source,
    );
    expect(failures.join("\n")).toContain("release-wide SHA256SUMS");
  });

  const advanceStepBlock = (source) => {
    const start = source.indexOf("      - name: Advance the production updater manifest");
    const end = source.indexOf("\n      - ", start);
    return source.slice(start, end + 1);
  };

  it("is not fooled by a decoy comment when the manifest advance moves after the release", () => {
    const decoy = "      # Advance the production updater manifest ran in the step above\n";
    const attestHeader = "      - name: Attest build provenance for the published artifacts\n";
    const failures = run((file, source) => {
      if (!file.includes("release.yml")) return source;
      const step = advanceStepBlock(source);
      return source.replace(step, decoy).replace(attestHeader, `${step}${attestHeader}`);
    });
    expect(failures.join("\n")).toContain("release-wide SHA256SUMS");
  });

  it("is not fooled by a decoy comment that literally names the releases-admin URL", () => {
    // Unlike the paraphrase above, this decoy quotes the exact needle
    // orderedBefore searches for, planted ahead of the real (now displaced)
    // step; a raw indexOf would find the comment and wrongly call this ordered.
    const decoy = "      # https://releases.sitecmd.com/api/releases-admin ran above already\n";
    const attestHeader = "      - name: Attest build provenance for the published artifacts\n";
    const failures = run((file, source) => {
      if (!file.includes("release.yml")) return source;
      const step = advanceStepBlock(source);
      return source.replace(step, decoy).replace(attestHeader, `${step}${attestHeader}`);
    });
    expect(failures.join("\n")).toContain("release-wide SHA256SUMS");
  });

  it("catches a publisher that drops the upload-plan cross-check", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace("          while read -r hash name; do\n", "")
        : source,
    );
    expect(failures.join("\n")).toContain("release-wide SHA256SUMS");
  });

  it("catches an upload-plan cross-check whose lookup is a no-op", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace(
            'grep -Fq "$(printf \'\\tv%s/%s\\t%s\' "$VERSION" "$name" "$hash")" publication/upload-plan.tsv',
            "true",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("release-wide SHA256SUMS");
  });

  it("catches a publisher that leaves an existing Release unrepaired", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace(
            '              gh release upload "$TAG_NAME" "payload/$asset" \\\n                --repo "$GITHUB_REPOSITORY" --clobber\n',
            "",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("must repair an existing Release");
  });

  it("catches a publisher that stopped failing on a draft Release", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace(
            `if [ "$(jq -r '.isDraft' release-state.json)" = "true" ]; then`,
            "if false; then",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("must repair an existing Release");
  });

  it("catches a smoke test whose terminal failure exit is dropped", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace('          done\n          exit "$fail"\n', "          done\n")
        : source,
    );
    expect(failures.join("\n")).toContain("public smoke test");
  });

  it("catches a smoke-test curl that stops announcing the monitor User-Agent", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace("-w '%{http_code}' -A \"$SMOKE_UA\" ", "-w '%{http_code}' ")
        : source,
    );
    expect(failures.join("\n")).toContain('-A "$SMOKE_UA" on every curl request');
  });

  it("catches a smoke test whose User-Agent literal drifts", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace('SMOKE_UA="SiteCMD-Release-Smoke/1"', 'SMOKE_UA="curl/8"')
        : source,
    );
    expect(failures.join("\n")).toContain("SiteCMD-Release-Smoke/1");
  });

  it("catches a README that dropped the manifest-signature check the notes promise", () => {
    const failures = run((file, source) =>
      file === "README.md"
        ? source.replace("minisign -Vm SHA256SUMS -x SHA256SUMS.minisig -P ", "minisign -V # ")
        : source,
    );
    expect(failures.join("\n")).toContain("README.md#verify-your-download");
  });

  it("catches a README that dropped the downloaded-file checksum check", () => {
    const failures = run((file, source) =>
      file === "README.md"
        ? source.replace("shasum -a 256 -c --ignore-missing SHA256SUMS", "shasum -a 256 SHA256SUMS")
        : source,
    );
    expect(failures.join("\n")).toContain("README.md#verify-your-download");
  });

  it("catches provenance attestation moved out of the publisher", () => {
    const failures = run((file, source) =>
      file.includes("release.yml") ? source.replace("      attestations: write\n", "") : source,
    );
    expect(failures.join("\n")).toContain("attest-build-provenance");
  });

  it("catches a deleted attestation subject", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace("            payload/SHA256SUMS\n", "")
        : source,
    );
    expect(failures.join("\n")).toContain("attest-build-provenance");
  });

  it("catches an attestation subject swapped for the unverified candidate manifest", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace(
            "            payload/*/*.dmg\n",
            "            release-candidate/manifest.json\n",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("attest-build-provenance");
  });

  it("is not fooled by a decoy comment when the attest step moves ahead of the release", () => {
    const attestStep = [
      "      - name: Attest build provenance for the published artifacts",
      "        uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2",
      "        with:",
      "          subject-path: |",
      "            payload/*/*.tar.gz",
      "            payload/*/*.AppImage",
      "            payload/*/*-setup.exe",
      "            payload/*/*.zip",
      "            payload/*/*.dmg",
      "            payload/SHA256SUMS",
    ].join("\n");
    const publishHeader = "      - name: Publish the GitHub Release with notes and checksums";
    const decoy = "      # gh release create already ran; nothing left to publish\n";
    const failures = run((file, source) => {
      if (!file.includes("release.yml")) return source;
      const withoutAttest = source.replace(`\n\n${attestStep}\n`, "\n");
      return withoutAttest.replace(
        `${publishHeader}\n`,
        `${decoy}\n${attestStep}\n\n${publishHeader}\n`,
      );
    });
    expect(failures.join("\n")).toContain("attest-build-provenance");
  });

  it('is not fooled by a decoy comment that literally names "gh release create"', () => {
    // Unlike the paraphrase above, this decoy quotes the exact needle
    // orderedBefore searches for, planted ahead of the attest step moved up
    // in front of it; a raw indexOf would find the comment and wrongly call
    // this ordered.
    const attestStep = [
      "      - name: Attest build provenance for the published artifacts",
      "        uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2",
      "        with:",
      "          subject-path: |",
      "            payload/*/*.tar.gz",
      "            payload/*/*.AppImage",
      "            payload/*/*-setup.exe",
      "            payload/*/*.zip",
      "            payload/*/*.dmg",
      "            payload/SHA256SUMS",
    ].join("\n");
    const publishHeader = "      - name: Publish the GitHub Release with notes and checksums";
    const decoy = '      # gh release create "$TAG_NAME" already ran above\n';
    const failures = run((file, source) => {
      if (!file.includes("release.yml")) return source;
      const withoutAttest = source.replace(`\n\n${attestStep}\n`, "\n");
      return withoutAttest.replace(
        `${publishHeader}\n`,
        `${decoy}\n${attestStep}\n\n${publishHeader}\n`,
      );
    });
    expect(failures.join("\n")).toContain("attest-build-provenance");
  });

  it("catches a removed updater-key probe job", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace("\n  validate-updater-key:\n", "\n  validate-updater-key-detached:\n")
        : source,
    );
    expect(failures.join("\n")).toContain("validate-updater-key");
  });

  it("catches a removed publish-credential probe job", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace("\n  validate-publish-key:\n", "\n  validate-publish-key-detached:\n")
        : source,
    );
    expect(failures.join("\n")).toContain("validate-publish-key");
  });

  it("catches release helpers omitted from an isolated sparse checkout", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace("            .github/scripts/release\n", "")
        : source,
    );
    expect(failures.join("\n")).toContain(
      "must include .github/scripts/release in its sparse checkout",
    );
  });

  it("is not satisfied by a probe that stopped checking the response code", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace('if [ "$status" != "400" ]; then', 'if [ "$status" = "999" ]; then')
        : source,
    );
    expect(failures.join("\n")).toContain("validate-publish-key");
  });

  it("catches a probe that can no longer mint its OIDC token", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace(
            "      # audience, minted in release-publish on a v* tag of this repository.\n      id-token: write\n",
            "      # audience, minted in release-publish on a v* tag of this repository.\n",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("validate-publish-key");
  });

  it("catches a probe that authenticates with anything but the OIDC token", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace(
            "-w '%{http_code}' -X POST \\\n            -H \"Authorization: Bearer ${token}\"",
            "-w '%{http_code}' -X POST \\\n            -H \"Authorization: Bearer ${RELEASE_ADMIN_KEY}\"",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("validate-publish-key");
  });

  it("catches a manifest advance that stopped presenting the OIDC token", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace(
            '-H "Authorization: Bearer ${token}" \\\n            -H "Content-Type: application/json" \\\n            --data-binary',
            '-H "Authorization: Bearer ${RELEASE_ADMIN_KEY}" \\\n            -H "Content-Type: application/json" \\\n            --data-binary',
          )
        : source,
    );
    expect(failures.join("\n")).toContain("releases-audience OIDC token (id-token: write)");
  });

  it("catches a manifest advance that hides the worker's refusal reason", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace("curl --fail-with-body -sS -X POST", "curl --fail -sS -X POST")
        : source,
    );
    expect(failures.join("\n")).toContain("curl --fail-with-body");
  });

  it("catches a token request that no longer fails on a token-service error", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replaceAll(
            'response=$(curl --fail-with-body -sS -H "Authorization: bearer',
            'response=$(curl -sS -H "Authorization: bearer',
          )
        : source,
    );
    expect(failures.join("\n")).toContain("validate-publish-key");
  });

  it("catches a releases-audience token requested by a third step", () => {
    const tokenLine =
      '          response=$(curl --fail-with-body -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://releases.sitecmd.com")\n';
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace(
            "      - name: Smoke test the public release surface\n",
            `      - name: Smoke test the public release surface\n        run: |\n${tokenLine}`,
          )
        : source,
    );
    expect(failures.join("\n")).toContain("validate-publish-key");
  });

  it("catches a publish job missing the AWS region", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace("          AWS_DEFAULT_REGION: auto\n", "")
        : source,
    );
    expect(failures.join("\n")).toContain("AWS_DEFAULT_REGION");
  });

  it("catches a decode that stopped stripping carriage returns", () => {
    const failures = run((file, source) =>
      file.endsWith("verify-signed-payload.sh")
        ? source.replace(
            "tr -d '\\r' | base64 --decode > updater-public-key.pub",
            "base64 --decode > updater-public-key.pub",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("carriage returns");
  });

  it("catches a macOS CLI whose native signature is no longer verified", () => {
    const failures = run((file, source) =>
      file.endsWith("verify-unix-artifacts.sh")
        ? source.replace(
            "  codesign --verify --strict cli-check/sitecmd",
            "  # codesign --verify --strict cli-check/sitecmd",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("extracted macOS CLI");
  });

  it("catches a Windows CLI whose Authenticode signature is no longer verified", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace(
            "          $cliSignature = Get-AuthenticodeSignature $cli",
            "          # $cliSignature = Get-AuthenticodeSignature $cli",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("extracted Windows CLI");
  });

  it("catches a CLI archive that omits its license materials", () => {
    const failures = run((file, source) =>
      file.endsWith("build-cli.sh")
        ? source.replace('  "$GITHUB_WORKSPACE/THIRD_PARTY_DEPENDENCIES.json" \\\n', "")
        : source,
    );
    expect(failures.join("\n")).toContain(
      "CLI archive must include notices, a dependency inventory, upstream license texts",
    );
  });

  it("catches a desktop bundle that omits its license materials", () => {
    const failures = run((file, source) =>
      file.endsWith("tauri.conf.json")
        ? source.replace(
            '      "../../../LICENSE": "LICENSE",\n      "../../../NOTICE": "NOTICE",\n      "../../../THIRD_PARTY_NOTICES": "THIRD_PARTY_NOTICES",\n',
            "",
          )
        : source,
    );
    expect(failures.join("\n")).toContain(
      "Desktop bundle must include notices, a dependency inventory, and upstream license texts",
    );
  });
});

describe("release audits are mirrored faithfully and run first", () => {
  const walk = (dir, filter) => {
    const out = [];
    const go = (d) => {
      for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
        const full = `${d}/${entry.name}`;
        if (entry.isDirectory()) go(full);
        else if (filter(full)) out.push(full);
      }
    };
    go(dir);
    return out;
  };
  const run = (mutate = (_file, source) => source) =>
    ciCostSafetyFailures((file) => mutate(file, realRead(file)), walk);

  it("passes the real repository", () => {
    expect(run()).toEqual([]);
  });

  it("catches a local gate that drops the fresh-advisory flag", () => {
    const failures = run((file, source) =>
      file.includes("verify-push.mjs")
        ? source.replace(
            "SITECMD_RUST_AUDIT_FETCH=1 pnpm run audit:deps:rust",
            "pnpm run audit:deps:rust",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("SITECMD_RUST_AUDIT_FETCH=1");
  });

  it("is not satisfied by the flag appearing only in a comment", () => {
    const failures = run((file, source) =>
      file.includes("verify-push.mjs")
        ? source.replace(
            '      name: "audit:deps:rust",\n      cmd: "SITECMD_RUST_AUDIT_FETCH=1 pnpm run audit:deps:rust",',
            '      // Set SITECMD_RUST_AUDIT_FETCH=1 here to match CI.\n      name: "audit:deps:rust",\n      cmd: "pnpm run audit:deps:rust",',
          )
        : source,
    );
    expect(failures.join("\n")).toContain("SITECMD_RUST_AUDIT_FETCH=1");
  });

  it("catches audits moved back behind the test suites", () => {
    const failures = run((file, source) => {
      if (!file.includes("release.yml")) return source;
      const audits = source.match(
        / {6}- name: JavaScript dependency audit[\s\S]*?run: pnpm run audit:deps:rust\n/,
      )[0];
      return source
        .replace(audits, "")
        .replace("      - name: Rust tests", `${audits}\n      - name: Rust tests`);
    });
    expect(failures.join("\n")).toContain("before `pnpm test`");
  });

  const diskStepBlock = (source) => {
    const start = source.indexOf("      - name: Free runner disk");
    const end = source.indexOf("\n      - ", start);
    return source.slice(start, end + 1);
  };

  it("catches a removed Free runner disk step", () => {
    const failures = run((file, source) =>
      file.includes("release.yml") ? source.replace(diskStepBlock(source), "") : source,
    );
    expect(failures.join("\n")).toContain("Free runner disk");
  });

  it("is not satisfied by a comment naming the disk step", () => {
    const failures = run((file, source) =>
      file.includes("release.yml")
        ? source.replace(diskStepBlock(source), "      # - name: Free runner disk\n")
        : source,
    );
    expect(failures.join("\n")).toContain("Free runner disk");
  });

  it("catches a dropped Linux clippy push trigger", () => {
    const failures = run((file, source) =>
      file.includes("cargo-clippy.yml")
        ? source.replace(
            '  push:\n    branches: [main]\n    paths:\n      - "apps/desktop/src-tauri/**"\n      - ".github/workflows/cargo-clippy.yml"\n',
            "",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("cargo-clippy.yml must keep its push-to-main trigger");
  });

  it("catches the disk step moved behind the Rust tests", () => {
    const failures = run((file, source) => {
      if (!file.includes("release.yml")) return source;
      const step = diskStepBlock(source);
      return source
        .replace(step, "")
        .replace("      - name: Rust doctests", `${step}      - name: Rust doctests`);
    });
    expect(failures.join("\n")).toContain("before the Rust test steps");
  });
});
