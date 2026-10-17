import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  parsePublicationArguments,
  preparePublicHistory,
  resolveBackupPath,
  runPublicationChecks,
} from "./prepare-public-history.mjs";

const temporaryRoots = [];
const PUBLIC_HISTORY_TEST_TIMEOUT_MS = 15_000;

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

function command(commandName, args, cwd, { capture = true } = {}) {
  const result = spawnSync(commandName, args, {
    cwd,
    encoding: "utf8",
    stdio: capture ? ["ignore", "pipe", "pipe"] : "ignore",
  });
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || result.stdout.trim() || `${commandName} failed`);
  }
  return capture ? result.stdout.trim() : "";
}

function git(root, ...args) {
  return command("git", args, root);
}

function repositoryFixture() {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "sitecmd-public-history-test-"));
  temporaryRoots.push(temporaryRoot);
  const root = path.join(temporaryRoot, "repository");
  const key = path.join(temporaryRoot, "signing-key");
  const backup = path.join(temporaryRoot, "private-history.bundle");
  fs.mkdirSync(root);
  git(root, "init", "--initial-branch=main");
  git(root, "config", "user.name", "SiteCMD Test");
  git(root, "config", "user.email", "test@sitecmd.invalid");
  command("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", key], root);
  git(root, "config", "gpg.format", "ssh");
  git(root, "config", "user.signingkey", `${key}.pub`);
  // A global tag.gpgSign turns the lightweight fixture tag into a signed one that needs a message.
  git(root, "config", "tag.gpgSign", "false");

  fs.mkdirSync(path.join(root, ".github"));
  const publicKey = fs.readFileSync(`${key}.pub`, "utf8").trim();
  fs.writeFileSync(
    path.join(root, ".github", "allowed-signers"),
    `test@sitecmd.invalid ${publicKey}\n`,
  );
  fs.writeFileSync(path.join(root, "README.md"), "private history\n");
  git(root, "add", "--all");
  git(root, "commit", "-m", "Create fixture");
  fs.writeFileSync(path.join(root, "README.md"), "approved public tree\n");
  git(root, "add", "README.md");
  git(root, "commit", "-m", "Approve public tree");
  git(root, "tag", "private-history-tag", "HEAD~1");
  return { backup, root };
}

describe("parsePublicationArguments", () => {
  it("defaults to a dry run", () => {
    expect(parsePublicationArguments(["--backup", "/tmp/sitecmd.bundle"])).toEqual({
      apply: false,
      backup: "/tmp/sitecmd.bundle",
      confirmed: false,
    });
  });

  it("requires explicit confirmation for apply mode", () => {
    expect(() => parsePublicationArguments(["--backup", "/tmp/sitecmd.bundle", "--apply"])).toThrow(
      "--confirm-rewrite-main",
    );
  });

  it("rejects unknown arguments", () => {
    expect(() => parsePublicationArguments(["--backup", "/tmp/sitecmd.bundle", "main"])).toThrow(
      "unknown argument",
    );
  });
});

describe("resolveBackupPath", () => {
  it("requires a new absolute bundle outside the checkout", () => {
    const { backup, root } = repositoryFixture();
    expect(resolveBackupPath(root, backup)).toBe(
      path.join(fs.realpathSync(path.dirname(backup)), path.basename(backup)),
    );
    expect(() => resolveBackupPath(root, "private.bundle")).toThrow("must be absolute");
    expect(() => resolveBackupPath(root, path.join(root, "private.bundle"))).toThrow(
      "outside the repository",
    );
  });
});

describe("preparePublicHistory", { timeout: PUBLIC_HISTORY_TEST_TIMEOUT_MS }, () => {
  it("scans an exact tracked-tree export without ignored checkout files", () => {
    const { root } = repositoryFixture();
    fs.writeFileSync(path.join(root, ".gitignore"), ".env\n");
    git(root, "add", ".gitignore");
    git(root, "commit", "-m", "Ignore local environment");
    fs.writeFileSync(path.join(root, ".env"), "TOKEN=test-fixture-local-secret\n");

    const expectedTree = git(root, "rev-parse", "HEAD^{tree}");
    let scanRoot = "";
    const runCommand = (commandName, args, cwd, options = {}) => {
      if (commandName === process.execPath) return "";
      if (commandName === "gitleaks") {
        scanRoot = cwd;
        expect(args.at(-1)).toBe(".");
        expect(cwd).not.toBe(root);
        expect(fs.readFileSync(path.join(cwd, "README.md"), "utf8")).toBe("approved public tree\n");
        expect(fs.existsSync(path.join(cwd, ".env"))).toBe(false);
        return "";
      }
      return command(commandName, args, cwd, options);
    };

    runPublicationChecks(root, runCommand, expectedTree);

    expect(scanRoot).not.toBe("");
    expect(fs.existsSync(scanRoot)).toBe(false);
  });

  it("refuses a dirty or non-main checkout", () => {
    const dirty = repositoryFixture();
    fs.writeFileSync(path.join(dirty.root, "README.md"), "uncommitted change\n");
    expect(() =>
      preparePublicHistory({
        root: dirty.root,
        options: { apply: false, backup: dirty.backup, confirmed: false },
        checkPublication: () => {},
        write: () => {},
      }),
    ).toThrow("commit the exact approved tree");

    const branch = repositoryFixture();
    git(branch.root, "switch", "-c", "release/candidate");
    expect(() =>
      preparePublicHistory({
        root: branch.root,
        options: { apply: false, backup: branch.backup, confirmed: false },
        checkPublication: () => {},
        write: () => {},
      }),
    ).toThrow("requires the main branch");
  });

  it("refuses dirty linked worktrees", () => {
    const { backup, root } = repositoryFixture();
    const linkedRoot = path.join(path.dirname(root), "linked-worktree");
    git(root, "worktree", "add", "--detach", linkedRoot, "HEAD");
    fs.writeFileSync(path.join(linkedRoot, "README.md"), "uncommitted linked change\n");

    expect(() =>
      preparePublicHistory({
        root,
        options: { apply: false, backup, confirmed: false },
        checkPublication: () => {},
        write: () => {},
      }),
    ).toThrow("dirty linked worktrees");
  });

  it("does not write a bundle or move main during a dry run", () => {
    const { backup, root } = repositoryFixture();
    const before = git(root, "rev-parse", "HEAD");
    const output = [];
    const result = preparePublicHistory({
      root,
      options: { apply: false, backup, confirmed: false },
      checkPublication: () => {},
      write: (value) => output.push(value),
    });

    expect(result.applied).toBe(false);
    expect(fs.existsSync(backup)).toBe(false);
    expect(git(root, "rev-parse", "HEAD")).toBe(before);
    expect(output.join("\n")).toContain("DRY RUN");
  });

  it("backs up all refs before moving main to a signed exact-tree root commit", () => {
    const { backup, root } = repositoryFixture();
    const oldHead = git(root, "rev-parse", "HEAD");
    const oldTree = git(root, "rev-parse", "HEAD^{tree}");
    const output = [];
    const result = preparePublicHistory({
      root,
      options: { apply: true, backup, confirmed: true },
      checkPublication: () => {},
      checkCandidateHistory: () => {},
      write: (value) => output.push(value),
    });

    expect(result.applied).toBe(true);
    expect(fs.existsSync(backup)).toBe(true);
    expect(git(root, "bundle", "list-heads", backup)).toContain(oldHead);
    expect(git(root, "bundle", "list-heads", backup)).toContain("refs/tags/private-history-tag");
    expect(git(root, "rev-list", "--count", "main")).toBe("1");
    expect(git(root, "rev-parse", "HEAD^{tree}")).toBe(oldTree);
    expect(git(root, "status", "--porcelain")).toBe("");
    expect(output.join("\n")).toContain("Old local branches and tags still exist");
    git(
      root,
      "-c",
      "gpg.ssh.allowedSignersFile=.github/allowed-signers",
      "verify-commit",
      result.commit,
    );
  });

  it("restores main if a post-rewrite verification fails", () => {
    const { backup, root } = repositoryFixture();
    const oldHead = git(root, "rev-parse", "HEAD");
    let mainMoved = false;
    let injectedFailure = false;
    const runCommand = (commandName, args, cwd, options = {}) => {
      if (
        mainMoved &&
        !injectedFailure &&
        commandName === "git" &&
        args[0] === "rev-parse" &&
        args[1] === "--show-toplevel"
      ) {
        injectedFailure = true;
        throw new Error("injected postcondition failure");
      }
      const output = command(commandName, args, cwd, options);
      if (
        commandName === "git" &&
        args[0] === "update-ref" &&
        args[1] === "refs/heads/main" &&
        args[3] === oldHead
      ) {
        mainMoved = true;
      }
      return output;
    };

    expect(() =>
      preparePublicHistory({
        root,
        options: { apply: true, backup, confirmed: true },
        runCommand,
        checkPublication: () => {},
        checkCandidateHistory: () => {},
        write: () => {},
      }),
    ).toThrow("main was restored");
    expect(injectedFailure).toBe(true);
    expect(git(root, "rev-parse", "HEAD")).toBe(oldHead);
    expect(fs.existsSync(backup)).toBe(true);
  });
});
