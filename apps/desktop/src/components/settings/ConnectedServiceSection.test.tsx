import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { invokeMock, copyMock, toastSuccess, toastError } = vi.hoisted(() => ({
  invokeMock: vi.fn<(...args: unknown[]) => Promise<unknown>>(),
  copyMock: vi.fn<(...args: unknown[]) => Promise<void>>(() => Promise.resolve()),
  toastSuccess: vi.fn(),
  toastError: vi.fn(),
}));

vi.mock("@/lib/tauri-invoke", () => ({ invoke: invokeMock }));
vi.mock("@/lib/clipboard", () => ({ copyToClipboard: copyMock }));
vi.mock("@/hooks/useToast", () => ({
  useToast: () => ({ success: toastSuccess, error: toastError }),
}));

import { withQueryClient } from "@/test-utils/query-client";
import { ConnectedServiceSection } from "./ConnectedServiceSection";

function renderSection() {
  return render(
    <ConnectedServiceSection projectId={7} environmentScopeKey="https://example.com" />,
    { wrapper: withQueryClient() },
  );
}

describe("ConnectedServiceSection", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    copyMock.mockClear();
    toastSuccess.mockClear();
    toastError.mockClear();
  });

  it("shows the exact unsent payload before a site is connected", async () => {
    invokeMock.mockImplementation((command: unknown) => {
      if (command === "get_connected_status") {
        return Promise.resolve({
          endpointConfigured: true,
          connected: false,
          siteId: null,
          bootstrapped: false,
          hasInstallationToken: false,
          hasFingerprintKey: false,
          pendingMutations: 0,
          conflictedMutations: 0,
          lastSubmissionSequence: 0,
          fingerprintKeyVersion: 1,
          pendingKeyVersion: null,
        });
      }
      if (command === "inspect_connected_sync") {
        return Promise.resolve({
          payload: '{"schema_version":1,"site_id":"site_pending_connection"}',
          connected: false,
          includesBootstrap: true,
          proposedSubmissionSequence: 1,
        });
      }
      return Promise.resolve(null);
    });

    renderSection();
    fireEvent.click(await screen.findByRole("button", { name: "Inspect Payload" }));

    expect(
      await screen.findByText('{"schema_version":1,"site_id":"site_pending_connection"}'),
    ).toBeInTheDocument();
    expect(screen.getByText(/Nothing has been sent/)).toBeInTheDocument();
    expect(invokeMock).toHaveBeenCalledWith("inspect_connected_sync", {
      projectId: 7,
      environmentScopeKey: "https://example.com",
    });
  });

  it("creates a site and then shows what has to be published to prove it", async () => {
    let connected = false;
    invokeMock.mockImplementation((command: unknown) => {
      if (command === "get_connected_status") {
        return Promise.resolve({
          endpointConfigured: true,
          connected,
          siteId: connected ? "site_new" : null,
          bootstrapped: false,
          hasInstallationToken: connected,
          hasFingerprintKey: connected,
          pendingMutations: 0,
          conflictedMutations: 0,
          lastSubmissionSequence: 0,
          fingerprintKeyVersion: 1,
          pendingKeyVersion: null,
        });
      }
      if (command === "create_connected_site") {
        connected = true;
        return Promise.resolve({
          siteId: "site_new",
          url: "https://example.com",
          phase: "pending_verification",
          challenge: "0123456789abcdef",
          dnsName: "_sitecmd.example.com",
          dnsType: "TXT",
          wellKnownPath: "/.well-known/sitecmd-site-verification",
        });
      }
      if (command === "fetch_connected_site_state") {
        return Promise.resolve({
          siteId: "site_new",
          phase: "pending_verification",
          eventSequence: 1,
          challenge: null,
        });
      }
      return Promise.resolve(null);
    });

    renderSection();
    fireEvent.change(await screen.findByLabelText("Production URL"), {
      target: { value: "https://example.com" },
    });
    fireEvent.change(screen.getByLabelText("Installation token (only when moving one by hand)"), {
      target: { value: "sitecmd_ins_abc" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create Connected Site" }));

    expect(await screen.findByText("0123456789abcdef")).toBeInTheDocument();
    expect(screen.getByText("TXT _sitecmd.example.com")).toBeInTheDocument();
    expect(invokeMock).toHaveBeenCalledWith("create_connected_site", {
      projectId: 7,
      environmentScopeKey: "https://example.com",
      url: "https://example.com",
      installationToken: "sitecmd_ins_abc",
    });
    expect(screen.getByText(/Nothing is scanned and no mail is sent/)).toBeInTheDocument();
  });

  it("recovers the challenge from the service when the app was reopened", async () => {
    invokeMock.mockImplementation((command: unknown) => {
      if (command === "get_connected_status") {
        return Promise.resolve({
          endpointConfigured: true,
          connected: true,
          siteId: "site_new",
          bootstrapped: false,
          hasInstallationToken: true,
          hasFingerprintKey: true,
          pendingMutations: 0,
          conflictedMutations: 0,
          lastSubmissionSequence: 0,
          fingerprintKeyVersion: 1,
          pendingKeyVersion: null,
        });
      }
      if (command === "fetch_connected_site_state") {
        return Promise.resolve({
          siteId: "site_new",
          phase: "pending_verification",
          eventSequence: 1,
          challenge: {
            siteId: "site_new",
            url: "",
            phase: "pending_verification",
            challenge: "recovered-challenge",
            dnsName: "_sitecmd.example.com",
            dnsType: "TXT",
            wellKnownPath: "/.well-known/sitecmd-site-verification",
          },
        });
      }
      if (command === "verify_connected_site") {
        return Promise.resolve({ phase: "pending_bootstrap", verified: true });
      }
      return Promise.resolve(null);
    });

    renderSection();
    expect(await screen.findByText("recovered-challenge")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Verify DNS Record" }));
    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith("verify_connected_site", {
        projectId: 7,
        environmentScopeKey: "https://example.com",
        method: "dns_txt",
      }),
    );
    expect(toastSuccess).toHaveBeenCalledWith("Ownership proved", expect.any(String));
  });

  it("shows the connected scope and site-allowance standing returned by the service", async () => {
    invokeMock.mockImplementation((command: unknown) => {
      if (command === "get_connected_status") {
        return Promise.resolve({
          endpointConfigured: true,
          connected: true,
          siteId: "site_new",
          bootstrapped: true,
          hasInstallationToken: true,
          hasFingerprintKey: true,
          pendingMutations: 0,
          conflictedMutations: 0,
          lastSubmissionSequence: 1,
          fingerprintKeyVersion: 1,
          pendingKeyVersion: null,
        });
      }
      if (command === "fetch_connected_site_state") {
        return Promise.resolve({
          siteId: "site_new",
          phase: "connected",
          eventSequence: 8,
          challenge: null,
          scopeRevision: 3,
          scopeRoutes: ["/", "/pricing"],
          scopeEffectiveRouteCount: 12,
          scopeRouteCap: 10,
          scopeOverPlan: true,
          scopeOverPlanGraceExpiresAt: "2099-08-20T00:00:00.000Z",
          scopeOverflowCount: 2,
          siteAllowanceOverPlan: false,
          siteAllowanceOverPlanGraceExpiresAt: null,
        });
      }
      return Promise.resolve(null);
    });

    renderSection();

    expect(
      await screen.findByText(/12 routes, 2 over 10-route plan, Grace until/),
    ).toBeInTheDocument();
    expect(screen.getByText("Within plan")).toBeInTheDocument();
  });

  it("verifies through a provider project and reports the deploy trigger", async () => {
    invokeMock.mockImplementation((command: unknown) => {
      if (command === "get_connected_status") {
        return Promise.resolve({
          endpointConfigured: true,
          connected: true,
          siteId: "site_new",
          bootstrapped: false,
          hasInstallationToken: true,
          hasFingerprintKey: true,
          pendingMutations: 0,
          conflictedMutations: 0,
          lastSubmissionSequence: 0,
          fingerprintKeyVersion: 1,
          pendingKeyVersion: null,
        });
      }
      if (command === "fetch_connected_site_state") {
        return Promise.resolve({
          siteId: "site_new",
          phase: "pending_verification",
          eventSequence: 1,
          challenge: {
            siteId: "site_new",
            url: "",
            phase: "pending_verification",
            challenge: "challenge-value",
            dnsName: "_sitecmd.example.com",
            dnsType: "TXT",
            wellKnownPath: "/.well-known/sitecmd-site-verification",
          },
        });
      }
      if (command === "list_connected_provider_connections") {
        return Promise.resolve([
          {
            id: "pc_1",
            provider: "vercel",
            status: "active",
            createdAt: "2026-08-01T00:00:00Z",
            activatedAt: "2026-08-01T00:01:00Z",
            externalAccount: { id: "acct_1", name: "Acme Team" },
            grantedScopes: "read-write projects",
            failedReason: null,
            revokedAt: null,
            revokedReason: null,
          },
        ]);
      }
      if (command === "list_connected_provider_projects") {
        return Promise.resolve([{ externalProjectId: "prj_9", name: "acme-site" }]);
      }
      if (command === "verify_connected_site_provider") {
        return Promise.resolve({
          phase: "pending_bootstrap",
          verified: true,
          deployTriggerStatus: "provisioned",
          deployTriggerProvider: "vercel",
        });
      }
      return Promise.resolve(null);
    });

    renderSection();
    fireEvent.change(await screen.findByLabelText(/let a connected provider vouch/), {
      target: { value: "pc_1" },
    });
    // Wait until the provider project becomes selectable.
    await screen.findByRole("option", { name: "acme-site" });
    fireEvent.change(screen.getByLabelText("Provider project"), {
      target: { value: "prj_9" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify Through Provider" }));

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith("verify_connected_site_provider", {
        projectId: 7,
        environmentScopeKey: "https://example.com",
        connectionId: "pc_1",
        externalProjectId: "prj_9",
      }),
    );
    expect(toastSuccess).toHaveBeenCalledWith(
      "Ownership proved through the provider",
      expect.stringContaining("Deploys will be reported automatically"),
    );
  });

  it("shows a minted CI token exactly once and says so", async () => {
    invokeMock.mockImplementation((command: unknown) => {
      if (command === "get_connected_status") {
        return Promise.resolve({
          endpointConfigured: true,
          connected: true,
          siteId: "site_123",
          bootstrapped: true,
          hasInstallationToken: true,
          hasFingerprintKey: true,
          pendingMutations: 0,
          conflictedMutations: 0,
          lastSubmissionSequence: 1,
          fingerprintKeyVersion: 1,
          pendingKeyVersion: null,
        });
      }
      if (command === "mint_connected_ci_token") {
        return Promise.resolve({
          id: "cit_abc",
          siteId: "site_123",
          token: "sitecmd_ci_secret",
          repository: "brambleworks/SiteCMD-Local",
          repositoryId: "1296269",
          orderingAuthorityId: "github:1296269:authority",
          orderingAuthorityEpoch: 1,
        });
      }
      return Promise.resolve(null);
    });

    renderSection();
    expect(
      await screen.findByText(/read only the deployment-ordering cursor/i),
    ).toBeInTheDocument();
    fireEvent.change(await screen.findByLabelText("Repository (optional)"), {
      target: { value: "brambleworks/SiteCMD-Local" },
    });
    fireEvent.change(screen.getByLabelText("Trusted workflow (required for verified CI)"), {
      target: { value: ".github/workflows/sitecmd.yml" },
    });
    fireEvent.change(screen.getByLabelText("Trusted ref (optional)"), {
      target: { value: "refs/heads/main" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create CI Token" }));

    expect(await screen.findByText("sitecmd_ci_secret")).toBeInTheDocument();
    expect(screen.getByText(/one time it is readable/i)).toBeInTheDocument();
    expect(screen.getByText(/immutable GitHub repository id 1296269/i)).toBeInTheDocument();
    expect(screen.getByText(/governing publish authority selected/i)).toHaveTextContent(
      "github:1296269:authority",
    );
    expect(screen.getByText(/id-token: write/i)).toBeInTheDocument();
    expect(invokeMock).toHaveBeenCalledWith("mint_connected_ci_token", {
      projectId: 7,
      environmentScopeKey: "https://example.com",
      repository: "brambleworks/SiteCMD-Local",
      workflowRef: ".github/workflows/sitecmd.yml",
      gitRef: "refs/heads/main",
    });
  });

  it("exchanges the license for the connected credential without a pasted token", async () => {
    let activated = false;
    invokeMock.mockImplementation((command: unknown) => {
      if (command === "get_connected_status") {
        return Promise.resolve({
          endpointConfigured: true,
          connected: false,
          siteId: null,
          bootstrapped: false,
          hasInstallationToken: activated,
          hasFingerprintKey: false,
          pendingMutations: 0,
          conflictedMutations: 0,
          lastSubmissionSequence: 0,
          fingerprintKeyVersion: 1,
          pendingKeyVersion: null,
        });
      }
      if (command === "activate_connected_service") {
        activated = true;
        return Promise.resolve({ tier: "core" });
      }
      return Promise.resolve(null);
    });

    renderSection();
    fireEvent.click(await screen.findByRole("button", { name: "Activate with Your License" }));

    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith("activate_connected_service", {}));
    expect(toastSuccess).toHaveBeenCalledWith("Connected service activated", expect.any(String));
    // The button gives way to the no-token state once the credential exists.
    expect(
      await screen.findByText(/already holds its connected-service credential/i),
    ).toBeInTheDocument();
  });

  it("stops watching remotely, as a distinct act from unlinking this desktop", async () => {
    let phase = "connected";
    invokeMock.mockImplementation((command: unknown) => {
      if (command === "get_connected_status") {
        return Promise.resolve({
          endpointConfigured: true,
          connected: true,
          siteId: "site_123",
          bootstrapped: true,
          hasInstallationToken: true,
          hasFingerprintKey: true,
          pendingMutations: 0,
          conflictedMutations: 0,
          lastSubmissionSequence: 1,
          fingerprintKeyVersion: 1,
          pendingKeyVersion: null,
        });
      }
      if (command === "fetch_connected_site_state") {
        return Promise.resolve({
          siteId: "site_123",
          phase,
          eventSequence: 9,
          challenge: null,
        });
      }
      if (command === "disconnect_connected_site") {
        phase = "disconnected";
        return Promise.resolve(null);
      }
      return Promise.resolve(null);
    });

    renderSection();
    expect(await screen.findByRole("button", { name: "Sync Now" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create CI Token" })).toBeInTheDocument();
    fireEvent.click(await screen.findByRole("button", { name: "Stop Watching" }));

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith("disconnect_connected_site", {
        projectId: 7,
        environmentScopeKey: "https://example.com",
      }),
    );
    expect(toastSuccess).toHaveBeenCalledWith("Site disconnected", expect.any(String));
    expect(await screen.findByRole("button", { name: "Resume Watching" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Sync Now" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create CI Token" })).not.toBeInTheDocument();
    expect(screen.getByText(/does not delete the remote site/i)).toBeInTheDocument();
  });

  it("offers resume instead of stop for a disconnected site, reminted secret shown once", async () => {
    let phase = "disconnected";
    invokeMock.mockImplementation((command: unknown) => {
      if (command === "get_connected_status") {
        return Promise.resolve({
          endpointConfigured: true,
          connected: true,
          siteId: "site_123",
          bootstrapped: true,
          hasInstallationToken: true,
          hasFingerprintKey: true,
          pendingMutations: 0,
          conflictedMutations: 0,
          lastSubmissionSequence: 1,
          fingerprintKeyVersion: 1,
          pendingKeyVersion: null,
        });
      }
      if (command === "fetch_connected_site_state") {
        return Promise.resolve({
          siteId: "site_123",
          phase,
          eventSequence: 9,
          challenge: null,
        });
      }
      if (command === "reconnect_connected_site") {
        phase = "watching";
        return Promise.resolve({
          phase: "watching",
          webhookSecret: { id: "swh_1", secret: "sitecmd_whs_reminted", secretGeneration: 2 },
          deployTriggerStatus: null,
          deployTriggerProvider: null,
        });
      }
      return Promise.resolve(null);
    });

    renderSection();
    fireEvent.click(await screen.findByRole("button", { name: "Resume Watching" }));
    expect(screen.queryByRole("button", { name: "Stop Watching" })).not.toBeInTheDocument();

    expect(await screen.findByText("sitecmd_whs_reminted")).toBeInTheDocument();
    expect(screen.getByText(/revoked every value shown before/i)).toBeInTheDocument();
    expect(invokeMock).toHaveBeenCalledWith("reconnect_connected_site", {
      projectId: 7,
      environmentScopeKey: "https://example.com",
    });
    // The site is watched again, and the shown-once panel survives the flip.
    expect(await screen.findByRole("button", { name: "Stop Watching" })).toBeInTheDocument();
  });

  it("erases the site and shows the receipt token exactly once", async () => {
    let erased = false;
    invokeMock.mockImplementation((command: unknown) => {
      if (command === "get_connected_status") {
        return Promise.resolve({
          endpointConfigured: true,
          connected: !erased,
          siteId: erased ? null : "site_123",
          bootstrapped: !erased,
          hasInstallationToken: !erased,
          hasFingerprintKey: !erased,
          pendingMutations: 0,
          conflictedMutations: 0,
          lastSubmissionSequence: 1,
          fingerprintKeyVersion: 1,
          pendingKeyVersion: null,
        });
      }
      if (command === "erase_connected_site") {
        erased = true;
        return Promise.resolve({ jobId: "erj_1", statusToken: "sitecmd_ers_receipt" });
      }
      return Promise.resolve(null);
    });

    renderSection();
    fireEvent.click(await screen.findByRole("button", { name: "Erase Site Data" }));

    expect(await screen.findByText("sitecmd_ers_receipt")).toBeInTheDocument();
    expect(screen.getByText(/readable exactly once/i)).toBeInTheDocument();
    expect(
      await screen.findByRole("button", { name: "Create Connected Site" }),
    ).toBeInTheDocument();
    expect(invokeMock).toHaveBeenCalledWith("erase_connected_site", {
      projectId: 7,
      environmentScopeKey: "https://example.com",
    });
  });

  it("syncs a connected site and offers a credential-free encrypted export", async () => {
    invokeMock.mockImplementation((command: unknown) => {
      if (command === "get_connected_status") {
        return Promise.resolve({
          endpointConfigured: true,
          connected: true,
          siteId: "site_123",
          bootstrapped: true,
          hasInstallationToken: true,
          hasFingerprintKey: true,
          pendingMutations: 2,
          conflictedMutations: 0,
          pendingScopeSync: true,
          lastSubmissionSequence: 4,
          fingerprintKeyVersion: 1,
          pendingKeyVersion: null,
        });
      }
      if (command === "sync_connected_site") {
        return Promise.resolve({
          submissionSequence: 5,
          eventSequence: 12,
          groupsPulled: 3,
          mutationsSettled: 2,
          mutationConflicts: 0,
        });
      }
      if (command === "export_connected_connection") {
        return Promise.resolve("sitecmd-connection-v1.encrypted");
      }
      return Promise.resolve(null);
    });

    renderSection();
    expect(await screen.findByText("site_123")).toBeInTheDocument();
    expect(screen.getByText("Retry pending")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Sync Now" }));
    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith("sync_connected_site", {
        projectId: 7,
        environmentScopeKey: "https://example.com",
      }),
    );
    await waitFor(() => {
      const remoteReads = invokeMock.mock.calls.filter(
        ([command]) => command === "fetch_connected_site_state",
      );
      expect(remoteReads.length).toBeGreaterThanOrEqual(2);
    });

    fireEvent.change(screen.getByLabelText("Export passphrase"), {
      target: { value: "correct horse battery staple" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create Encrypted Export" }));
    expect(await screen.findByText("sitecmd-connection-v1.encrypted")).toBeInTheDocument();
    expect(invokeMock).toHaveBeenCalledWith("export_connected_connection", {
      projectId: 7,
      environmentScopeKey: "https://example.com",
      passphrase: "correct horse battery staple",
    });
    expect(screen.getByText(/never contains the installation token/i)).toBeInTheDocument();
  });

  it("reports an undelivered scan scope without calling the whole sync a failure", async () => {
    invokeMock.mockImplementation((command: unknown) => {
      if (command === "get_connected_status") {
        return Promise.resolve({
          endpointConfigured: true,
          connected: true,
          siteId: "site_123",
          bootstrapped: true,
          hasInstallationToken: true,
          hasFingerprintKey: true,
          pendingMutations: 0,
          conflictedMutations: 0,
          pendingScopeSync: true,
          lastSubmissionSequence: 4,
          fingerprintKeyVersion: 1,
          pendingKeyVersion: null,
        });
      }
      if (command === "sync_connected_site") {
        return Promise.resolve({
          submissionSequence: 5,
          eventSequence: 12,
          groupsPulled: 3,
          mutationsSettled: 1,
          mutationConflicts: 0,
          keyRotationCompleted: null,
          scopeDeliveryPending: true,
        });
      }
      return Promise.resolve(null);
    });

    renderSection();
    expect(await screen.findByText("site_123")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Sync Now" }));

    await waitFor(() =>
      expect(toastSuccess).toHaveBeenCalledWith(
        "Connected state synced",
        expect.stringContaining("The scan scope has not been delivered yet"),
      ),
    );
    expect(toastError).not.toHaveBeenCalled();
    expect(screen.getByText("Retry pending")).toBeInTheDocument();
  });
});
