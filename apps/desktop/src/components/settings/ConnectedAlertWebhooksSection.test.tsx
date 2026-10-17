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
import { ConnectedAlertWebhooksSection } from "./ConnectedAlertWebhooksSection";

function renderSection() {
  return render(
    <ConnectedAlertWebhooksSection projectId={7} environmentScopeKey="https://example.com" />,
    { wrapper: withQueryClient() },
  );
}

const healthyRow = {
  webhookId: "awh_1",
  url: "https://hooks.example.com/sitecmd",
  secretFingerprint: "sha256:0123456789abcdef",
  secretGeneration: 1,
  disabled: false,
  disabledReason: null,
  rotationOverlapUntil: null,
  createdAt: "2026-08-01T00:00:00Z",
};

describe("ConnectedAlertWebhooksSection", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    copyMock.mockClear();
    toastSuccess.mockClear();
    toastError.mockClear();
  });

  it("adds an endpoint and shows the signing secret exactly once", async () => {
    invokeMock.mockImplementation((command: unknown) => {
      if (command === "list_connected_alert_webhooks") return Promise.resolve([]);
      if (command === "create_connected_alert_webhook") {
        return Promise.resolve({
          webhookId: "awh_new",
          url: "https://hooks.example.com/sitecmd",
          secret: "shown-once-secret",
          secretFingerprint: "sha256:feedfacefeedface",
        });
      }
      return Promise.resolve(null);
    });

    renderSection();
    fireEvent.change(await screen.findByLabelText("Endpoint URL (public HTTPS)"), {
      target: { value: "https://hooks.example.com/sitecmd" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add Webhook Endpoint" }));

    expect(await screen.findByText("shown-once-secret")).toBeInTheDocument();
    expect(screen.getByText(/one time it is readable/i)).toBeInTheDocument();
    expect(screen.getByText(/whsec_ secret and any Standard Webhooks library/)).toBeInTheDocument();
    expect(
      screen.getByText(/webhook-id, webhook-timestamp, and webhook-signature headers/),
    ).toBeInTheDocument();
    expect(screen.queryByText(/X-SiteCMD-Signature/i)).not.toBeInTheDocument();
    expect(invokeMock).toHaveBeenCalledWith("create_connected_alert_webhook", {
      projectId: 7,
      environmentScopeKey: "https://example.com",
      url: "https://hooks.example.com/sitecmd",
    });

    fireEvent.click(screen.getByRole("button", { name: "Copy Secret" }));
    await waitFor(() => expect(copyMock).toHaveBeenCalledWith("shown-once-secret"));
  });

  it("lists endpoints with fingerprints and makes auto-disable visible, never silent", async () => {
    invokeMock.mockImplementation((command: unknown) => {
      if (command === "list_connected_alert_webhooks") {
        return Promise.resolve([
          healthyRow,
          {
            ...healthyRow,
            webhookId: "awh_down",
            url: "https://dead.example.com/hook",
            disabled: true,
            disabledReason: "persistent_failure",
          },
        ]);
      }
      return Promise.resolve(null);
    });

    renderSection();
    expect(await screen.findByText("https://dead.example.com/hook")).toBeInTheDocument();
    expect(screen.getByText(/disabled after repeated failures/)).toBeInTheDocument();
    expect(screen.getByText(/a successful test re-enables it/)).toBeInTheDocument();
    expect(screen.getAllByText(/sha256:0123456789abcdef/)).toHaveLength(2);
  });

  it("rotates a secret and explains the dual-signature overlap", async () => {
    invokeMock.mockImplementation((command: unknown) => {
      if (command === "list_connected_alert_webhooks") return Promise.resolve([healthyRow]);
      if (command === "rotate_connected_alert_webhook") {
        return Promise.resolve({
          webhookId: "awh_1",
          secret: "next-generation-secret",
          secretFingerprint: "sha256:aaaabbbbccccdddd",
          rotationOverlapUntil: "2026-08-11T00:00:00Z",
        });
      }
      return Promise.resolve(null);
    });

    renderSection();
    fireEvent.click(await screen.findByRole("button", { name: "Rotate Secret" }));

    expect(await screen.findByText("next-generation-secret")).toBeInTheDocument();
    expect(screen.getByText(/previous generation's signature too/)).toBeInTheDocument();
    expect(screen.getByText(/webhook-signature carries the previous/)).toBeInTheDocument();
    expect(screen.queryByText(/X-SiteCMD-Signature/i)).not.toBeInTheDocument();
    expect(invokeMock).toHaveBeenCalledWith("rotate_connected_alert_webhook", {
      projectId: 7,
      environmentScopeKey: "https://example.com",
      webhookId: "awh_1",
    });
  });

  it("sends a test delivery through the service's queue", async () => {
    invokeMock.mockImplementation((command: unknown) => {
      if (command === "list_connected_alert_webhooks") return Promise.resolve([healthyRow]);
      if (command === "test_connected_alert_webhook") {
        return Promise.resolve({ attemptId: "att_1", webhookId: "awh_1" });
      }
      return Promise.resolve(null);
    });

    renderSection();
    fireEvent.click(await screen.findByRole("button", { name: "Test" }));

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith("test_connected_alert_webhook", {
        projectId: 7,
        environmentScopeKey: "https://example.com",
        webhookId: "awh_1",
      }),
    );
    expect(toastSuccess).toHaveBeenCalledWith("Test delivery on its way", expect.any(String));
  });

  it("deletes an endpoint", async () => {
    invokeMock.mockImplementation((command: unknown) => {
      if (command === "list_connected_alert_webhooks") return Promise.resolve([healthyRow]);
      return Promise.resolve(null);
    });

    renderSection();
    fireEvent.click(await screen.findByRole("button", { name: "Remove" }));

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith("delete_connected_alert_webhook", {
        projectId: 7,
        environmentScopeKey: "https://example.com",
        webhookId: "awh_1",
      }),
    );
    expect(toastSuccess).toHaveBeenCalledWith("Webhook endpoint deleted");
  });
});
