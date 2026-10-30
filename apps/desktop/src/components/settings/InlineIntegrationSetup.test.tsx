import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { invokeMock, hasFeatureMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  hasFeatureMock: vi.fn(),
}));

vi.mock("@/lib/tauri-invoke", () => ({ invoke: invokeMock }));
vi.mock("@/hooks/useTier", () => ({
  useTier: () => ({
    tier: "free",
    licenseInfo: {
      tier: "free",
      status: "none",
      plan_name: "Free",
      is_active: false,
      expires_at: null,
      checkout_urls: {
        core_monthly: "",
        core_annual: "",
        pro_monthly: "",
        pro_annual: "",
      },
      customer_portal_url: "",
    },
    isLoading: false,
    hasFeature: hasFeatureMock,
    activateLicense: vi.fn(),
    deactivateLicense: vi.fn(),
    refreshLicense: vi.fn(),
  }),
}));
vi.mock("@/hooks/useToast", () => ({
  useToast: () => ({
    success: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
  }),
}));
vi.mock("@/components/icons/ServiceIcon", () => ({
  ServiceIconWithBg: () => React.createElement("span", null, "icon"),
}));
vi.mock("@/components/ui/external-link", () => ({
  ExtLink: ({
    children,
    href,
    className,
  }: {
    children: React.ReactNode;
    href: string;
    className?: string;
  }) => React.createElement("a", { href, className }, children),
}));

import { InlineIntegrationSetup } from "./InlineIntegrationSetup";
import { createTestQueryClient, withQueryClient } from "@/test-utils/query-client";

function renderInline(ui: React.ReactElement) {
  return render(ui, { wrapper: withQueryClient(createTestQueryClient()) });
}

describe("InlineIntegrationSetup", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    hasFeatureMock.mockReset();
    hasFeatureMock.mockImplementation((feature: string) => feature === "integration_connect");
  });

  it("shows every requested integration as connectable", async () => {
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "get_integrations") {
        return [];
      }
      return null;
    });

    renderInline(
      <InlineIntegrationSetup
        serviceTypes={["plausible", "github"]}
        projectId={42}
        url="https://example.com"
      />,
    );

    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith("get_integrations", { projectId: 42 });
    });

    expect(screen.queryByText(/Upgrade to connect/i)).not.toBeInTheDocument();
    expect(await screen.findByText("GitHub")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Connect with GitHub/i })).toBeInTheDocument();

    fireEvent.click(screen.getByText("Plausible Analytics").closest("button")!);

    expect(await screen.findByRole("button", { name: "Connect" })).toBeInTheDocument();
    expect(screen.getByText("Open Plausible API Keys →")).toBeInTheDocument();
  });

  it("hides an already-connected service by default but surfaces it for reconnect", async () => {
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "get_integrations") {
        return [{ integrationType: "plausible" }];
      }
      return null;
    });

    const { rerender } = renderInline(
      <InlineIntegrationSetup
        serviceTypes={["plausible"]}
        projectId={42}
        url="https://example.com"
      />,
    );

    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith("get_integrations", { projectId: 42 });
    });
    expect(screen.queryByText("Plausible Analytics")).not.toBeInTheDocument();

    rerender(
      <InlineIntegrationSetup
        serviceTypes={["plausible"]}
        projectId={42}
        url="https://example.com"
        allowReconnect={["plausible"]}
      />,
    );

    await waitFor(() => {
      expect(screen.getByText("Plausible Analytics")).toBeInTheDocument();
    });
  });

  it("renders multiple API-key integrations as available without an upgrade gate", async () => {
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "get_integrations") {
        return [];
      }
      return null;
    });

    renderInline(
      <InlineIntegrationSetup
        serviceTypes={["plausible", "cloudflare"]}
        projectId={42}
        url="https://example.com"
      />,
    );

    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith("get_integrations", { projectId: 42 });
    });

    expect(screen.queryByText(/Upgrade to connect/i)).not.toBeInTheDocument();
    expect(await screen.findByText("Plausible Analytics")).toBeInTheDocument();
    expect(screen.getByText("Cloudflare")).toBeInTheDocument();
  });

  it("shows a combined picker when OAuth returns both GA4 and GSC choices", async () => {
    invokeMock.mockImplementation(async (command: string) => {
      switch (command) {
        case "get_integrations":
          return [];
        case "connect_google":
          return { flow_id: "inline-dual-flow" };
        case "complete_google_oauth":
          return {
            ga4_properties: [
              {
                property_id: "properties/222",
                display_name: "Analytics Prop",
                account_name: "Account",
              },
            ],
            gsc_sites: [{ site_url: "https://mysite.com/", permission: "siteOwner" }],
          };
        default:
          return null;
      }
    });

    renderInline(
      <InlineIntegrationSetup
        serviceTypes={["googleanalytics", "googlesearchconsole"]}
        projectId={42}
        url="https://mysite.com"
        includeGoogle={true}
      />,
    );

    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith("get_integrations", { projectId: 42 });
    });

    fireEvent.click(await screen.findByRole("button", { name: "Sign in with Google" }));

    // Picker modal should appear with both service dropdowns
    await waitFor(() => {
      expect(screen.getByRole("dialog")).toBeInTheDocument();
    });
    expect(screen.getByText("Choose what to connect")).toBeInTheDocument();
    expect(screen.getByLabelText("Google Analytics property")).toHaveValue("");
    expect(screen.getByLabelText("Search Console site")).toHaveValue("https://mysite.com/");

    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => {
      expect(
        invokeMock.mock.calls.filter(([command]) => command === "save_google_integration"),
      ).toEqual([
        [
          "save_google_integration",
          {
            projectId: 42,
            flowId: "inline-dual-flow",
            integrationType: "googlesearchconsole",
            siteId: "https://mysite.com/",
          },
        ],
      ]);
    });
  });

  it.each([
    {
      type: "googlesearchconsole",
      label: "Search Console site",
      otherLabel: "Google Analytics property",
      choice: "https://mysite.com/",
    },
    {
      type: "googleanalytics",
      label: "Google Analytics property",
      otherLabel: "Search Console site",
      choice: "properties/222",
    },
  ])("keeps $type setup scoped to the requested service", async (target) => {
    invokeMock.mockImplementation(async (command: string) => {
      switch (command) {
        case "get_integrations":
          return [];
        case "connect_google":
          return { flow_id: "targeted-flow" };
        case "complete_google_oauth":
          return {
            ga4_properties: [
              {
                property_id: "properties/222",
                display_name: "Unrelated site",
                account_name: "Account",
              },
            ],
            gsc_sites: [
              { site_url: "https://mysite.com/", permission: "siteOwner" },
              { site_url: "sc-domain:mysite.com", permission: "siteOwner" },
            ],
          };
        default:
          return null;
      }
    });

    renderInline(
      <InlineIntegrationSetup
        serviceTypes={[target.type]}
        projectId={42}
        url="https://mysite.com"
        includeGoogle
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Sign in with Google" }));
    const select = await screen.findByLabelText(target.label);
    expect(screen.queryByLabelText(target.otherLabel)).not.toBeInTheDocument();
    expect(select).toHaveValue("");
    // The picker opens its native dialog in an effect, after the select exists,
    // and getByRole skips a closed dialog's contents, so wait for the button.
    expect(await screen.findByRole("button", { name: "Connect" })).toBeDisabled();
    expect(invokeMock).not.toHaveBeenCalledWith("save_google_integration", expect.anything());

    fireEvent.change(select, { target: { value: target.choice } });
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => {
      expect(
        invokeMock.mock.calls.filter(([command]) => command === "save_google_integration"),
      ).toEqual([
        [
          "save_google_integration",
          {
            projectId: 42,
            flowId: "targeted-flow",
            integrationType: target.type,
            siteId: target.choice,
          },
        ],
      ]);
    });
  });

  it("does not offer Analytics when the requested Search Console account has no sites", async () => {
    invokeMock.mockImplementation(async (command: string) => {
      switch (command) {
        case "get_integrations":
          return [];
        case "connect_google":
          return { flow_id: "missing-gsc-flow" };
        case "complete_google_oauth":
          return {
            ga4_properties: [
              {
                property_id: "properties/222",
                display_name: "Unrelated site",
                account_name: "Account",
              },
            ],
            gsc_sites: [],
          };
        default:
          return null;
      }
    });

    renderInline(
      <InlineIntegrationSetup
        serviceTypes={["googlesearchconsole"]}
        projectId={42}
        url="https://mysite.com"
        includeGoogle
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Sign in with Google" }));
    expect(
      await screen.findByText("No Search Console sites found for this Google account."),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText("Google Analytics property")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Connect" })).not.toBeInTheDocument();
    expect(invokeMock).not.toHaveBeenCalledWith("save_google_integration", expect.anything());
  });

  it("auto-reconnects without a picker when the backend already re-saved the tokens", async () => {
    const onConnected = vi.fn();
    invokeMock.mockImplementation(async (command: string) => {
      switch (command) {
        case "get_integrations":
          // Search Console is already configured (an expired reconnect).
          return [{ integrationType: "googlesearchconsole", siteId: "https://mysite.com/" }];
        case "connect_google":
          return { flow_id: "inline-reconnect-flow" };
        case "complete_google_oauth":
          // Backend re-saved the configured service server-side (durable
          // reconnect), so the UI never needs the picker.
          return {
            ga4_properties: [],
            gsc_sites: [{ site_url: "https://mysite.com/", permission: "siteOwner" }],
            auto_saved: ["googlesearchconsole"],
          };
        default:
          return null;
      }
    });

    renderInline(
      <InlineIntegrationSetup
        serviceTypes={["googlesearchconsole"]}
        projectId={42}
        url="https://mysite.com"
        includeGoogle={true}
        allowReconnect={["googlesearchconsole"]}
        onConnected={onConnected}
      />,
    );

    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith("get_integrations", { projectId: 42 });
    });

    fireEvent.click(await screen.findByRole("button", { name: "Sign in with Google" }));

    await waitFor(() => {
      expect(onConnected).toHaveBeenCalledWith("googlesearchconsole");
    });
    // No picker dialog: the reconnect completed server-side.
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
