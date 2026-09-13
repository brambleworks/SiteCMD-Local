import { beforeEach, describe, expect, it, vi } from "vitest";
import { sendTelemetryRequest } from "@/lib/commands";
import { tauriTelemetryTransport } from "./telemetry-transport";

vi.mock("@/lib/commands", () => ({
  sendTelemetryRequest: vi.fn(),
}));

const sendTelemetryRequestMock = vi.mocked(sendTelemetryRequest);

describe("telemetry transport", () => {
  beforeEach(() => {
    sendTelemetryRequestMock.mockReset();
    sendTelemetryRequestMock.mockResolvedValue({
      status: 201,
      body: '{"ok":true}',
      headers: { "content-type": "application/json" },
    });
  });

  it("maps usage delivery to a typed operation without forwarding the endpoint", async () => {
    const response = await tauriTelemetryTransport(
      "https://telemetry.sitecmd.com/v1/events",
      '{"events":[]}',
      { headers: { Authorization: "Bearer test-token" } },
    );

    expect(sendTelemetryRequestMock).toHaveBeenCalledWith({
      args: {
        kind: "usageEvents",
        body: { events: [] },
        authorization: "Bearer test-token",
      },
    });
    expect(JSON.stringify(sendTelemetryRequestMock.mock.calls[0]?.[0])).not.toContain(
      "telemetry.sitecmd.com",
    );
    expect(response.status).toBe(201);
    await expect(response.json()).resolves.toEqual({ ok: true });
  });

  it("maps registration and deletion to their closed request variants", async () => {
    await tauriTelemetryTransport(
      "https://telemetry.sitecmd.com/v1/register",
      '{"subjectId":"scmd_12345678","deleteProofHash":"hash"}',
    );
    await tauriTelemetryTransport(
      "https://telemetry.sitecmd.com/v1/delete",
      '{"subjectId":"scmd_12345678"}',
    );

    expect(sendTelemetryRequestMock.mock.calls.map(([request]) => request.args.kind)).toEqual([
      "usageRegister",
      "usageDelete",
    ]);
  });

  it("rejects renderer-selected hosts, paths, and missing event authorization", async () => {
    await expect(
      tauriTelemetryTransport("https://example.com/v1/events", '{"events":[]}'),
    ).rejects.toThrow("not allowed");
    await expect(
      tauriTelemetryTransport("https://telemetry.sitecmd.com/v1/other", "{}"),
    ).rejects.toThrow("not allowed");
    await expect(
      tauriTelemetryTransport("https://telemetry.sitecmd.com/v1/events", '{"events":[]}'),
    ).rejects.toThrow("authorization is required");
    expect(sendTelemetryRequestMock).not.toHaveBeenCalled();
  });
});
