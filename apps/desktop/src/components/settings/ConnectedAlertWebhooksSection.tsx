import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/useToast";
import { copyToClipboard } from "@/lib/clipboard";
import {
  createConnectedAlertWebhook,
  deleteConnectedAlertWebhook,
  listConnectedAlertWebhooks,
  rotateConnectedAlertWebhook,
  testConnectedAlertWebhook,
} from "@/lib/commands";
import { queryKeys } from "@/lib/query/query-keys";
import { userFacingError } from "@/lib/user-facing-error";

interface ConnectedAlertWebhooksSectionProps {
  projectId: number;
  environmentScopeKey: string;
}

/** A shown-once signing secret, with the endpoint it belongs to and the
 *  rotation overlap deadline when a rotation produced it. */
interface RevealedSecret {
  webhookId: string;
  secret: string;
  rotationOverlapUntil: string | null;
}

/** Manage signed webhooks whose secrets appear only at creation or rotation. */
export function ConnectedAlertWebhooksSection({
  projectId,
  environmentScopeKey,
}: ConnectedAlertWebhooksSectionProps) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const queryKey = queryKeys.settings.connectedAlertWebhooks(projectId, environmentScopeKey);
  const scope = { environmentScopeKey, projectId };
  const webhooksQuery = useQuery({
    queryKey,
    queryFn: () => listConnectedAlertWebhooks(scope),
  });
  const [newUrl, setNewUrl] = useState("");
  const [creating, setCreating] = useState(false);
  const [revealed, setRevealed] = useState<RevealedSecret | null>(null);
  const [busyWebhook, setBusyWebhook] = useState<string | null>(null);

  const refresh = () => queryClient.invalidateQueries({ queryKey });

  const handleCreate = async () => {
    setCreating(true);
    try {
      const created = await createConnectedAlertWebhook({ ...scope, url: newUrl.trim() });
      setRevealed({
        rotationOverlapUntil: null,
        secret: created.secret,
        webhookId: created.webhookId,
      });
      setNewUrl("");
      await refresh();
      toast.success(
        "Webhook endpoint added",
        "Copy the signing secret now. It is not shown again.",
      );
    } catch (error) {
      toast.error(
        "Could not add the webhook endpoint",
        userFacingError(error, "Your change was not saved. Try again."),
      );
    } finally {
      setCreating(false);
    }
  };

  const handleTest = async (webhookId: string) => {
    setBusyWebhook(webhookId);
    try {
      await testConnectedAlertWebhook({ ...scope, webhookId });
      await refresh();
      toast.success(
        "Test delivery on its way",
        "The service signs and posts it shortly. A delivered test re-enables a disabled endpoint.",
      );
    } catch (error) {
      toast.error(
        "Could not send the test delivery",
        userFacingError(error, "Try again in a moment."),
      );
    } finally {
      setBusyWebhook(null);
    }
  };

  const handleRotate = async (webhookId: string) => {
    setBusyWebhook(webhookId);
    try {
      const rotated = await rotateConnectedAlertWebhook({ ...scope, webhookId });
      setRevealed({
        rotationOverlapUntil: rotated.rotationOverlapUntil,
        secret: rotated.secret,
        webhookId: rotated.webhookId,
      });
      await refresh();
      toast.success("Secret rotated", "Copy the new secret now. It is not shown again.");
    } catch (error) {
      toast.error(
        "Could not rotate the secret",
        userFacingError(error, "Your change was not saved. Try again."),
      );
    } finally {
      setBusyWebhook(null);
    }
  };

  const handleDelete = async (webhookId: string) => {
    setBusyWebhook(webhookId);
    try {
      await deleteConnectedAlertWebhook({ ...scope, webhookId });
      if (revealed?.webhookId === webhookId) setRevealed(null);
      await refresh();
      toast.success("Webhook endpoint deleted");
    } catch (error) {
      toast.error(
        "Could not delete the webhook endpoint",
        userFacingError(error, "Your change was not saved. Try again."),
      );
    } finally {
      setBusyWebhook(null);
    }
  };

  const webhooks = webhooksQuery.data ?? [];

  return (
    <section className="card card--spacious">
      <div className="settings-card-title-rule">
        <h2 className="settings-card-title">Alert Webhooks</h2>
      </div>
      <p className="body-muted">
        The machine channel. Every alert this site raises is posted to each endpoint as JSON with
        check ids, severities, and public routes, signed in the Standard Webhooks format with
        webhook-id, webhook-timestamp, and webhook-signature headers. Delivery ignores email muting:
        mute quiets your inbox, not your automation. An endpoint that keeps failing is disabled
        visibly here, and a successful test turns it back on.
      </p>
      {webhooksQuery.isError ? (
        <p className="agent-handoff-error" role="alert">
          Webhook endpoints could not load.
        </p>
      ) : null}
      {webhooks.length > 0 ? (
        <div className="webhook-list">
          {webhooks.map((webhook) => (
            <div key={webhook.webhookId} className="settings-webhook-row">
              <span
                className={
                  webhook.disabled ? "status-dot-info status-dot-dim" : "status-dot-success"
                }
              />
              <div className="flex-fill min-w-0">
                <div className="text-mono-sm text-truncate">{webhook.url}</div>
                <div className="text-13-muted">
                  {webhook.secretFingerprint}, generation {webhook.secretGeneration}
                  {webhook.disabled
                    ? webhook.disabledReason === "persistent_failure"
                      ? "; disabled after repeated failures - a successful test re-enables it"
                      : "; disabled"
                    : ""}
                  {webhook.rotationOverlapUntil
                    ? "; rotation overlap active, deliveries carry both signatures"
                    : ""}
                </div>
              </div>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => void handleTest(webhook.webhookId)}
                disabled={busyWebhook === webhook.webhookId}>
                Test
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => void handleRotate(webhook.webhookId)}
                disabled={busyWebhook === webhook.webhookId}>
                Rotate Secret
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => void handleDelete(webhook.webhookId)}
                disabled={busyWebhook === webhook.webhookId}>
                Remove
              </Button>
            </div>
          ))}
        </div>
      ) : webhooksQuery.isSuccess ? (
        <p className="body-muted">No webhook endpoints yet. Add the first one below.</p>
      ) : null}
      <div className="stack-base connected-form">
        <label className="form-label" htmlFor="connected-webhook-url">
          Endpoint URL (public HTTPS)
        </label>
        <Input
          id="connected-webhook-url"
          type="url"
          autoComplete="off"
          placeholder="https://hooks.example.com/sitecmd"
          value={newUrl}
          onChange={(event) => setNewUrl(event.target.value)}
        />
        <Button onClick={() => void handleCreate()} disabled={creating || !newUrl.trim()}>
          {creating ? "Adding..." : "Add Webhook Endpoint"}
        </Button>
      </div>
      {revealed ? (
        <div className="connected-payload-wrap">
          <div className="row-between">
            <p className="text-13-medium">Signing secret (copy this now)</p>
            <Button size="sm" variant="ghost" onClick={() => void copyToClipboard(revealed.secret)}>
              Copy Secret
            </Button>
          </div>
          <pre className="connected-payload">{revealed.secret}</pre>
          <p className="text-body-muted">
            {revealed.rotationOverlapUntil
              ? "Verify deliveries with this whsec_ secret and any Standard Webhooks library. For 24 hours webhook-signature carries the previous generation's signature too, so your receiver can switch without a gap."
              : "Verify deliveries with this whsec_ secret and any Standard Webhooks library, which checks the signature over the raw request body and refuses stale timestamps. SiteCMD stores only a fingerprint, so this is the one time it is readable."}
          </p>
        </div>
      ) : null}
    </section>
  );
}
