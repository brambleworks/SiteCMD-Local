# Entitlement threat model

The CLI in this repository is open source, so a check inside it cannot be a paid
boundary: anyone can build it without the check. The CLI does no local feature
gating, and paid entitlement is enforced server-side by the connected service.

## Subscription lapse

The [Terms of Service](https://sitecmd.com/terms) say cancellation takes effect
at the end of the free trial or the paid period and SiteCMD stops watching
your sites when the subscription ends.

The CLI runs Code Scan and local site checks through the embedded module
without checking subscription status. For public-site scans, it calls the
hosted scanner, where the service enforces entitlement.
