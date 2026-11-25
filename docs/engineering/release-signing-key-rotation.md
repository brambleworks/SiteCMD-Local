# Updater Signing Key Incident Procedure

The public installer and setup action verify CLI archives with a checked-in
minisign public key. Use an independently authenticated channel to announce a
replacement key after suspected compromise.

## Suspected compromise

1. Freeze releases and disable the production updater manifest.
2. Remove the signing secret from the `release-updater-signing` GitHub
   environment. Preserve audit logs and record the time and suspected exposure.
3. Rotate any credentials that could have exposed the key, including release
   environment access and maintainer sessions.
4. Generate a new keypair offline on a clean machine:

   ```bash
   npm exec --prefix .github/updater-signer -- tauri signer generate \
     --write-keys ./sitecmd-signing-NEW \
     --password "<long-random-password>"
   ```

5. Store the new encrypted private key and password in the protected
   `release-updater-signing` environment. Update the public CLI installer and setup action trust roots in the same
   pull request.
6. Cut a release through the normal workflow. The release must pass the
   updater-key probe, secretless artifact verification, platform signing, and
   CLI signature verification before publication.
7. Publish a security notice and fresh installer through separately
   authenticated channels. Use the HTTPS download site, a signed source tag,
   and Apple or Windows platform signatures where available. Publish the new
   minisign key fingerprint through more than one channel for Linux users.

## Recovery verification

For every recovery release:

- Confirm the checked-in public key matches the new private key using the
  release workflow's `validate-updater-key` job.
- Verify CLI signatures in the secretless `verify-release` job.
- Install the fresh package on each supported platform and confirm its archive
  verifies against the replacement key.
- Confirm a package signed by the retired key is rejected.
- Confirm the public download page, release metadata, and published key
  fingerprint all name the same release.

## Key record

- `FF14638274D8CCED` is the current updater signing-key identifier.

Record every future key change here with the old and new key identifiers, the
first release carrying the new key, the reason for the change, and whether
existing installations require manual recovery.
