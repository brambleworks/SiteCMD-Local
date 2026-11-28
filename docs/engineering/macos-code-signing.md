# macOS CLI Signing and Notarization

The macOS leg of `build` compiles `sitecmd` for Apple silicon and Intel, combines
the binaries, runs `--version` without signing credentials, and uploads
`built-cli-darwin-universal` with the legal files. The macOS leg of
`sign-platforms` waits for maintainer approval in the `release-signing` environment
and runs on a separate runner. It checks the digest GitHub recorded at upload
before signing the downloaded binary. [Release workflow](../../.github/workflows/release.yml)

## Prepare the Apple credentials

1. Generate a private key and a certificate signing request on a Mac you
   control. Run these commands with OpenSSL 3 in a private directory.

   ```bash
   umask 077
   openssl req -new -newkey rsa:2048 -keyout developer-id.key \
     -out developer-id.certSigningRequest
   ```

2. As the Apple Developer Account Holder, request a **Developer ID Application**
   certificate under **Certificates, Identifiers & Profiles**. Choose the G2
   intermediate if prompted, upload the request, and download the certificate
   as `developer-id.cer`. [Apple Developer ID certificates](https://developer.apple.com/help/account/certificates/create-developer-id-certificates)
3. Download the **Developer ID G2** intermediate as `developer-id-g2.cer`.
   Convert both certificates to PEM and export the signing identity as a
   password-protected PKCS#12 file that the runner can import. [Apple certificate authority](https://www.apple.com/certificateauthority/)

   ```bash
   openssl x509 -inform DER -in developer-id.cer -out developer-id.pem
   openssl x509 -inform DER -in developer-id-g2.cer -out developer-id-g2.pem
   openssl pkcs12 -export -legacy -inkey developer-id.key -in developer-id.pem \
     -certfile developer-id-g2.pem -out developer-id.p12
   ```

4. In App Store Connect, go to **Users and Access > Integrations > App Store
   Connect API > Team Keys** and look up the role of the key currently used for
   releases. As the Account Holder or an Admin, create a Team key with the same
   role. Record the issuer ID and key ID, and download the `.p8` file. Apple
   offers the private key download once.
   [App Store Connect API keys](https://developer.apple.com/documentation/AppStoreConnectAPI/creating-api-keys-for-app-store-connect-api)

Keep private keys and backups in encrypted, access-controlled storage. In
GitHub, go to **Settings > Environments > release-signing** and add these
environment secrets. Encode the `.p12` and `.p8` files as base64 on one line.

| Secret                       | Value                                                                                     |
| ---------------------------- | ----------------------------------------------------------------------------------------- |
| `APPLE_CERTIFICATE`          | Base64 of `developer-id.p12`                                                              |
| `APPLE_CERTIFICATE_PASSWORD` | PKCS#12 export password                                                                   |
| `APPLE_SIGNING_IDENTITY`     | Full signing identity, in the form `Developer ID Application: <organization> (<team ID>)` |
| `APPLE_TEAM_ID`              | Apple Developer team ID from that identity                                                |
| `KEYCHAIN_PASSWORD`          | Password for the runner's temporary signing keychain                                      |
| `APPLE_API_ISSUER`           | App Store Connect team API issuer ID                                                      |
| `APPLE_API_KEY_ID`           | App Store Connect team API key ID                                                         |
| `APPLE_API_KEY_P8`           | Base64 of the downloaded App Store Connect private key                                    |

## Sign and notarize in CI

**Verify Apple notarization credentials** runs `xcrun notarytool history` with
the team API key. The signing script then imports the Developer ID identity
into a temporary keychain, signs the downloaded `sitecmd` with hardened runtime
and a secure timestamp, and checks its team ID.

The script submits a ZIP containing that signed binary to Apple with
`xcrun notarytool submit --wait`. Once Apple returns `Accepted`, the job
packages the same executable as `sitecmd-cli_<version>_darwin-universal.tar.gz`
with its legal files. The signing runner never executes the downloaded binary.
[Signing script](../../.github/scripts/release/sign-cli.sh)

## Verify the release

On macOS, extract `sitecmd` from the release archive and run the signature
and online notarization checks. The released executable uses Apple's online
notarization ticket.

```bash
codesign --verify --strict ./sitecmd --all-architectures
codesign -vvvv -R="notarized" --check-notarization ./sitecmd
codesign -dv --verbose=4 ./sitecmd
```

Check that `TeamIdentifier` matches `APPLE_TEAM_ID`. The release verifier also
runs `sitecmd --version` and checks the result against the release version.

## Troubleshoot and rotate credentials

- If the notarization probe returns `403` with a missing or expired agreement,
  have the Account Holder accept the pending agreement in the Apple Developer
  account or App Store Connect. For other authentication failures, check that
  the issuer ID, key ID, and private key belong to the same active team key.
- For a rejected submission, download the `cli-notarization-darwin-universal`
  artifact and inspect `submission.json`, `submission-id.txt`, and
  `notary-log.json` when present. GitHub Actions keeps these notarization logs
  for 14 days.
- Re-run the failed signing job while its build artifact is available if the
  fix is in the Apple account or a secret. If the signing script or binary
  needs a fix, release a new version with a new tag. The job checks out the
  tagged commit.
- Before the Developer ID certificate expires, create a replacement identity
  and update `APPLE_CERTIFICATE` and `APPLE_CERTIFICATE_PASSWORD` together.
  Update `APPLE_SIGNING_IDENTITY` and `APPLE_TEAM_ID` if the replacement
  changes those values. Let the old certificate expire. The timestamped
  `sitecmd` binaries already signed with it keep working after expiration.
  Revoke the certificate only if its private key leaks. Revocation prevents
  every shipped `sitecmd` signed with that certificate from launching.
  Check the certificate's expiration date with OpenSSL.
  [Apple Developer ID certificates](https://developer.apple.com/help/account/certificates/create-developer-id-certificates)

  ```bash
  openssl x509 -in developer-id.pem -noout -enddate
  ```

- To rotate the App Store Connect key, create a replacement Team key with the
  same role. On macOS, check the new private key and its IDs with
  `notarytool` before updating GitHub.

  ```bash
  xcrun notarytool history --key AuthKey_KEY_ID.p8 \
    --key-id KEY_ID --issuer ISSUER_ID
  ```

  After the check succeeds, update `APPLE_API_KEY_ID` and `APPLE_API_KEY_P8`
  together. Update `APPLE_API_ISSUER` if the issuer changes, then revoke the
  old App Store Connect key.

See the [release runbook](../operations/releasing.md) for approval and artifact
retention deadlines.
