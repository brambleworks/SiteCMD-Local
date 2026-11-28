# Windows CLI Signing with Azure Artifact Signing

The Windows leg of `build` compiles `sitecmd.exe`, runs `--version` without
signing credentials, and uploads `built-cli-windows-x86_64` with the legal files.
The Windows leg of `sign-platforms` waits for maintainer approval in the
`release-signing` environment and runs on a separate runner. It checks the
digest GitHub recorded at upload before signing the downloaded executable. [Release workflow](../../.github/workflows/release.yml)

## Set up Azure Artifact Signing

1. Register the `Microsoft.CodeSigning` resource provider, create an Artifact
   Signing account in a supported Azure region, and complete public identity
   validation in the Azure portal. Create a **Public Trust** certificate
   profile. Record the account name, profile name, and regional endpoint.
   [Azure Artifact Signing quickstart](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart)
2. Register a Microsoft Entra application for release signing. Record its
   tenant ID and application ID. In **Certificates & secrets > Client secrets**,
   create a client secret and record its value when Entra displays it.
   [Microsoft Entra app credentials](https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials)
3. Assign the application's service principal the **Artifact Signing
   Certificate Profile Signer** role on the certificate profile.
   [Azure Artifact Signing roles](https://learn.microsoft.com/en-us/azure/artifact-signing/tutorial-assign-roles)

## Configure GitHub

In the repository, go to **Settings > Environments > release-signing** and add
these environment secrets and variables.

| Name                  | Kind     | Value                                                          |
| --------------------- | -------- | -------------------------------------------------------------- |
| `AZURE_TENANT_ID`     | Secret   | Directory (tenant) ID                                          |
| `AZURE_CLIENT_ID`     | Secret   | Application (client) ID                                        |
| `AZURE_CLIENT_SECRET` | Secret   | Entra client secret value                                      |
| `AZURE_SIGN_ENDPOINT` | Variable | Regional endpoint, such as `https://eus.codesigning.azure.net` |
| `AZURE_SIGN_ACCOUNT`  | Variable | Artifact Signing account name                                  |
| `AZURE_SIGN_PROFILE`  | Variable | Public Trust certificate profile name                          |

## Sign in CI

The Windows signing runner checks the environment configuration and installs
the pinned version of [`artifact-signing-cli`]. **Verify Azure signing** signs
a temporary copy of the downloaded unsigned `sitecmd.exe` to check the Entra
credential and Public Trust certificate profile. It requires a valid embedded
Authenticode signature and records the signer subject and the profile's
durable Extended Key Usage (EKU).
[Azure certificate profile EKU](https://learn.microsoft.com/en-us/azure/artifact-signing/concept-certificate-management#certificate-profile-eku)

The signing script Authenticode-signs the downloaded `sitecmd.exe` with the same
Azure profile. It packages the executable and its legal files as
`sitecmd-cli_<version>_windows-x86_64.zip` without running the binary.
[Signing script](../../.github/scripts/release/sign-cli.sh)

## Verify the release

Extract `sitecmd.exe` from the release ZIP and inspect its Authenticode
signature on Windows.

```powershell
Get-AuthenticodeSignature .\sitecmd.exe | Format-List
```

Expect `Status` to be `Valid` and `SignatureType` to be `Authenticode`. The
verifier requires the code signing EKU, the Public Trust marker, and exactly
one Azure profile EKU. It matches the signer subject and profile EKU to the
probe before running `sitecmd --version`. Azure keeps the profile EKU stable
for the life of the profile, including when certificates renew under a
different issuing CA.
[Azure certificate profile EKU](https://learn.microsoft.com/en-us/azure/artifact-signing/concept-certificate-management#certificate-profile-eku)

## Troubleshoot and rotate credentials

- Read **Verify Azure signing** in the Windows `sign-platforms` job for Azure
  diagnostics. Check the client secret expiration, the service principal's
  role on the certificate profile, and that the profile is active and belongs
  to the configured account and region.
- Azure renews the signing certificate daily, so the owner rotates only the
  client secret. Before it expires, create a replacement in the same Entra
  application and update `AZURE_CLIENT_SECRET` in `release-signing`. The signing
  tool runs only on Windows. Use **Verify Azure signing** on the next release to
  check the new secret, and keep the old secret valid until that step passes.
  [Azure certificate management](https://learn.microsoft.com/en-us/azure/artifact-signing/concept-certificate-management)
- Re-run a failed signing job while its build artifact is available if the fix
  is in the Azure account or a secret. If the signing script or binary needs a
  fix, release a new version with a new tag. The job checks out the tagged
  commit. See the [release runbook](../operations/releasing.md) for approval
  and artifact retention deadlines.

[`artifact-signing-cli`]: https://crates.io/crates/artifact-signing-cli
