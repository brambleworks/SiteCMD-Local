using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "../../../.github/scripts/release/windows-signer-identity.ps1")

$now = [DateTimeOffset]::UtcNow
$codeSigning = "1.3.6.1.5.5.7.3.3"
$publicTrust = "1.3.6.1.4.1.311.97.1.0"
$profile = "1.3.6.1.4.1.311.97.100.200.300.400"
$otherProfile = "1.3.6.1.4.1.311.97.400.300.200.100"
$publicTrustProfile = @($codeSigning, $publicTrust, $profile)

function New-IssuingCertificate([string] $Subject) {
    $key = [RSA]::Create(2048)
    try {
        $request = [CertificateRequest]::new($Subject, $key, [HashAlgorithmName]::SHA256, [RSASignaturePadding]::Pkcs1)
        $request.CertificateExtensions.Add([X509BasicConstraintsExtension]::new($true, $false, 0, $true))
        $request.CreateSelfSigned($now.AddDays(-1), $now.AddDays(30))
    } finally {
        $key.Dispose()
    }
}

function New-LeafCertificate([string] $Subject, [X509Certificate2] $Issuer, [byte] $Serial, [string[]] $Ekus) {
    $usages = [OidCollection]::new()
    foreach ($eku in $Ekus) {
        [void] $usages.Add([Oid]::new($eku))
    }
    $request = [CertificateRequest]::new($Subject, $leafKey, [HashAlgorithmName]::SHA256, [RSASignaturePadding]::Pkcs1)
    $request.CertificateExtensions.Add([X509EnhancedKeyUsageExtension]::new($usages, $false))
    $request.Create($Issuer, $now, $now.AddDays(3), [byte[]] @($Serial))
}

function New-SignatureFixture($Certificate, [string] $Status = "Valid", [string] $SignatureType = "Authenticode") {
    [pscustomobject] @{
        SignerCertificate = $Certificate
        Status = $Status
        SignatureType = $SignatureType
    }
}

# Replace the Windows trust API so the same signer check can run on Linux.
function Get-AuthenticodeSignature([string] $LiteralPath) {
    if (!$signatures.ContainsKey($LiteralPath)) {
        throw "No signature fixture for '$LiteralPath'."
    }
    $signatures[$LiteralPath]
}

function Assert-SignerRejected([string] $Path, [string] $Reason) {
    try {
        $null = Get-WindowsSignerIdentity -Path $Path
    } catch {
        if (!$_.Exception.Message.Contains($Reason)) { throw }
        return
    }
    throw "Expected the signer check to reject '$Path'."
}

$issuer = New-IssuingCertificate "CN=Test Issuer"
$anotherIssuer = New-IssuingCertificate "CN=Replacement Issuer"
$leafKey = [RSA]::Create(2048)
$signatures = @{}
try {
    $signatures["probe.exe"] = New-SignatureFixture (New-LeafCertificate "CN=SiteCMD" $issuer 1 $publicTrustProfile)
    $signatures["renewed.exe"] = New-SignatureFixture (New-LeafCertificate "CN=SiteCMD" $anotherIssuer 2 $publicTrustProfile)
    $signatures["other-profile.exe"] = New-SignatureFixture (New-LeafCertificate "CN=SiteCMD" $issuer 3 @($codeSigning, $publicTrust, $otherProfile))
    $signatures["other-subject.exe"] = New-SignatureFixture (New-LeafCertificate "CN=Other Publisher" $issuer 4 $publicTrustProfile)
    $signatures["no-public-trust.exe"] = New-SignatureFixture (New-LeafCertificate "CN=SiteCMD" $issuer 5 @($codeSigning, $profile))
    $signatures["no-code-signing.exe"] = New-SignatureFixture (New-LeafCertificate "CN=SiteCMD" $issuer 6 @($publicTrust, $profile))
    $signatures["no-profile.exe"] = New-SignatureFixture (New-LeafCertificate "CN=SiteCMD" $issuer 7 @($codeSigning, $publicTrust))
    $signatures["two-profiles.exe"] = New-SignatureFixture (New-LeafCertificate "CN=SiteCMD" $issuer 8 ($publicTrustProfile + $otherProfile))

    $certificate = $signatures["probe.exe"].SignerCertificate
    $signatures["catalog.exe"] = New-SignatureFixture $certificate -SignatureType "Catalog"
    $signatures["untrusted.exe"] = New-SignatureFixture $certificate -Status "NotTrusted"
    $signatures["tampered.exe"] = New-SignatureFixture $certificate -Status "HashMismatch"
    $signatures["unsigned.exe"] = New-SignatureFixture $null -Status "NotSigned" -SignatureType "None"
    $signatures["no-signer.exe"] = New-SignatureFixture $null

    $expected = Get-WindowsSignerIdentity -Path "probe.exe"
    if ((Get-WindowsSignerIdentity -Path "renewed.exe") -cne $expected) {
        throw "Renewing the same profile under another issuing CA changed the signer identity."
    }
    if ((Get-WindowsSignerIdentity -Path "other-profile.exe") -ceq $expected) {
        throw "A different profile with the same subject and issuer matched the signer identity."
    }
    if ((Get-WindowsSignerIdentity -Path "other-subject.exe") -ceq $expected) {
        throw "A different subject with the same profile matched the signer identity."
    }

    foreach ($path in @("no-public-trust.exe", "no-code-signing.exe", "no-profile.exe", "two-profiles.exe")) {
        Assert-SignerRejected $path "Artifact Signing Public Trust"
    }
    Assert-SignerRejected "catalog.exe" "embedded Authenticode"
    Assert-SignerRejected "untrusted.exe" "NotTrusted"
    Assert-SignerRejected "tampered.exe" "HashMismatch"
    Assert-SignerRejected "unsigned.exe" "NotSigned"
    Assert-SignerRejected "no-signer.exe" "signer certificate"
} finally {
    foreach ($fixture in $signatures.Values) {
        if ($fixture.Status -eq "Valid" -and $fixture.SignatureType -eq "Authenticode" -and $fixture.SignerCertificate) {
            $fixture.SignerCertificate.Dispose()
        }
    }
    $leafKey.Dispose()
    $issuer.Dispose()
    $anotherIssuer.Dispose()
}
