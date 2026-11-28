using namespace System.Security.Cryptography.X509Certificates

function Get-WindowsCertificateIdentity {
    param([Parameter(Mandatory)] [X509Certificate2] $Certificate)

    $ekus = @($Certificate.Extensions |
        Where-Object { $_ -is [X509EnhancedKeyUsageExtension] } |
        ForEach-Object { $_.EnhancedKeyUsages } |
        ForEach-Object { $_.Value })
    $publicTrustEku = "1.3.6.1.4.1.311.97.1.0"
    $profileEku = @($ekus | Where-Object {
        $_.StartsWith("1.3.6.1.4.1.311.97.", [StringComparison]::Ordinal) -and $_ -ne $publicTrustEku
    })
    if ($ekus -notcontains "1.3.6.1.5.5.7.3.3" -or $ekus -notcontains $publicTrustEku -or $profileEku.Count -ne 1) {
        throw "Expected the code signing and Artifact Signing Public Trust EKUs and exactly one profile EKU."
    }

    $subject = [Convert]::ToBase64String($Certificate.SubjectName.RawData)
    return "${subject}:$($profileEku[0])"
}

function Get-WindowsSignerIdentity {
    param([Parameter(Mandatory)] [string] $Path)

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne "Valid") {
        throw "Authenticode signature for '$Path' is $($signature.Status)."
    }
    if ($signature.SignatureType -ne "Authenticode") {
        throw "Expected an embedded Authenticode signature for '$Path'. Found $($signature.SignatureType)."
    }
    if (!$signature.SignerCertificate) {
        throw "No signer certificate found for '$Path'."
    }

    Get-WindowsCertificateIdentity -Certificate $signature.SignerCertificate
}
