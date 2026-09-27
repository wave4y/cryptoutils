param([string]$Source)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Source)) {
 $goCommand = Get-Command go -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
 if ($null -eq $goCommand) {
  throw 'Go was not found. Install Go or pass -Source <path-to-circl-v1.6.3> to use an existing source directory.'
 }
 $moduleCacheOutput = & $goCommand.Source env GOMODCACHE
 if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($moduleCacheOutput -join ''))) {
  throw 'Unable to read GOMODCACHE with go env. Pass -Source <path-to-circl-v1.6.3> explicitly.'
 }
 $moduleCachePath = ($moduleCacheOutput -join '').Trim()
 $Source = Join-Path $moduleCachePath 'github.com/cloudflare/circl@v1.6.3'
}
if (-not (Test-Path -LiteralPath $Source -PathType Container)) {
 throw "CIRCL v1.6.3 source directory does not exist: $Source. Pass -Source <path-to-circl-v1.6.3>. This script does not download source files."
}
$Source = (Resolve-Path -LiteralPath $Source).ProviderPath

# Validate the complete input set before replacing any checked-in fixture.
$requiredInputs = @(
 'kem/mlkem/testdata/ML-KEM-keyGen-FIPS203/prompt.json.gz'
 'kem/mlkem/testdata/ML-KEM-keyGen-FIPS203/expectedResults.json.gz'
 'kem/mlkem/testdata/ML-KEM-encapDecap-FIPS203/prompt.json.gz'
 'kem/mlkem/testdata/ML-KEM-encapDecap-FIPS203/expectedResults.json.gz'
 'sign/mldsa/testdata/ML-DSA-keyGen-FIPS204/prompt.json.gz'
 'sign/mldsa/testdata/ML-DSA-keyGen-FIPS204/expectedResults.json.gz'
 'sign/mldsa/testdata/ML-DSA-sigGen-FIPS204/prompt.json.gz'
 'sign/mldsa/testdata/ML-DSA-sigGen-FIPS204/expectedResults.json.gz'
 'sign/mldsa/testdata/ML-DSA-sigVer-FIPS204/prompt.json.gz'
 'sign/mldsa/testdata/ML-DSA-sigVer-FIPS204/expectedResults.json.gz'
 'sign/slhdsa/testdata/keyGen_prompt.json.gz'
 'sign/slhdsa/testdata/keyGen_results.json.gz'
 'sign/slhdsa/testdata/sigGen_prompt.json.gz'
 'sign/slhdsa/testdata/sigGen_results.json.gz'
 'sign/slhdsa/testdata/verify_prompt.json.gz'
 'sign/slhdsa/testdata/verify_results.json.gz'
)
foreach ($relativePath in $requiredInputs) {
 $inputPath = Join-Path $Source $relativePath
 if (-not (Test-Path -LiteralPath $inputPath -PathType Leaf)) {
  throw "Required CIRCL v1.6.3 test data is missing: $inputPath. Pass -Source to a complete source directory. No fixture has been changed."
 }
}
# Extract a small reproducible selection of upstream NIST ACVP cases, preserving
# tcId/tgId and exact hexadecimal values. No expected values are generated locally.
function Read-GzipJson([string]$path) {
 $file=[IO.File]::OpenRead($path)
 try {$gzip=[IO.Compression.GZipStream]::new($file,[IO.Compression.CompressionMode]::Decompress); $reader=[IO.StreamReader]::new($gzip); try {return ($reader.ReadToEnd() | ConvertFrom-Json -Depth 100)} finally {$reader.Dispose()}} finally {$file.Dispose()}
}
function Write-GzipJson([string]$name,$cases) {
 $bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject @($cases) -Depth 100 -Compress))
 $file=[IO.File]::Create((Join-Path $PSScriptRoot $name))
 try {$gzip=[IO.Compression.GZipStream]::new($file,[IO.Compression.CompressionLevel]::Optimal); try {$gzip.Write($bytes,0,$bytes.Length)} finally {$gzip.Dispose()}} finally {$file.Dispose()}
}
foreach($family in @('ML-KEM','ML-DSA','SLH-DSA')) {
 $cases=[System.Collections.Generic.List[object]]::new()
 $operations=if($family -eq 'ML-KEM'){@('keyGen','encapDecap')}else{@('keyGen','sigGen','sigVer')}
 foreach($op in $operations) {
  if($family -eq 'SLH-DSA') {
   $stem=if($op -eq 'sigVer'){'verify'}else{$op}
   $prompt=Read-GzipJson (Join-Path $Source "sign/slhdsa/testdata/${stem}_prompt.json.gz")
   $results=Read-GzipJson (Join-Path $Source "sign/slhdsa/testdata/${stem}_results.json.gz")
  } else {
   $base=if($family -eq 'ML-KEM'){'kem/mlkem/testdata'}else{'sign/mldsa/testdata'}
   $fips=if($family -eq 'ML-KEM'){'203'}else{'204'}
   $prompt=Read-GzipJson (Join-Path $Source "$base/$family-$op-FIPS$fips/prompt.json.gz")
   $results=Read-GzipJson (Join-Path $Source "$base/$family-$op-FIPS$fips/expectedResults.json.gz")
  }
  $byID=@{}
  foreach($group in $results.testGroups){foreach($case in $group.tests){$byID[[int]$case.tcId]=$case}}
  foreach($group in $prompt.testGroups) {
   if($family -eq 'SLH-DSA' -and $op -ne 'keyGen') {
    if($group.signatureInterface -ne 'external' -or $group.preHash -ne 'pure'){continue}
    if($op -eq 'sigGen' -and -not $group.deterministic){continue}
   }
   $selected=@($group.tests | Select-Object -First 1)
   if($op -eq 'sigVer') {
    $selected=@($group.tests | Where-Object {$byID[[int]$_.tcId].testPassed} | Select-Object -First 1)
    $selected+=@($group.tests | Where-Object {-not $byID[[int]$_.tcId].testPassed} | Select-Object -First 1)
   }
   foreach($case in $selected) {
    if($null -eq $case){continue}
    $record=[ordered]@{operation=$op;parameter=$group.parameterSet;tgId=$group.tgId;testType=$group.testType;input=$case;output=$byID[[int]$case.tcId]}
    foreach($prop in @('deterministic','pk','dk','signatureInterface','preHash')){if($group.PSObject.Properties.Name -contains $prop){$record[$prop]=$group.$prop}}
    $cases.Add($record)
   }
  }
 }
 Write-GzipJson "$family.json.gz" $cases
 Write-Output "$family cases=$($cases.Count)"
}
