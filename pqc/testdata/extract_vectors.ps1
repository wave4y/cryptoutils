param([string]$Source = 'C:\Users\1\go\pkg\mod\github.com\cloudflare\circl@v1.6.3')
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
