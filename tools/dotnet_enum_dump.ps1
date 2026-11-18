# M5 tool: .NET enum value extractor (protocol code tables live in managed enums)
# Usage: powershell -File dotnet_enum_dump.ps1 -Dll <path> [-Pattern 'Umas|Fonction']
#        -Dll may be a directory: all *.dll under it are scanned
param(
    [Parameter(Mandatory=$true)][string]$Dll,
    [string]$Pattern = 'Umas|Fonction|Function|Command|ServiceCode|OpCode'
)

if (Test-Path $Dll -PathType Container) {
    $files = Get-ChildItem -Path $Dll -Filter *.dll | Select-Object -ExpandProperty FullName
} else {
    $files = @($Dll)
}

# resolve deps from the dll's own directory (reflection-only needs this)
$dir = Split-Path $files[0]
$OnResolve = {
    param($s, $e)
    $n = (Split-Path $e.Name -Leaf) -replace ',.*$',''
    $p = Join-Path $dir "$n.dll"
    if (Test-Path $p) { return [Reflection.Assembly]::ReflectionOnlyLoadFrom($p) }
    return [Reflection.Assembly]::ReflectionOnlyLoad($e.Name)
}
[AppDomain]::CurrentDomain.add_ReflectionOnlyAssemblyResolve($OnResolve)

$found = 0
foreach ($f in $files) {
    try { $asm = [Reflection.Assembly]::ReflectionOnlyLoadFrom($f) } catch { continue }
    try { $types = $asm.GetTypes() } catch [Reflection.ReflectionTypeLoadException] { $types = $_.Exception.Types | Where-Object { $_ } }
    foreach ($t in $types) {
        if ($null -eq $t -or -not $t.IsEnum) { continue }
        if ($t.Name -notmatch $Pattern -and $t.FullName -notmatch $Pattern) { continue }
        $found++
        $fields = $t.GetFields([Reflection.BindingFlags]'Public,Static')
        Write-Output ("ENUM {0}  ({1})" -f $t.FullName, (Split-Path $f -Leaf))
        foreach ($fld in $fields) {
            $v = $fld.GetRawConstantValue()
            Write-Output ("  {0} = 0x{1:X}" -f $fld.Name, $v)
        }
        Write-Output ""
    }
}
Write-Output ("total enums matched: {0}" -f $found)
