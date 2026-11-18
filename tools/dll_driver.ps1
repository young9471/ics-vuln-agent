# P5-L4 ground-truth harness: drive the VENDOR's own communication DLL and
# capture what it actually puts on the wire (PLAYBOOK P5-L4).
#
# MUST run under 32-bit PowerShell for a 32-bit DLL:
#   C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -File dll_driver.ps1
#
# Three pitfalls pre-solved (PLAYBOOK pitfall #5):
#   [1] WSAStartup before any WinSock use by the vendor lib
#   [2] object buffers ZEROED before running constructors
#   [3] bitness: SysWOW64 host for 32-bit DLLs (and vice versa)
#
# Adapt the four TODO sections to the target case. The WAGO WBCComm.dll
# sequence is left in as a working reference (golden case).
$ErrorActionPreference = 'Stop'

# ---- TODO(1): vendor DLL path (use FORWARD slashes to survive C# strings)
$dllPath = 'E:/Codesys V2.3/CODESYS V2.3/Targets/WAGO/PLCconf/PFC200/RS/WBCComm.dll'

# ---- TODO(2): P/Invoke declarations ( EntryPoint = exact mangled export names;
#      use `dumpbin /exports` or pefile to get them; ThisCall for MSVC members )
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class V {
  [DllImport("ws2_32.dll")]
  public static extern int WSAStartup(ushort v, byte[] data);                    // pitfall [1]
  [DllImport("$dllPath", EntryPoint="??0CTCPIPConnection@WAGO@@QAE@XZ", CallingConvention=CallingConvention.ThisCall)]
  public static extern void ConnCtor(IntPtr self);
  [DllImport("$dllPath", EntryPoint="??0CTCPIPService@@QAE@PAVIConnection@WAGO@@@Z", CallingConvention=CallingConvention.ThisCall)]
  public static extern void SvcCtor(IntPtr self, IntPtr conn);
  [DllImport("$dllPath", EntryPoint="??0CServiceAPI@WAGO@@QAE@PAVIProtocol@1@@Z", CallingConvention=CallingConvention.ThisCall)]
  public static extern void ApiCtor(IntPtr self, IntPtr proto);
  [DllImport("$dllPath", EntryPoint="?Open@CTCPIPConnection@WAGO@@UAEXXZ", CallingConvention=CallingConvention.ThisCall)]
  public static extern void ConnOpen(IntPtr self);
  [DllImport("$dllPath", EntryPoint="?IdentifyDevice@CServiceAPI@WAGO@@QAE_NAAG00PAPAD@Z", CallingConvention=CallingConvention.ThisCall)]
  [return: MarshalAs(UnmanagedType.U1)]
  public static extern bool IdentifyDevice(IntPtr self, out ushort a, out ushort b, out ushort c, out IntPtr d);
}
"@

$M = [System.Runtime.InteropServices.Marshal]
$wsa = New-Object byte[] 400
"WSAStartup rc=" + [V]::WSAStartup(0x0202, $wsa)                                  # pitfall [1]

# ---- TODO(3): object graph (sizes generous; ZEROED before ctors - pitfall [2])
$zero = New-Object byte[] 0x400
$conn = $M::AllocHGlobal(0x400); $svc = $M::AllocHGlobal(0x400); $api = $M::AllocHGlobal(0x200)
foreach ($p in @($conn, $svc, $api)) { $M::Copy($zero, 0, $p, 0x200) }            # pitfall [2]

[V]::ConnCtor($conn)
# host std::string (MSVC SSO: buf@+0x68, size@+0x78) - offsets from ctor disasm
$ip = [System.Text.Encoding]::ASCII.GetBytes("192.168.1.20")                      # ---- TODO(4): target
$M::Copy($ip, 0, [IntPtr]::Add($conn, 0x68), $ip.Length)
$M::WriteInt32($conn, 0x78, $ip.Length)
[V]::SvcCtor($svc, $conn)
[V]::ApiCtor($api, $svc)
[V]::ConnOpen($conn)
"open ok"

# start tshark FIRST in real use; here the frames are small enough to log after
$a = [uint16]0; $b = [uint16]0; $c = [uint16]0; $d = [IntPtr]::Zero
try {
  $ok = [V]::IdentifyDevice($api, [ref]$a, [ref]$b, [ref]$c, [ref]$d)
  "IdentifyDevice ok=$ok a=$a b=$b c=$c"
  if ($d -ne [IntPtr]::Zero) { "blob: " + $M::PtrToStringAnsi($d) }
} catch {
  "native exception: $_  (inspect API+0x40 lasterr; see PLAYBOOK pitfall #5)"
}
