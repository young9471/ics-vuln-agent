"""Locate the optional offline analyzer bundle and build its subprocess env."""
import os
import shutil
from pathlib import Path


def find_bundle():
    env = os.environ.get("PROTOCOL_AGENT_ANALYZER_BUNDLE", "").strip()
    if env and (Path(env) / "ilspycmd" / "ilspycmd.exe").exists():
        return Path(env)
    here = Path(__file__).resolve().parent
    candidates = [
        here.parent / "offline" / "analyzers-win-x64",
        here.parent.parent / "offline" / "analyzers-win-x64",
        here / ".." / "offline" / "analyzers-win-x64",
    ]
    for c in candidates:
        if (c / "ilspycmd" / "ilspycmd.exe").exists() or (c / "dotnet" / "dotnet.exe").exists():
            return c.resolve()
    return None


def analyzer_env(base=None):
    env = dict(os.environ)
    bundle = find_bundle()
    if not bundle:
        return env
    env["PROTOCOL_AGENT_ANALYZER_BUNDLE"] = str(bundle)
    jdk = bundle / "jdk"
    if (jdk / "bin" / "java.exe").exists():
        env["JAVA_HOME"] = str(jdk)
    dotnet = bundle / "dotnet"
    if (dotnet / "dotnet.exe").exists():
        env["DOTNET_ROOT"] = str(dotnet)
    ghidra = bundle / "ghidra"
    ghidra_support = ""
    for d in ghidra.glob("ghidra_*"):
        if (d / "support" / "analyzeHeadless.bat").exists():
            env["GHIDRA_HOME"] = str(d)
            ghidra_support = str(d / "support")
            break
    parts = [
        str(jdk / "bin") if (jdk / "bin").exists() else "",
        ghidra_support,
        str(dotnet) if (dotnet / "dotnet.exe").exists() else "",
        str(bundle / "ilspycmd") if (bundle / "ilspycmd").exists() else "",
    ]
    env["PATH"] = ";".join([p for p in parts if p] + [env.get("PATH", "")])
    return env


def find_ilspy():
    if shutil.which("ilspycmd"):
        return shutil.which("ilspycmd")
    bundle = find_bundle()
    if bundle:
        p = bundle / "ilspycmd" / "ilspycmd.exe"
        if p.exists():
            return str(p)
    return None


def find_ghidra():
    if shutil.which("analyzeHeadless"):
        return shutil.which("analyzeHeadless")
    env_home = os.environ.get("GHIDRA_HOME", "").strip()
    if env_home:
        for n in ("analyzeHeadless.bat", "analyzeHeadless"):
            p = Path(env_home) / "support" / n
            if p.exists():
                return str(p)
    bundle = find_bundle()
    if bundle:
        for d in (bundle / "ghidra").glob("ghidra_*"):
            p = d / "support" / "analyzeHeadless.bat"
            if p.exists():
                return str(p)
    return None
