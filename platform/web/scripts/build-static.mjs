import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// Cross-platform replacement for `NEXT_EXPORT=1 next build`: the Unix env-var
// prefix does not work when npm runs scripts through cmd.exe on Windows.
const nextBin = fileURLToPath(new URL("../node_modules/next/dist/bin/next", import.meta.url));
const result = spawnSync(process.execPath, [nextBin, "build"], {
  stdio: "inherit",
  env: { ...process.env, NEXT_EXPORT: "1" },
});
process.exit(result.status ?? 1);