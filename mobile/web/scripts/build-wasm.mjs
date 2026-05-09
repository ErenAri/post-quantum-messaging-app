import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const webDir = resolve(scriptDir, "..");
const repoRoot = resolve(webDir, "..", "..");
const coreDir = resolve(repoRoot, "crates", "pqmsg-core");
const sourcePkgDir = resolve(coreDir, "pkg");
const targetPkgDir = resolve(webDir, "pkg");

const build = spawnSync(
  "wasm-pack",
  [
    "build",
    "--no-opt",
    coreDir,
    "--target",
    "web",
    "--no-default-features",
    "--features",
    "wasm-pq",
  ],
  {
    cwd: webDir,
    shell: process.platform === "win32",
    stdio: "inherit",
  },
);

if (build.status !== 0) {
  process.exit(build.status ?? 1);
}

if (!existsSync(sourcePkgDir)) {
  console.error(`wasm-pack succeeded but '${sourcePkgDir}' was not created.`);
  process.exit(1);
}

rmSync(targetPkgDir, { force: true, recursive: true });
mkdirSync(webDir, { recursive: true });
cpSync(sourcePkgDir, targetPkgDir, { recursive: true });
