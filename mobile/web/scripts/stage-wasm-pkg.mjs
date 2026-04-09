import { cpSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const webDir = resolve(scriptDir, "..");
const repoRoot = resolve(webDir, "..", "..");
const sourcePkgDir = resolve(repoRoot, "crates", "pqmsg-core", "pkg");
const publicPkgDir = resolve(webDir, "public", "pkg");

if (!existsSync(sourcePkgDir)) {
  console.error(
    `WASM package directory was not found at '${sourcePkgDir}'. Run 'npm run build:wasm' first.`
  );
  process.exit(1);
}

rmSync(publicPkgDir, { force: true, recursive: true });
mkdirSync(resolve(webDir, "public"), { recursive: true });
cpSync(sourcePkgDir, publicPkgDir, { recursive: true });

console.log(`Staged WASM package into ${publicPkgDir}`);
