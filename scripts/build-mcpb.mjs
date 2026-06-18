// Build the Sequesign MCP server as an .mcpb Desktop Extension bundle.
//
// An .mcpb is a zip of { manifest.json, server/index.js, + any runtime assets }
// that Claude Desktop installs in one click and configures via the manifest's
// user_config form. To keep the artifact self-contained (no node_modules), we
// bundle the server and all its deps into a single ESM file with esbuild.
//
// The one wrinkle: @sequesign/sdk loads its registry/schemas/profiles from disk
// at runtime, resolving them relative to the nearest package.json above the
// running module (see sequesign-sdk/dist/lib/paths.js). After bundling, that
// "nearest package.json" is the one we drop next to the bundle, so we copy the
// SDK's registry/, schemas/, and profiles/ into server/ alongside it. Then
// PROJECT_ROOT === server/ and resolveAsset("schemas/...") finds the data.
//
// This script runs in two layouts:
//   - standalone `Sequesign/mcp` (the publish repo): this package IS the repo
//     root and `@sequesign/sdk` is an installed npm dep that ships its
//     registry/schemas/profiles via the package "files" list;
//   - the monorepo (`packages/sequesign-mcp`): `@sequesign/sdk` resolves through
//     the workspace symlink to `packages/sequesign-sdk`.
// We resolve the SDK package directory the same way in both (createRequire on
// `@sequesign/sdk/package.json`) and copy the assets from there. The only
// monorepo-specific branch is building the SDK if its dist is missing — a
// published/installed SDK always ships dist, so that never fires standalone.
//
// Output: <pkg>/mcpb-dist/  (the packable directory)
// Then:   npx @anthropic-ai/mcpb pack mcpb-dist  → sequesign.mcpb
// (this script runs pack automatically when the CLI is reachable).

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { cp, mkdir, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

import esbuild from "esbuild";

const require = createRequire(import.meta.url);
const PKG_DIR = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

// Resolve the installed @sequesign/sdk package root. Works in both layouts: the
// standalone repo resolves to node_modules/@sequesign/sdk; the monorepo follows
// the workspace symlink to packages/sequesign-sdk. The SDK ships dist/ plus
// registry/schemas/profiles in its "files", so this directory has everything
// the bundle needs.
const SDK_DIR = path.dirname(require.resolve("@sequesign/sdk/package.json"));
const SDK_DIST = path.join(SDK_DIR, "dist", "sdk", "index.js");

// We are in the monorepo iff this package sits at <root>/packages/sequesign-mcp
// next to a workspace root package.json. Only then can we build the SDK from
// source; standalone, the SDK is a prebuilt npm dependency.
const MONOREPO_ROOT = path.resolve(PKG_DIR, "..", "..");
const IS_MONOREPO =
  path.basename(path.dirname(PKG_DIR)) === "packages" &&
  existsSync(path.join(MONOREPO_ROOT, "package.json"));

const OUT_DIR = path.join(PKG_DIR, "mcpb-dist");
const SERVER_DIR = path.join(OUT_DIR, "server");

function run(cmd, args, opts = {}) {
  execFileSync(cmd, args, { cwd: PKG_DIR, stdio: "inherit", ...opts });
}

async function main() {
  // The bundle pulls @sequesign/sdk from its built dist (resolved by the
  // package's exports), so make sure it exists. A published/installed SDK
  // always ships dist; only an unbuilt monorepo checkout needs a build.
  if (!existsSync(SDK_DIST)) {
    if (IS_MONOREPO) {
      console.log("• building @sequesign/sdk (dist missing)…");
      run("npm", ["run", "build", "-w", "@sequesign/sdk"], { cwd: MONOREPO_ROOT });
    } else {
      throw new Error(
        `@sequesign/sdk build not found at ${SDK_DIST}.\n` +
          "  Run `npm ci` (or `npm install`) first so the published SDK — which ships\n" +
          "  its own dist/ and registry/schemas/profiles — is installed."
      );
    }
  }

  console.log("• cleaning", path.relative(PKG_DIR, OUT_DIR));
  await rm(OUT_DIR, { recursive: true, force: true });
  await mkdir(SERVER_DIR, { recursive: true });

  console.log("• bundling server with esbuild…");
  await esbuild.build({
    entryPoints: [path.join(PKG_DIR, "src", "index.ts")],
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node22",
    // Bundle every dependency (SDK, MCP SDK, zod, transitives) so the .mcpb
    // needs no node_modules. node: builtins stay external automatically.
    packages: "bundle",
    // The SDK reads import.meta.url to find its data dir; keep it pointing at
    // the emitted file so PROJECT_ROOT resolves to server/.
    banner: {
      js: "// Sequesign MCP server — bundled for the .mcpb Desktop Extension.\nimport { createRequire as __createRequire } from 'node:module';\nconst require = __createRequire(import.meta.url);"
    },
    outfile: path.join(SERVER_DIR, "index.js"),
    logLevel: "info"
  });

  // A package.json next to the bundle anchors the SDK's PROJECT_ROOT walk here
  // and marks the emitted .js as ESM.
  await writeFile(
    path.join(SERVER_DIR, "package.json"),
    JSON.stringify({ name: "sequesign-mcp-bundle", private: true, type: "module" }, null, 2) + "\n"
  );

  // The SDK's runtime data, copied from the resolved @sequesign/sdk package
  // (which ships these dirs in its "files"). Placed next to server/package.json
  // so PROJECT_ROOT resolves here and resolveAsset finds it.
  for (const dir of ["registry", "schemas", "profiles"]) {
    const from = path.join(SDK_DIR, dir);
    if (!existsSync(from)) {
      throw new Error(
        `@sequesign/sdk is missing ${dir}/ at ${from}; cannot stage the .mcpb assets. ` +
          "(The published SDK ships registry/schemas/profiles; reinstall it.)"
      );
    }
    await cp(from, path.join(SERVER_DIR, dir), { recursive: true });
  }

  // Manifest + README at the bundle root.
  await cp(path.join(PKG_DIR, "manifest.json"), path.join(OUT_DIR, "manifest.json"));
  await cp(path.join(PKG_DIR, "README.md"), path.join(OUT_DIR, "README.md"));

  console.log("• staged", path.relative(PKG_DIR, OUT_DIR));

  // Pack into a single .mcpb. `mcpb pack` validates manifest.json and zips the
  // staged dir. Always remove any prior archive FIRST so a failed pack can never
  // leave a stale sequesign.mcpb for release automation to upload, and let a
  // pack/validation failure fail this build (execFileSync throws → exit 1) —
  // shipping a missing or stale Desktop Extension silently is worse than a red
  // build. For a local, offline staging-only build (no network to fetch the
  // mcpb CLI), set MCPB_SKIP_PACK=1 to stop after staging mcpb-dist/.
  const outFile = path.join(PKG_DIR, "sequesign.mcpb");
  await rm(outFile, { force: true });
  if (process.env.MCPB_SKIP_PACK === "1") {
    console.log(
      `\n• MCPB_SKIP_PACK=1 — staged ${path.relative(PKG_DIR, OUT_DIR)} only (skipped pack).` +
        `\n  Pack later with: npx @anthropic-ai/mcpb pack mcpb-dist`
    );
    return;
  }
  run("npx", ["-y", "@anthropic-ai/mcpb", "pack", OUT_DIR, outFile]);
  const hash = createHash("sha256").update(readFileSync(outFile)).digest("hex");
  console.log(`\n✓ packed ${path.relative(PKG_DIR, outFile)}`);
  console.log(`  sha256: ${hash}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
