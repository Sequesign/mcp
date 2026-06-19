#!/usr/bin/env node
// Sequesign MCP server (v1) — a thin local-stdio wrapper over @sequesign/sdk.
//
// Exposes six tools so an MCP-capable agent can produce a cryptographically
// verifiable receipt of its own delegated work, then verify it offline:
//
//   sequesign_start_session                  open a recording session (a chain)
//   sequesign_record_action                  append a signed action to the chain
//   sequesign_record_approval                attach a (locally signed) approval
//   sequesign_record_counterparty_attestation attach a counterparty confirmation
//   sequesign_finalize                       seal + witness the receipt
//   sequesign_verify                         verify a sealed package offline
//
// The agent key never leaves the machine: in direct mode the SDK signs each
// action locally and the hosted witness only co-signs a hash. Session state is
// held in memory for the life of the process, keyed by the receipt id returned
// from sequesign_start_session.
//
// Configuration (environment):
//   SEQUESIGN_MODE          "direct" (default) or "managed"
//   SEQUESIGN_WITNESS_URL   direct-mode witness (default https://witness.sequesign.com)
//   SEQUESIGN_BROKER_URL    managed-mode broker (default https://broker.sequesign.com)
//   SEQUESIGN_API_KEY       managed-mode write-class API key (required if managed)
//   SEQUESIGN_TIER          managed tier: hosted | hash-only | ephemeral (default hosted)
//   SEQUESIGN_AGENT_PRIVATE_KEY  Ed25519 PKCS#8 PEM for the agent key. If unset,
//                                a fresh ephemeral key is minted per session
//                                (identity reads self_asserted). In managed mode
//                                it must be the key your API key is registered to.
//   SEQUESIGN_PACKAGE_DIR   base directory for receipt packages
//                           (default <tmpdir>/sequesign-mcp)

import { mkdir, readFile, writeFile, rm } from "node:fs/promises";
import path from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  createHash,
  randomUUID
} from "node:crypto";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import {
  createSequesign,
  loadProfileById,
  loadSchemaByActionType,
  loadSchemaById
} from "@sequesign/sdk";
import type {
  AgentActionReceipt,
  KeyMaterial,
  ProfileReference,
  ReceiptMode,
  RecordedAction,
  Sdk,
  Session,
  SessionInit,
  VerificationReport,
  VerifiabilityClass
} from "@sequesign/sdk";
import {
  verifyReceiptPackage,
  witnessKeysFromReceipt,
  parseTrustedWitnessKeys,
  parseTrustedRegistrationKeys
} from "@sequesign/sdk/verify";

// The version reported to MCP clients via server info. Derived from the nearest
// package.json (walking up from this module) so it tracks the published version
// and can never drift from package.json/server.json the way a hard-coded literal
// did. Works in both layouts: the npm package (dist/index.js → package root's
// package.json) and the bundled .mcpb (server/index.js → the stub package.json,
// into which build-mcpb writes the release version).
function resolveServerVersion(): string {
  let dir = path.dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 8; i++) {
    try {
      const pkg = JSON.parse(readFileSync(path.join(dir, "package.json"), "utf8")) as {
        version?: string;
      };
      if (typeof pkg.version === "string" && pkg.version.length > 0) return pkg.version;
    } catch {
      /* no package.json here — keep walking up */
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return "0.0.0";
}
const SERVER_VERSION = resolveServerVersion();

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

type Mode = "direct" | "managed";

interface Config {
  mode: Mode;
  witnessUrl: string;
  brokerUrl: string;
  dashboardApiUrl: string;
  receiptLibraryUrl: string;
  apiKey?: string;
  tier: "hosted" | "hash-only" | "ephemeral";
  agentPrivateKeyPem?: string;
  packageBaseDir: string;
}

// The API key may only be sent to receipt-store origins the operator
// configured — never an arbitrary caller-supplied receiptUrl. Without this a
// prompt-injected or malicious `receiptUrl` could exfiltrate the write-class
// key to an attacker endpoint. Returns the parsed URL when its origin matches
// the broker or receipt-library origin; throws otherwise.
function assertTrustedReceiptUrl(rawUrl: string, config: Config): URL {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`receiptUrl is not a valid URL: "${rawUrl}".`);
  }
  const allowedOrigins = new Set(
    [config.receiptLibraryUrl, config.brokerUrl].map((u) => new URL(u).origin)
  );
  if (!allowedOrigins.has(parsed.origin)) {
    throw new Error(
      `receiptUrl origin "${parsed.origin}" is not an allowed Sequesign receipt store ` +
        `(${[...allowedOrigins].join(", ")}). The API key is only sent to the configured ` +
        `broker / receipt-library origins; set SEQUESIGN_RECEIPT_LIBRARY_URL or ` +
        `SEQUESIGN_BROKER_URL for a self-hosted store.`
    );
  }
  return parsed;
}

// Managed mode (whether the default or a per-call override) needs both a
// write-class API key and the registered agent key — the broker rejects any
// other agent key. Throwing here keeps a managed start_session from appearing
// to succeed and then failing at the first recordAction/finalize.
function assertManagedReady(config: Config): void {
  if (!config.apiKey) {
    throw new Error(
      "managed mode requires SEQUESIGN_API_KEY (a write-class API key)."
    );
  }
  if (!config.agentPrivateKeyPem) {
    throw new Error(
      "managed mode requires SEQUESIGN_AGENT_PRIVATE_KEY: the Ed25519 private-key PEM your API key is registered to. (Ephemeral keys are only for direct mode.)"
    );
  }
}

// A managed satellite submit only POSTs chain/receipt/content hashes to the
// broker and signs with the approver/counterparty key — the recording agent's
// private key is NOT used. So it needs only the API key; a reviewer machine
// must be able to attest to a sealed receipt without possessing the agent key
// (the whole point of the deferred multi-party flow). start_session still uses
// assertManagedReady (it signs actions with the registered agent key).
function assertManagedBrokerConfigured(config: Config): void {
  if (!config.apiKey) {
    throw new Error(
      "managed mode requires SEQUESIGN_API_KEY to seal a satellite via the broker."
    );
  }
}

// Read an env var, treating empty / whitespace-only as ABSENT. The .mcpb
// (Desktop Extension) host substitutes any user_config field the user left
// blank as an empty string, so `process.env.X ?? default` would keep that ""
// and defeat the default (an empty SEQUESIGN_MODE / SEQUESIGN_PACKAGE_DIR would
// then break startup). Coalescing "" → undefined makes the defaults below fire
// for blank optional fields, and is correct for a shell `export X=` too.
function env(name: string): string | undefined {
  const v = process.env[name];
  return v !== undefined && v.trim().length > 0 ? v : undefined;
}

function loadConfig(): Config {
  const mode = (env("SEQUESIGN_MODE") ?? "direct") as Mode;
  if (mode !== "direct" && mode !== "managed") {
    throw new Error(`SEQUESIGN_MODE must be "direct" or "managed" (got "${mode}").`);
  }
  const tier = (env("SEQUESIGN_TIER") ?? "hosted") as Config["tier"];
  // Trim trailing slashes so we can safely append "/.well-known/..." paths;
  // a configured base like "https://witness.example/" would otherwise yield a
  // "//.well-known/..." the witness/dashboard handlers don't match.
  const trimUrl = (u: string): string => u.replace(/\/+$/, "");
  const config: Config = {
    mode,
    witnessUrl: trimUrl(env("SEQUESIGN_WITNESS_URL") ?? "https://witness.sequesign.com"),
    brokerUrl: trimUrl(env("SEQUESIGN_BROKER_URL") ?? "https://broker.sequesign.com"),
    dashboardApiUrl: trimUrl(
      env("SEQUESIGN_DASHBOARD_API_URL") ?? "https://dashboard-api.sequesign.com"
    ),
    receiptLibraryUrl: trimUrl(
      env("SEQUESIGN_RECEIPT_LIBRARY_URL") ?? "https://library.sequesign.com"
    ),
    apiKey: env("SEQUESIGN_API_KEY"),
    tier,
    agentPrivateKeyPem: env("SEQUESIGN_AGENT_PRIVATE_KEY"),
    packageBaseDir: env("SEQUESIGN_PACKAGE_DIR") ?? path.join(tmpdir(), "sequesign-mcp")
  };
  // Fail fast when the DEFAULT mode is managed but its secrets are missing.
  // (A per-call mode:"managed" override is validated again in start_session.)
  // Managed mode needs at least the broker API key to start. The agent key is
  // required only by start_session (which signs actions with the registered
  // key) and is enforced there per-call — so a broker-only reviewer server that
  // uses just the satellite tools (approve/countersign) can initialize with the
  // API key alone, which is the intended deferred-attestation flow.
  if (mode === "managed") assertManagedBrokerConfigured(config);
  return config;
}

// Build the SDK for a given mode. Direct mode passes the API key to the
// witness too: the hosted witness authenticates the signing POST, so an
// unauthenticated direct call is rejected — the key authenticates/meters the
// request without making the (independent) witness any less independent.
function buildSdk(config: Config, mode: Mode): Sdk {
  if (mode === "managed") {
    return createSequesign({
      mode: "managed",
      tier: config.tier,
      broker: { baseUrl: config.brokerUrl, apiKey: config.apiKey! }
    });
  }
  return createSequesign({
    mode: "direct",
    witness: { baseUrl: config.witnessUrl, ...(config.apiKey ? { apiKey: config.apiKey } : {}) }
  });
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

// Mint a fresh ephemeral Ed25519 keypair (node:crypto — no SDK helper needed).
function mintKeypair(): KeyMaterial {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  };
}

// Normalize a pasted private-key PEM into canonical form. Config UIs — notably
// the Claude Desktop extension's user_config form — often collapse a multi-line
// secret onto one line or keep literal "\n", which makes OpenSSL reject it with
// BAD_END_LINE. Rather than force users to reference a file, we reconstruct the
// PEM from whatever arrives: turn literal \n/\r back into newlines, then re-wrap
// the base64 body between the BEGIN/END markers at 64 columns. A correctly
// formatted multi-line PEM round-trips unchanged.
function normalizePem(raw: string): string {
  const s = raw.trim().replace(/\\r\\n|\\n|\\r/g, "\n");
  const m = s.match(/-----BEGIN ([A-Z0-9 ]+?)-----([\s\S]*?)-----END [A-Z0-9 ]+?-----/);
  if (!m) return s; // not PEM-shaped — let the parser raise its own error
  const label = m[1].trim();
  const body = (m[2].match(/[A-Za-z0-9+/=]/g) ?? []).join("");
  const wrapped = body.match(/.{1,64}/g)?.join("\n") ?? "";
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----\n`;
}

// Derive the full keypair from a private-key PEM, validating it is Ed25519. The
// PEM is normalized first so a key pasted into a single-line config field (with
// newlines stripped or escaped) still parses.
function keypairFromPrivatePem(label: string, rawPem: string): KeyMaterial {
  const pem = normalizePem(rawPem);
  if (!pem.includes("PRIVATE KEY")) {
    throw new Error(`${label} is not an Ed25519 private-key PEM.`);
  }
  const priv = createPrivateKey(pem);
  if (priv.asymmetricKeyType !== "ed25519") {
    throw new Error(`${label} must be an Ed25519 private key (got ${priv.asymmetricKeyType}).`);
  }
  return {
    privateKeyPem: pem,
    publicKeyPem: createPublicKey(priv).export({ type: "spki", format: "pem" }).toString()
  };
}

// Resolve a party keypair from an optional PEM: a supplied key is used as-is;
// otherwise an ephemeral key is minted (the leg stays present_unverified —
// vouching requires an enrolled key + identity proof).
function resolvePartyKeypair(
  label: string,
  pem: string | undefined
): { keypair: KeyMaterial; ephemeral: boolean } {
  if (pem && pem.trim().length > 0) {
    return { keypair: keypairFromPrivatePem(label, pem), ephemeral: false };
  }
  return { keypair: mintKeypair(), ephemeral: true };
}

// ---------------------------------------------------------------------------
// Session registry (in-memory, process-lifetime)
// ---------------------------------------------------------------------------

interface OpenSession {
  session: Session;
  packageDirectory: string;
  // The session's receipt mode. In schema_validated / profile_constrained mode,
  // record_action must attach the per-action schemaId+schemaHash; freeform does
  // not. Captured at start_session so record_action knows which applies.
  mode: ReceiptMode;
  // Per-session serialization tail. The MCP transport can have multiple
  // tool calls in flight at once, and the SDK reads sequenceNext /
  // currentChainState *before* awaiting the witness — so two overlapping
  // mutating calls on one session could both sign the same sequence and
  // corrupt the chain. Every mutating op chains onto this tail (see
  // runExclusive) so they run strictly one at a time per session.
  queue: Promise<unknown>;
}

const sessions = new Map<string, OpenSession>();

// Run fn after any in-flight mutating op for this session has settled, and
// make the next caller wait for fn — a single-slot mutex per session. The
// tail swallows outcomes so one op's rejection never blocks or rejects the
// next; fn's own result/rejection is returned to its caller unchanged.
function runExclusive<T>(open: OpenSession, fn: () => Promise<T>): Promise<T> {
  const run = open.queue.then(fn, fn);
  open.queue = run.then(
    () => undefined,
    () => undefined
  );
  return run;
}

// Per-package-directory serialization for satellite submits. Satellites operate
// on a sealed package on disk (no live session), and each submit reads the
// attestations.jsonl sidecar for its dedup check then appends — so two
// concurrent submits against the same package could race that read-then-append.
// Keyed by package directory; entries are bounded by the distinct package paths
// a process touches.
const packageLocks = new Map<string, Promise<unknown>>();

function runExclusiveByKey<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const prev = packageLocks.get(key) ?? Promise.resolve();
  const run = prev.then(fn, fn);
  packageLocks.set(
    key,
    run.then(
      () => undefined,
      () => undefined
    )
  );
  return run;
}

// Read a sealed receipt envelope (receipt.json) from a package directory.
async function readSealedReceipt(packageDirectory: string): Promise<AgentActionReceipt> {
  const raw = await readFile(path.join(packageDirectory, "receipt.json"), "utf8");
  return JSON.parse(raw) as AgentActionReceipt;
}

// Resolve the receipt a satellite should bind to. Default: the local sealed
// envelope. With receiptUrl: the broker-STORED authoritative copy (which in
// managed mode carries the registered agent_identity_attestation and thus a
// different canonical hash). Binding to the stored copy is what lets a later
// `verify --receiptUrl` show the registered identity AND the folded satellite
// legs on one receipt. Fetch is authenticated and origin-allowlisted, like the
// verify tool — the API key never goes to an arbitrary URL.
async function resolveSatelliteReceipt(
  packageDirectory: string,
  receiptUrl: string | undefined,
  config: Config
): Promise<AgentActionReceipt> {
  // Always read the local sealed package first. The satellite is appended to
  // this package's sidecar and is only verifiable against its actions/evidence,
  // so a typo'd or missing packageDirectory must fail fast — before a witness
  // signature is spent — rather than create a dir with only attestations.jsonl.
  const local = await readSealedReceipt(packageDirectory);
  if (!receiptUrl) return local;
  if (!config.apiKey) {
    throw new Error(
      "receiptUrl requires SEQUESIGN_API_KEY (the stored receipt is fetched authenticated). Omit receiptUrl to bind to the local package's receipt instead."
    );
  }
  const trusted = assertTrustedReceiptUrl(receiptUrl, config);
  const raw = await fetchText(trusted.toString(), config.apiKey);
  const stored = JSON.parse(raw) as AgentActionReceipt;
  // The stored receipt must be the SAME receipt as this package; otherwise the
  // satellite would bind to a receipt whose actions/evidence aren't here and
  // could never verify against this package.
  if (stored.chain?.chain_id !== local.chain?.chain_id) {
    throw new Error(
      `receiptUrl points at chain ${stored.chain?.chain_id ?? "(unknown)"}, but packageDirectory holds chain ${local.chain?.chain_id ?? "(unknown)"}. They must be the same receipt.`
    );
  }
  return stored;
}

function requireSession(sessionId: string): OpenSession {
  const open = sessions.get(sessionId);
  if (!open) {
    throw new Error(
      `Unknown sessionId "${sessionId}". Call sequesign_start_session first; the id is the receiptId it returns. (Sessions are in-memory and do not survive a server restart or sequesign_finalize.)`
    );
  }
  return open;
}

// An opaque, deterministic commitment over a policy object. The receipt's
// policy_context_hash is never recomputed by the verifier (it has no
// preimage), so any stable 64-hex digest serves; we sort keys for stability.
function policyContextHash(policy: unknown): string {
  return createHash("sha256").update(stableStringify(policy)).digest("hex");
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`);
  return `{${entries.join(",")}}`;
}

// ---------------------------------------------------------------------------
// Tool-result helpers
// ---------------------------------------------------------------------------

type ToolResult = {
  content: { type: "text"; text: string }[];
  isError?: boolean;
};

function ok(payload: unknown): ToolResult {
  return { content: [{ type: "text", text: JSON.stringify(payload, null, 2) }] };
}

function fail(error: unknown): ToolResult {
  const message = error instanceof Error ? error.message : String(error);
  return { content: [{ type: "text", text: `Error: ${message}` }], isError: true };
}

function summarizeVerification(report: VerificationReport) {
  return {
    valid: report.valid,
    reason: report.reason,
    verification_level: report.verification_level,
    trust_anchor_mode: report.trust_anchor_mode,
    flags: report.flags,
    identity_assurance: report.identity_assurance ?? null,
    agent_identity: report.agent_identity?.kind ?? null
  };
}

// GET a URL as text, optionally bearer-authenticated, with a clear error on
// non-2xx. Used to fetch the broker-stored receipt and the published trust
// anchors for the stored-receipt verify path. Bounded by a timeout (via
// AbortSignal) so a configured service that accepts the connection but stalls
// can't hang the tool call — the best-effort registration-anchor path then
// falls through to registration_anchor: "unavailable" instead of blocking.
const FETCH_TIMEOUT_MS = 15_000;

async function fetchText(url: string, apiKey?: string): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      ...(apiKey ? { headers: { authorization: `Bearer ${apiKey}` } } : {})
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error(`GET ${url} failed (HTTP ${res.status}): ${text.slice(0, 300)}`);
    }
    return text;
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error(`GET ${url} timed out after ${FETCH_TIMEOUT_MS}ms.`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Server wiring
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const config = loadConfig();

  // One SDK per mode, built on first use. Lets a single server run both
  // direct and managed sessions (chosen per call) without re-reading config.
  const sdkByMode = new Map<Mode, Sdk>();
  const getSdk = (mode: Mode): Sdk => {
    let sdk = sdkByMode.get(mode);
    if (!sdk) {
      sdk = buildSdk(config, mode);
      sdkByMode.set(mode, sdk);
    }
    return sdk;
  };

  const server = new McpServer({
    name: "sequesign",
    version: SERVER_VERSION
  });

  server.registerTool(
    "sequesign_start_session",
    {
      title: "Start a Sequesign session",
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true
      },
      description:
        "Open a new receipt-recording session (one signed action chain). Returns a sessionId (the receiptId) used by the other tools. Provide a policyContext object to bind the receipt to a policy (reaches verification level L3_POLICY_BOUND).",
      inputSchema: {
        taskId: z.string().describe("Stable identifier for the delegated task."),
        delegatorId: z
          .string()
          .describe("Who delegated the task (the principal the agent acts for)."),
        agentId: z
          .string()
          .optional()
          .describe("Identifier for the acting agent. Defaults to 'sequesign-mcp-agent'."),
        policyContext: z
          .record(z.unknown())
          .optional()
          .describe(
            "Policy the agent operates under (object). Hashed into the receipt's policy_context_hash; presence raises the receipt to L3_POLICY_BOUND."
          ),
        mode: z
          .enum(["direct", "managed"])
          .optional()
          .describe(
            "Override the server's default transport for this session. 'direct' signs locally and the independent witness co-signs (self_asserted identity, you keep the envelope). 'managed' routes through the broker (registered identity, broker-stored). Defaults to SEQUESIGN_MODE."
          ),
        profile: z
          .string()
          .optional()
          .describe(
            "Registered workflow profile id (e.g. 'sequesign.invoice_payment.v0.1') to bind this receipt to. When set, the session records in profile_constrained mode: each action must be a registered action type whose evidence validates against its JSON Schema, and the chain must satisfy the profile's required actions/transitions — reaching schema_valid + workflow_profile_valid. Omit for a freeform receipt (the default)."
          )
      }
    },
    async (args) => {
      try {
        const effectiveMode: Mode = args.mode ?? config.mode;
        // Managed needs the API key + registered agent key (whether it's the
        // default or a per-call override); fail before the session is created.
        if (effectiveMode === "managed") assertManagedReady(config);

        // Managed must sign with the registered key; direct uses the provided
        // key if present, else a fresh ephemeral one (self_asserted).
        const agentKeypair = config.agentPrivateKeyPem
          ? keypairFromPrivatePem("SEQUESIGN_AGENT_PRIVATE_KEY", config.agentPrivateKeyPem)
          : mintKeypair();

        // Optional workflow profile → profile_constrained recording. Resolve the
        // profile id to its canonical { profile_id, profile_hash } from the
        // bundled registry (the SDK's schema policy verifies that hash and each
        // action's schema). No profile → freeform (the default, unchanged).
        let receiptMode: ReceiptMode = "freeform";
        let profileRef: ProfileReference | undefined;
        if (args.profile) {
          const loaded = await loadProfileById(args.profile);
          if (!loaded) {
            throw new Error(
              `Unknown profile "${args.profile}". It must be a profile_id in the bundled registry (e.g. "sequesign.invoice_payment.v0.1").`
            );
          }
          receiptMode = "profile_constrained";
          profileRef = { profile_id: loaded.profileId, profile_hash: loaded.profileHash };
        }

        await mkdir(config.packageBaseDir, { recursive: true });
        const safeTask = args.taskId.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 80);
        const packageDirectory = path.join(
          config.packageBaseDir,
          `${safeTask}-${Date.now()}.sequesign`
        );

        const init: SessionInit = {
          agent: { agentId: args.agentId ?? "sequesign-mcp-agent", keypair: agentKeypair },
          task: {
            taskId: args.taskId,
            delegatorId: args.delegatorId,
            ...(args.policyContext
              ? { policyContextHash: policyContextHash(args.policyContext) }
              : {})
          },
          mode: receiptMode,
          ...(profileRef ? { profile: profileRef } : {}),
          package: { directory: packageDirectory, ifExists: "fail" }
        };
        if (effectiveMode === "direct") {
          // Pass the API key to the witness: the hosted witness authenticates
          // the signing POST, so an unauthenticated direct call is rejected.
          init.witness = {
            baseUrl: config.witnessUrl,
            ...(config.apiKey ? { apiKey: config.apiKey } : {})
          };
        }

        const session = await getSdk(effectiveMode).startSession(init);
        sessions.set(session.receiptId, {
          session,
          packageDirectory,
          mode: session.mode,
          queue: Promise.resolve()
        });

        return ok({
          sessionId: session.receiptId,
          chainId: session.chainId,
          mode: session.mode,
          transport: effectiveMode,
          // In managed mode the registered key is always used; ephemeral only
          // happens in direct mode with no SEQUESIGN_AGENT_PRIVATE_KEY set.
          ephemeral_agent_key: effectiveMode === "direct" && !config.agentPrivateKeyPem,
          package_directory: packageDirectory,
          policy_bound: Boolean(args.policyContext)
        });
      } catch (error) {
        return fail(error);
      }
    }
  );

  server.registerTool(
    "sequesign_record_action",
    {
      title: "Record an action",
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true
      },
      description:
        "Append a signed action to the session's chain. evidence is the structured record of what the agent did or observed; it is hashed and signed. Returns the actionId (use it as attestedActionId for a counterparty attestation).",
      inputSchema: {
        sessionId: z.string().describe("The receiptId returned by sequesign_start_session."),
        actionType: z
          .string()
          .describe("Short snake_case label for the action (e.g. 'invoice_policy_checked')."),
        evidence: z
          .unknown()
          .describe("Structured evidence for the action (any JSON value). Hashed and signed."),
        verifiabilityClass: z
          .enum([
            "deterministic",
            "non_deterministic",
            "counterparty_attested",
            "tool_captured",
            "human_signed",
            "unknown"
          ])
          .optional()
          .describe("How the evidence can be verified. Defaults to 'deterministic'."),
        metadata: z
          .record(z.unknown())
          .optional()
          .describe("Optional non-signed-over metadata (e.g. agent reasoning)."),
        schemaId: z
          .string()
          .optional()
          .describe(
            "Override the registered schema for this action (a schema_id). Only used when the session is schema/profile-bound; by default the schema is resolved from actionType. Ignored for freeform sessions."
          )
      }
    },
    async (args) => {
      try {
        const open = requireSession(args.sessionId);
        // Schema/profile-bound sessions require a per-action schemaId+schemaHash,
        // verified against the bundled registry. Resolve from an explicit
        // schemaId override, else from the action type. Freeform sessions skip
        // this entirely (the schema fields stay undefined).
        let schemaFields: { schemaId?: string; schemaHash?: string } = {};
        if (open.mode === "profile_constrained" || open.mode === "schema_validated") {
          const loaded = args.schemaId
            ? await loadSchemaById(args.schemaId)
            : await loadSchemaByActionType(args.actionType);
          if (!loaded) {
            throw new Error(
              `No registered schema for ${
                args.schemaId ? `schema_id "${args.schemaId}"` : `action type "${args.actionType}"`
              }; ${open.mode} mode requires every action to carry a registered schema.`
            );
          }
          schemaFields = { schemaId: loaded.schemaId, schemaHash: loaded.schemaHash };
        }
        const recorded: RecordedAction = await runExclusive(open, () =>
          open.session.recordAction({
            actionType: args.actionType,
            evidence: args.evidence,
            verifiabilityClass:
              (args.verifiabilityClass as VerifiabilityClass | undefined) ?? "deterministic",
            metadata: args.metadata,
            ...schemaFields
          })
        );
        return ok({
          actionId: recorded.actionId,
          actionType: recorded.actionType,
          sequence: recorded.sequence,
          evidenceHash: recorded.evidenceHash,
          chainState: recorded.chainState,
          ...(schemaFields.schemaId ? { schemaId: schemaFields.schemaId } : {})
        });
      } catch (error) {
        return fail(error);
      }
    }
  );

  server.registerTool(
    "sequesign_record_approval",
    {
      title: "Record an approval",
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      },
      description:
        "Attach a signed approval for an action already recorded in this session (e.g. a human or independent agent reviewer signing off). The action being approved must already be recorded. If no approverPrivateKeyPem is given, an ephemeral key is minted and the approval leg stays present_unverified; supply an enrolled key plus identityProofRef to make it a vouched (present_verified) approval.",
      inputSchema: {
        sessionId: z.string().describe("The receiptId returned by sequesign_start_session."),
        approverId: z
          .string()
          .describe("Identity of the approver (lowercase email or label, e.g. 'cfo@acme.example')."),
        approvedActionType: z
          .string()
          .describe("The action_type being approved (must match a recorded action)."),
        approvalContext: z
          .unknown()
          .describe("What is being approved (any JSON value). Hashed into the signed approval."),
        partyType: z
          .enum(["human", "agent"])
          .optional()
          .describe("Whether the approver is a human or an agent reviewer. Defaults to 'human'."),
        approverPrivateKeyPem: z
          .string()
          .optional()
          .describe("Ed25519 private-key PEM of the approver. Omit to mint an ephemeral key."),
        identityProofRef: z
          .string()
          .optional()
          .describe(
            "base64url SignedRegistrationRecord (issuer 'sequesign') from enrollment, to make the approval vouched (present_verified)."
          )
      }
    },
    async (args) => {
      try {
        const open = requireSession(args.sessionId);
        const { keypair, ephemeral } = resolvePartyKeypair(
          "approverPrivateKeyPem",
          args.approverPrivateKeyPem
        );
        if (args.identityProofRef && ephemeral) {
          return fail(
            "identityProofRef was supplied without approverPrivateKeyPem. An identity proof is issued for a specific enrolled key; it can never match a freshly minted ephemeral key, so the leg would stay present_unverified. Pass the enrolled approver's private-key PEM to vouch."
          );
        }
        const attestation = await runExclusive(open, () =>
          open.session.recordApproval({
            mode: "sign_locally",
            approverId: args.approverId,
            partyType: args.partyType ?? "human",
            approverKeypair: keypair,
            approvedActionType: args.approvedActionType,
            approvalContext: args.approvalContext,
            ...(args.identityProofRef
              ? { identityProof: { issuer: "sequesign", ref: args.identityProofRef } }
              : {})
          })
        );
        return ok({
          approvalId: attestation.approval_id,
          approverId: attestation.approver_id,
          partyType: attestation.party_type,
          approvedActionType: attestation.approved_action_type,
          ephemeral_key: ephemeral,
          // A proof was attached; whether the leg actually verifies as
          // present_verified is decided at verify time (the proof must match
          // this signer key AND the verifier must be given trusted
          // registration keys), so do not claim "vouched" here.
          identity_proof_attached: Boolean(args.identityProofRef)
        });
      } catch (error) {
        return fail(error);
      }
    }
  );

  server.registerTool(
    "sequesign_record_counterparty_attestation",
    {
      title: "Record a counterparty attestation",
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      },
      description:
        "Attach a counterparty's signed confirmation of an action already recorded in this session (e.g. a vendor confirming a corrected invoice total). The SDK derives the content binding from the attested action, so the confirmation cannot be pointed at content the counterparty never saw. If no counterpartyPrivateKeyPem is given, an ephemeral key is minted (present_unverified); supply an enrolled key plus identityProofRef for a vouched (present_verified) attestation.",
      inputSchema: {
        sessionId: z.string().describe("The receiptId returned by sequesign_start_session."),
        counterpartyId: z
          .string()
          .describe(
            "Canonical counterparty id (lowercase alphanumeric segments joined by single dots or hyphens, e.g. 'vendor-abc')."
          ),
        attestedActionId: z
          .string()
          .describe("The actionId (from sequesign_record_action) the counterparty is confirming."),
        attestationPurpose: z
          .string()
          .describe("Why the counterparty is signing (e.g. 'invoice_amount_confirmation')."),
        counterpartyPrivateKeyPem: z
          .string()
          .optional()
          .describe("Ed25519 private-key PEM of the counterparty. Omit to mint an ephemeral key."),
        identityProofRef: z
          .string()
          .optional()
          .describe(
            "base64url SignedRegistrationRecord (issuer 'sequesign') from enrollment, to make the attestation vouched (present_verified)."
          )
      }
    },
    async (args) => {
      try {
        const open = requireSession(args.sessionId);
        const { keypair, ephemeral } = resolvePartyKeypair(
          "counterpartyPrivateKeyPem",
          args.counterpartyPrivateKeyPem
        );
        if (args.identityProofRef && ephemeral) {
          return fail(
            "identityProofRef was supplied without counterpartyPrivateKeyPem. An identity proof is issued for a specific enrolled key; it can never match a freshly minted ephemeral key, so the leg would stay present_unverified. Pass the enrolled counterparty's private-key PEM to vouch."
          );
        }
        const attestation = await runExclusive(open, () =>
          open.session.recordCounterpartyAttestation({
            mode: "sign_locally",
            counterpartyId: args.counterpartyId,
            counterpartyKeypair: keypair,
            attestedActionId: args.attestedActionId,
            attestationPurpose: args.attestationPurpose,
            ...(args.identityProofRef
              ? { identityProof: { issuer: "sequesign", ref: args.identityProofRef } }
              : {})
          })
        );
        return ok({
          counterpartyId: attestation.counterparty_id,
          attestedActionId: attestation.attested_action_id,
          attestationPurpose: attestation.attestation_purpose,
          ephemeral_key: ephemeral,
          // A proof was attached; present_verified is decided at verify time
          // (proof must match this signer key AND trusted registration keys
          // must be supplied), so do not claim "vouched" here.
          identity_proof_attached: Boolean(args.identityProofRef)
        });
      } catch (error) {
        return fail(error);
      }
    }
  );

  server.registerTool(
    "sequesign_approve_receipt",
    {
      title: "Approve a sealed receipt (deferred satellite)",
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true
      },
      description:
        "Attach an independently-witnessed APPROVAL to an already-finalized receipt, without modifying it. Use this when a reviewer (human or another agent) signs off after the receipt was sealed — e.g. one model approves work another model recorded. The approval is bound to the sealed receipt by hash, witnessed at its own time, and written to the package's attestations sidecar. The approver MUST be distinct from the recording agent. If no approverPrivateKeyPem is given an ephemeral key is minted (present_unverified); pass an enrolled key + identityProofRef to vouch.",
      inputSchema: {
        packageDirectory: z
          .string()
          .describe("Path to the sealed .sequesign package directory (the receipt to approve)."),
        approverId: z
          .string()
          .describe("Identity of the approver (lowercase email or label, e.g. 'reviewer@acme.example')."),
        approvedActionType: z
          .string()
          .describe("The action_type being approved (must match an action in the sealed receipt)."),
        approvalContext: z
          .unknown()
          .describe("What is being approved (any JSON value). Hashed into the signed approval."),
        partyType: z
          .enum(["human", "agent"])
          .optional()
          .describe("Whether the approver is a human or an agent reviewer. Defaults to 'human'."),
        approverPrivateKeyPem: z
          .string()
          .optional()
          .describe("Ed25519 private-key PEM of the approver. Omit to mint an ephemeral key."),
        identityProofRef: z
          .string()
          .optional()
          .describe(
            "base64url SignedRegistrationRecord (issuer 'sequesign') from enrollment, to make the approval vouched (present_verified)."
          ),
        mode: z
          .enum(["direct", "managed"])
          .optional()
          .describe(
            "Transport for the witness seal. It MUST match how the receipt was sealed — the satellite must be witnessed by the same witness that sealed the receipt, or the verifier drops it (satellite_seal_untrusted_witness). Defaults to SEQUESIGN_MODE; set it if the receipt was finalized with a different per-call mode."
          ),
        receiptUrl: z
          .string()
          .optional()
          .describe(
            "Bind the approval to the broker-STORED receipt at this URL instead of the local package's receipt.json. In managed mode the stored copy carries the registered agent identity (different hash), so binding to it lets a later `verify --receiptUrl` show the registered identity AND this approval on one receipt. Fetched authenticated; must be a configured Sequesign receipt-store origin."
          )
      }
    },
    async (args) => {
      try {
        const effectiveMode: Mode = args.mode ?? config.mode;
        if (effectiveMode === "managed") assertManagedBrokerConfigured(config);
        const { keypair, ephemeral } = resolvePartyKeypair(
          "approverPrivateKeyPem",
          args.approverPrivateKeyPem
        );
        if (args.identityProofRef && ephemeral) {
          return fail(
            "identityProofRef was supplied without approverPrivateKeyPem. An identity proof is issued for a specific enrolled key; it can never match a freshly minted ephemeral key, so the leg would stay present_unverified. Pass the enrolled approver's private-key PEM to vouch."
          );
        }
        const satellite = await runExclusiveByKey(args.packageDirectory, async () => {
          const receipt = await resolveSatelliteReceipt(
            args.packageDirectory,
            args.receiptUrl,
            config
          );
          return getSdk(effectiveMode).submitApprovalSatellite({
            packageDirectory: args.packageDirectory,
            receipt,
            mode: "sign_locally",
            approverId: args.approverId,
            partyType: args.partyType ?? "human",
            approverKeypair: keypair,
            approvedActionType: args.approvedActionType,
            approvalContext: args.approvalContext,
            ...(args.identityProofRef
              ? { identityProof: { issuer: "sequesign", ref: args.identityProofRef } }
              : {})
          });
        });
        return ok({
          satellite: "approval",
          approvalId: satellite.approval.approval_id,
          approverId: satellite.approval.approver_id,
          partyType: satellite.approval.party_type,
          approvedActionType: satellite.approval.approved_action_type,
          witnessed_at: satellite.witness_attestation.witnessed_at,
          ephemeral_key: ephemeral,
          identity_proof_attached: Boolean(args.identityProofRef)
        });
      } catch (error) {
        return fail(error);
      }
    }
  );

  server.registerTool(
    "sequesign_countersign_receipt",
    {
      title: "Countersign a sealed receipt (deferred counterparty satellite)",
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true
      },
      description:
        "Attach an independently-witnessed COUNTERPARTY confirmation to an already-finalized receipt, without modifying it. Use this when a counterparty (e.g. a vendor, or another model acting as one) confirms an action after the receipt was sealed. The confirmation is bound to the sealed receipt + the attested action by hash, witnessed at its own time, and written to the package's attestations sidecar. If no counterpartyPrivateKeyPem is given an ephemeral key is minted (present_unverified); pass an enrolled key + identityProofRef to vouch.",
      inputSchema: {
        packageDirectory: z
          .string()
          .describe("Path to the sealed .sequesign package directory (the receipt to countersign)."),
        counterpartyId: z
          .string()
          .describe(
            "Canonical counterparty id (lowercase alphanumeric segments joined by single dots or hyphens, e.g. 'vendor-abc')."
          ),
        attestedActionId: z
          .string()
          .describe("The actionId in the sealed receipt the counterparty is confirming."),
        attestationPurpose: z
          .string()
          .describe("Why the counterparty is signing (e.g. 'delivery_confirmation')."),
        counterpartyPrivateKeyPem: z
          .string()
          .optional()
          .describe("Ed25519 private-key PEM of the counterparty. Omit to mint an ephemeral key."),
        identityProofRef: z
          .string()
          .optional()
          .describe(
            "base64url SignedRegistrationRecord (issuer 'sequesign') from enrollment, to make the attestation vouched (present_verified)."
          ),
        mode: z
          .enum(["direct", "managed"])
          .optional()
          .describe(
            "Transport for the witness seal. It MUST match how the receipt was sealed — the satellite must be witnessed by the same witness that sealed the receipt, or the verifier drops it (satellite_seal_untrusted_witness). Defaults to SEQUESIGN_MODE; set it if the receipt was finalized with a different per-call mode."
          ),
        receiptUrl: z
          .string()
          .optional()
          .describe(
            "Bind the confirmation to the broker-STORED receipt at this URL instead of the local package's receipt.json. In managed mode the stored copy carries the registered agent identity (different hash), so binding to it lets a later `verify --receiptUrl` show the registered identity AND this confirmation on one receipt. Fetched authenticated; must be a configured Sequesign receipt-store origin."
          )
      }
    },
    async (args) => {
      try {
        const effectiveMode: Mode = args.mode ?? config.mode;
        if (effectiveMode === "managed") assertManagedBrokerConfigured(config);
        const { keypair, ephemeral } = resolvePartyKeypair(
          "counterpartyPrivateKeyPem",
          args.counterpartyPrivateKeyPem
        );
        if (args.identityProofRef && ephemeral) {
          return fail(
            "identityProofRef was supplied without counterpartyPrivateKeyPem. An identity proof is issued for a specific enrolled key; it can never match a freshly minted ephemeral key, so the leg would stay present_unverified. Pass the enrolled counterparty's private-key PEM to vouch."
          );
        }
        const satellite = await runExclusiveByKey(args.packageDirectory, async () => {
          const receipt = await resolveSatelliteReceipt(
            args.packageDirectory,
            args.receiptUrl,
            config
          );
          return getSdk(effectiveMode).submitCounterpartySatellite({
            packageDirectory: args.packageDirectory,
            receipt,
            mode: "sign_locally",
            counterpartyId: args.counterpartyId,
            counterpartyKeypair: keypair,
            attestedActionId: args.attestedActionId,
            attestationPurpose: args.attestationPurpose,
            ...(args.identityProofRef
              ? { identityProof: { issuer: "sequesign", ref: args.identityProofRef } }
              : {})
          });
        });
        return ok({
          satellite: "counterparty",
          counterpartyId: satellite.counterparty.counterparty_id,
          attestedActionId: satellite.counterparty.attested_action_id,
          attestationPurpose: satellite.counterparty.attestation_purpose,
          witnessed_at: satellite.witness_attestation.witnessed_at,
          ephemeral_key: ephemeral,
          identity_proof_attached: Boolean(args.identityProofRef)
        });
      } catch (error) {
        return fail(error);
      }
    }
  );

  server.registerTool(
    "sequesign_finalize",
    {
      title: "Finalize the receipt",
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true
      },
      description:
        "Seal the session into a verifiable receipt package and run the SDK's own verification. After finalize the sessionId is closed (removed from memory). Returns the package directory (and the stored receipt URL in managed mode) plus a verification summary.",
      inputSchema: {
        sessionId: z.string().describe("The receiptId returned by sequesign_start_session.")
      }
    },
    async (args) => {
      try {
        const open = requireSession(args.sessionId);
        // Serialized with the other mutating ops so finalize cannot run while
        // a recordAction is mid-flight (which would seal a partial chain).
        const result = await runExclusive(open, () => open.session.finalize());
        sessions.delete(args.sessionId);
        return ok({
          receiptId: result.receiptId,
          package_directory: open.packageDirectory,
          receipt_url: result.receiptUrl ?? null,
          verification: summarizeVerification(result.verification)
        });
      } catch (error) {
        return fail(error);
      }
    }
  );

  server.registerTool(
    "sequesign_verify",
    {
      title: "Verify a receipt package",
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true
      },
      description:
        "Verify a sealed Sequesign receipt. Modes: (1) default — an integrity self-check of the local package (trust anchor is the receipt's own embedded witness keys); (2) pass trustedWitnessKeysJson and/or trustedRegistrationKeysJson for a third-party 'external' trust check and registered-identity promotion; (3) set fetchAnchors:true to auto-fetch those witness + registration anchors from the configured well-knowns (so a local direct-mode receipt reports external trust and a registered identity without pasting JSON); (4) pass receiptUrl to verify the broker-STORED receipt (the authoritative copy that carries the registered agent_identity_attestation), auto-fetching the anchors. receiptUrl still needs packageDirectory (the stored envelope is verified against the package's evidence/keys).",
      inputSchema: {
        packageDirectory: z
          .string()
          .describe("Path to the .sequesign package directory (the actions/evidence/keys live here)."),
        receiptUrl: z
          .string()
          .optional()
          .describe(
            "The broker-stored receipt URL (the receipt_url from finalize). When set, the stored envelope is fetched (with SEQUESIGN_API_KEY) and verified against packageDirectory, with witness + registration anchors auto-fetched — surfacing external trust and the registered identity."
          ),
        trustedWitnessKeysJson: z
          .string()
          .optional()
          .describe(
            "Contents of the witness's published keys.json. Provided → 'external' trust check; omitted (and no receiptUrl) → the receipt's embedded keys are used ('self', integrity only). With receiptUrl it overrides the auto-fetched witness anchors."
          ),
        trustedRegistrationKeysJson: z
          .string()
          .optional()
          .describe(
            "Contents of the platform's published registration-keys.json, to flip the agent/approver/counterparty legs to verified. With receiptUrl it overrides the auto-fetched registration anchors."
          ),
        fetchAnchors: z
          .boolean()
          .optional()
          .describe(
            "Local verify only (ignored with receiptUrl): auto-fetch the witness keys and platform registration-keys from the configured SEQUESIGN_WITNESS_URL / SEQUESIGN_DASHBOARD_API_URL well-knowns, so the result surfaces external witness trust and the registered agent/approver/counterparty identity without pasting JSON. Explicit trustedWitnessKeysJson / trustedRegistrationKeysJson override the matching fetch. Best-effort: an unreachable endpoint falls back (witness → self; registration → leg not promoted) and is noted in the result. Default false = fully offline self-check."
          )
      }
    },
    async (args) => {
      try {
        // (3) Stored-receipt verify: fetch the broker's authoritative envelope
        // (it carries the registered agent_identity_attestation the local copy
        // lacks) and verify it against the local package, anchored on the
        // published witness + registration keys (auto-fetched unless overridden).
        if (args.receiptUrl) {
          if (!config.apiKey) {
            return fail(
              "Verifying a stored receiptUrl requires SEQUESIGN_API_KEY (the stored receipt is fetched authenticated). Set it, or omit receiptUrl to verify the local package."
            );
          }
          // Only forward the API key to a configured Sequesign receipt-store
          // origin — never an arbitrary caller-supplied URL (key-exfiltration
          // guard). Throws (→ fail) if receiptUrl points elsewhere.
          const trustedReceiptUrl = assertTrustedReceiptUrl(args.receiptUrl, config);
          const storedEnvelope = await fetchText(trustedReceiptUrl.toString(), config.apiKey);
          const envelopePath = path.join(tmpdir(), `sequesign-mcp-stored-${randomUUID()}.json`);
          await writeFile(envelopePath, storedEnvelope);
          try {
            const trustedWitnessKeys = parseTrustedWitnessKeys(
              args.trustedWitnessKeysJson ??
                (await fetchText(`${config.witnessUrl}/.well-known/sequesign/keys.json`))
            );
            let trustedRegistrationKeys;
            let registrationAnchor = "applied";
            if (args.trustedRegistrationKeysJson) {
              // A caller-supplied anchor is explicit intent: malformed input
              // must fail loudly (matching the local-package path), never
              // silently downgrade the identity leg.
              trustedRegistrationKeys = parseTrustedRegistrationKeys(
                args.trustedRegistrationKeysJson
              );
            } else {
              // Auto-fetched anchor is best-effort: if that endpoint is down,
              // witness/integrity still verify — the identity leg just isn't
              // promoted. Surface which happened in the result.
              try {
                trustedRegistrationKeys = parseTrustedRegistrationKeys(
                  await fetchText(
                    `${config.dashboardApiUrl}/.well-known/sequesign/registration-keys.json`
                  )
                );
              } catch (regError) {
                registrationAnchor = `unavailable (${
                  regError instanceof Error ? regError.message : String(regError)
                })`;
              }
            }
            const report = await verifyReceiptPackage(args.packageDirectory, {
              envelopePath,
              trustedWitnessKeys,
              trustAnchorMode: "external",
              ...(trustedRegistrationKeys ? { trustedRegistrationKeys } : {})
            });
            return ok({
              source: "stored_receipt",
              self_check: false,
              registration_anchor: registrationAnchor,
              ...summarizeVerification(report)
            });
          } finally {
            await rm(envelopePath, { force: true });
          }
        }

        // Local-package verify (no receiptUrl). Default: a fully offline
        // self-check anchored on the receipt's own embedded witness keys.
        // Explicit trusted*KeysJson — or fetchAnchors, which pulls the witness +
        // registration well-knowns from the configured URLs — promote the trust
        // and identity legs without the caller pasting key JSON.

        // Registration anchor (flips agent/approver/counterparty → registered).
        let trustedRegistrationKeys;
        let registrationAnchor = "not_requested";
        if (args.trustedRegistrationKeysJson) {
          // Explicit intent → malformed input fails loudly.
          trustedRegistrationKeys = parseTrustedRegistrationKeys(args.trustedRegistrationKeysJson);
          registrationAnchor = "applied";
        } else if (args.fetchAnchors) {
          // Best-effort: a down endpoint leaves integrity/witness intact; the
          // identity leg simply isn't promoted.
          try {
            trustedRegistrationKeys = parseTrustedRegistrationKeys(
              await fetchText(
                `${config.dashboardApiUrl}/.well-known/sequesign/registration-keys.json`
              )
            );
            registrationAnchor = "applied";
          } catch (regError) {
            registrationAnchor = `unavailable (${
              regError instanceof Error ? regError.message : String(regError)
            })`;
          }
        }

        // Witness anchor (flips trust_anchor_mode self → external).
        let trustedWitnessKeys;
        let trustAnchorMode: "self" | "external" = "self";
        if (args.trustedWitnessKeysJson) {
          trustedWitnessKeys = parseTrustedWitnessKeys(args.trustedWitnessKeysJson);
          trustAnchorMode = "external";
        } else if (args.fetchAnchors) {
          try {
            trustedWitnessKeys = parseTrustedWitnessKeys(
              await fetchText(`${config.witnessUrl}/.well-known/sequesign/keys.json`)
            );
            trustAnchorMode = "external";
          } catch {
            // Witness well-known unreachable → fall back to embedded self-trust
            // below; any fetched registration anchor still promotes identity.
          }
        }
        if (!trustedWitnessKeys) {
          const receipt = JSON.parse(
            await readFile(path.join(args.packageDirectory, "receipt.json"), "utf8")
          );
          trustedWitnessKeys = witnessKeysFromReceipt(receipt);
          trustAnchorMode = "self";
        }

        const report: VerificationReport = await verifyReceiptPackage(args.packageDirectory, {
          trustedWitnessKeys,
          trustAnchorMode,
          ...(trustedRegistrationKeys ? { trustedRegistrationKeys } : {})
        });

        return ok({
          source: "local_package",
          self_check: trustAnchorMode === "self",
          ...(args.fetchAnchors || args.trustedRegistrationKeysJson
            ? { registration_anchor: registrationAnchor }
            : {}),
          ...summarizeVerification(report)
        });
      } catch (error) {
        return fail(error);
      }
    }
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
  // stdout is the MCP transport; log lifecycle to stderr only.
  process.stderr.write(
    `sequesign-mcp ready (mode=${config.mode}, witness=${config.witnessUrl})\n`
  );
}

main().catch((error) => {
  process.stderr.write(
    `sequesign-mcp failed to start: ${error instanceof Error ? error.message : String(error)}\n`
  );
  process.exit(1);
});
