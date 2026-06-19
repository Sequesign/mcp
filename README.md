# @sequesign/mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for
[Sequesign](https://sequesign.com) — let an MCP-capable agent produce a
cryptographically verifiable receipt of its own delegated work, then verify it
offline.

It is a thin local-stdio wrapper over [`@sequesign/sdk`](../sequesign-sdk). The
agent's signing key never leaves the machine: in direct mode the SDK signs each
action locally and the hosted witness only co-signs a hash.

## Tools

| Tool | What it does |
| --- | --- |
| `sequesign_start_session` | Open a recording session (one signed action chain). Returns a `sessionId` (the receipt id) used by every other tool. Pass a `policyContext` object to bind the receipt to a policy (reaches `L3_POLICY_BOUND`). Optional `mode` (`direct`/`managed`) overrides the server default per session. |
| `sequesign_record_action` | Append a signed action to the chain. `evidence` is hashed and signed. Returns the `actionId`. |
| `sequesign_record_approval` | Attach a locally signed approval for a recorded action (e.g. a human or agent reviewer signing off). |
| `sequesign_record_counterparty_attestation` | Attach a counterparty's signed confirmation of a recorded action (e.g. a vendor confirming an amount). The SDK derives the content binding from the attested action. |
| `sequesign_approve_receipt` | Attach an independently-witnessed **approval** to an *already-sealed* receipt (a deferred satellite). For a reviewer — human or another agent — signing off after the fact. The approver must be distinct from the recording agent. |
| `sequesign_countersign_receipt` | Attach an independently-witnessed **counterparty confirmation** to an *already-sealed* receipt (a deferred satellite), bound to a specific action. |
| `sequesign_finalize` | Seal + witness the receipt and run the SDK's own verification. Closes the session. |
| `sequesign_verify` | Verify a sealed receipt offline. Three modes: integrity self-check of the local package (default); third-party `external` check when you pass the witness's published keys; or pass `receiptUrl` to verify the broker-**stored** receipt (the authoritative copy carrying the registered identity), auto-fetching the published witness + registration anchors. |

### Choosing a mode per session

The server default is `SEQUESIGN_MODE`, but `sequesign_start_session` accepts a
`mode` argument (`direct` or `managed`) so one running server can do both
without editing config. A `mode: "managed"` session still requires the managed
secrets (`SEQUESIGN_API_KEY` + `SEQUESIGN_AGENT_PRIVATE_KEY`); the call fails
fast if they're absent.

### Verifying the stored (registered-identity) receipt

In managed mode the broker stamps the registered `agent_identity_attestation`
into the **stored** receipt, not the local envelope — so a local verify reads
`self_asserted`. Pass the `receipt_url` from `finalize` as `receiptUrl` to
`sequesign_verify`: it fetches the stored receipt (using `SEQUESIGN_API_KEY`),
verifies it against your local package, and auto-fetches the published witness
and registration anchors, so the result shows `external` trust **and** the
`registered` identity.

### Multi-party / deferred attestation (after sealing)

`sequesign_approve_receipt` and `sequesign_countersign_receipt` attest to a
receipt that's **already finalized**, without modifying it. Each produces a
detached **satellite** that's bound to the sealed receipt by hash, independently
witnessed *at its own time*, and written to the package's `attestations.jsonl`
sidecar; the verifier folds a valid satellite into the same approval/counterparty
leg as an in-receipt one. They take the sealed **`packageDirectory`** (not a live
session), so a *different* party — even a different model on a different machine,
as long as it has the package — can approve or countersign later. This is the
basis for a multi-party flow: one agent records and seals the work, a second
party approves it, a third confirms it — three independent, timestamped
signatures on one receipt.

**Binding to the registered (stored) receipt.** By default a satellite binds to
the local `receipt.json`. In managed mode the broker-stored copy carries the
registered `agent_identity_attestation` (a different hash), so pass the
`receipt_url` as **`receiptUrl`** to `approve_receipt` / `countersign_receipt`:
the tool fetches the stored receipt (authenticated, origin-allowlisted) and
binds the satellite to it. A later `sequesign_verify --receiptUrl` then shows
the **registered identity AND the folded approval/counterparty legs on one
receipt**. Set the satellite's `mode` to match how the receipt was sealed.

**Convergence note (cross-platform).** The broker does **not** store satellites
— a sealed satellite is appended to the local package's `attestations.jsonl`.
So for parties on *different* machines/platforms to converge on one verifiable
receipt, the `.sequesign` **package must travel between them** (an orchestrator
moves it, each appends its satellite). Independent submission with server-side
satellite storage is a future broker capability.

### Vouching (verified parties)

`sequesign_record_approval` and `sequesign_record_counterparty_attestation`
mint an **ephemeral** key when you don't pass one, so the leg verifies as
`present_unverified`. To get a `present_verified` (vouched) leg, enroll the
party's key with the platform first and pass both the enrolled private key PEM
and the returned `identityProofRef`. Then `sequesign_verify` flips the leg to
`present_verified` when given the platform's published registration keys.

## Configuration

All configuration is via environment variables:

| Variable | Default | Notes |
| --- | --- | --- |
| `SEQUESIGN_MODE` | `direct` | Default transport: `direct` (local key, independent witness co-signs) or `managed` (broker). Overridable per session via the `mode` tool argument. |
| `SEQUESIGN_WITNESS_URL` | `https://witness.sequesign.com` | Direct-mode witness. |
| `SEQUESIGN_BROKER_URL` | `https://broker.sequesign.com` | Managed-mode broker. |
| `SEQUESIGN_DASHBOARD_API_URL` | `https://dashboard-api.sequesign.com` | Source of the published registration keys for the `receiptUrl` verify path. |
| `SEQUESIGN_RECEIPT_LIBRARY_URL` | `https://library.sequesign.com` | Receipt-store origin. The API key is forwarded **only** to this or the broker origin when fetching a `receiptUrl`; any other origin is rejected before the key is sent (key-exfiltration guard). |
| `SEQUESIGN_API_KEY` | — | Required in managed mode (write-class key). In **direct** mode it's passed to the witness too — the hosted witness authenticates the signing POST, so direct mode needs it unless you point `SEQUESIGN_WITNESS_URL` at a witness that allows unauthenticated signing. |
| `SEQUESIGN_TIER` | `hosted` | Managed tier: `hosted`, `hash-only`, or `ephemeral`. |
| `SEQUESIGN_AGENT_PRIVATE_KEY` | — | Ed25519 PKCS#8 PEM for the agent key. In direct mode, if unset a fresh ephemeral key is minted per session (identity reads `self_asserted`). **Required in managed mode** — it must be the key your API key is registered to (the broker rejects any other agent key). |
| `SEQUESIGN_PACKAGE_DIR` | `<tmpdir>/sequesign-mcp` | Where receipt packages are written. |

> Sessions are held **in memory** for the life of the process. A `sessionId`
> does not survive a server restart or `sequesign_finalize`.

## Install

### As a Claude Desktop Extension (`.mcpb`) — recommended

The one-click path: download `sequesign.mcpb` from the
[GitHub releases](https://github.com/Sequesign/mcp/releases) and open it
with Claude Desktop (Settings → Extensions → install from file). Desktop renders
a setup form from the manifest's `user_config`; fill in:

| Field | Notes |
| --- | --- |
| **Mode** | `direct` (default) or `managed`. |
| **API key** | Your write-class key. Required for `managed`; in `direct` it authenticates the hosted witness. Stored in your OS keychain. |
| **Agent private key (PEM)** | Ed25519 PKCS#8 PEM. Required in `managed` (must match the key your API key is registered to); leave blank in `direct` to mint an ephemeral key per session. Stored in your OS keychain. |
| **Receipt package directory** | Where sealed packages are written. Blank → a temp directory. |

Secrets go to the OS keychain (never the manifest), and blank optional fields
fall back to their defaults. The bundle is self-contained — no `npm`/`node`
project setup required. **Where do the API key and agent key come from?** See
[Getting your keys](#getting-your-keys-and-which-identity-you-get) below.

**Building the `.mcpb` from source:**

```sh
npm run build:mcpb -w @sequesign/mcp
# → packages/sequesign-mcp/sequesign.mcpb (+ the staged mcpb-dist/ directory)
```

The build bundles the server and all dependencies into a single file with
esbuild and copies the protocol registry/schemas/profiles next to it, then packs
and validates via `@anthropic-ai/mcpb`. Attach the resulting `.mcpb` (and its
printed SHA-256) to a GitHub release.

> Releasing to npm and the official MCP registry is automated — see
> [PUBLISHING.md](./PUBLISHING.md).

### Via npm

For non-Desktop MCP clients (or if you prefer managing config yourself), install
from npm and configure via environment variables — see **Usage** below.

## Getting your keys (and which identity you get)

The two secrets — your **API key** and your **agent private key** — come from the
Sequesign dashboard's Create-API-key flow. The key you use in managed mode must
be the one **registered** to your API key.

### Managed mode — registered identity

Create an API key in the dashboard (Settings → API keys → **Create key**).
Registration is **off by default**, so you must opt in:

1. Enable **"Register this key with an agent public key"** (the checkbox in the
   create dialog — it's unchecked by default; without it you get a plain API key
   and **no** private-key PEM, which is not enough for managed mode).
2. Choose **"Generate keypair (recommended)"**. The dashboard then generates an
   Ed25519 keypair **in your browser** (the private key never reaches our
   servers), registers the **public** key to your account (the platform signs a
   registration record bound to its fingerprint), and shows you the
   **private-key PEM once** — download it then.
3. Copy the **API key** and that **private-key PEM**.

Paste both into the setup form (or set `SEQUESIGN_API_KEY` and
`SEQUESIGN_AGENT_PRIVATE_KEY`). Reuse them across installs and machines — you do
**not** make a new key each time.

**Bring your own key (advanced).** Instead of "Generate keypair", you can pick
**"Bring your own public key (advanced)"** and paste the **public** PEM of a key
you generated yourself (e.g. in an HSM). You hold the private key; the platform
records the public half. Fully supported in managed mode.

> The broker accepts **only** the agent key your API key is registered to —
> whether the dashboard generated it or you brought your own. An **unregistered**
> key (generated locally and never registered) is rejected
> (`agent_public_key_not_registered`). That's the rule: the key must be on file
> against your API key, and that binding happens at API-key creation.

Verifying the broker-stored receipt then shows a **registered** agent identity
(see the `receiptUrl` verify path below).

### Direct mode — self-asserted identity

Direct mode has no account and no registration. The agent key only proves
*continuity* (the same signer produced these receipts), not a platform-vouched
identity. Two choices:

- **Leave the key blank** → the server mints a fresh ephemeral key per session.
  Good for quick, one-off, anonymous-but-verifiable receipts; each receipt has a
  different `self_asserted` key.
- **Paste a fixed PEM** → one stable identity reused across sessions. Any
  Ed25519 PKCS#8 PEM works (e.g. the one the dashboard can generate for you, or
  `openssl genpkey -algorithm ed25519`). It stays `self_asserted` **unless** that
  key is the one registered to your `SEQUESIGN_API_KEY`: in that case the witness
  (which authenticates the same key) confirms the match and the receipt verifies
  as a **registered** identity — direct signing *and* a registered identity. (The
  witness also rejects signing under a key that isn't the one registered to your
  API key, so an API key can't mint receipts under an unregistered key.)

## Usage

Add it to an MCP client (e.g. Claude Desktop) as a stdio server:

```json
{
  "mcpServers": {
    "sequesign": {
      "command": "npx",
      "args": ["-y", "@sequesign/mcp"],
      "env": {
        "SEQUESIGN_MODE": "direct"
      }
    }
  }
}
```

Or run it directly:

```sh
npm install -g @sequesign/mcp
sequesign-mcp
```

## Example prompts

Drop these into any MCP-capable agent (Claude Desktop, etc.) once the server is
configured. They're written the way you'd actually ask — the agent picks the
tools.

**1. Record and seal a single piece of work, then verify it.**

> Using Sequesign, open a session for task `q3-refund-review` delegated by
> `ops@acme.example`, record an action `refund_approved` with the evidence
> `{ "invoice": "INV-2231", "amount_usd": 480, "reason": "duplicate charge" }`,
> then finalize the receipt and verify it. Tell me the package directory and
> whether it verified.

Exercises `start_session` → `record_action` → `finalize` → `verify` (the local
integrity self-check).

**2. Multi-party: one agent records, two others attest after the fact.**

> The receipt at `<packageDirectory>` is already sealed. Have Sequesign attach
> an approval to it as `cfo@acme.example` (a human reviewer), then attach a
> counterparty confirmation as `vendor-globex` for the `refund_approved` action
> with purpose `refund_amount_confirmation`. Then verify the package and show me
> the approval and counterparty legs.

Exercises `approve_receipt` and `countersign_receipt` (deferred satellites bound
to an already-finalized receipt), then `verify`. A *different* party — even a
different model on another machine that has the package — can run these.

**3. Verify the broker-stored, registered-identity copy (managed mode).**

> I finalized a managed-mode receipt; its `receipt_url` is `<receipt_url>` and
> the local package is at `<packageDirectory>`. Use Sequesign to verify the
> stored receipt against my package and tell me whether it shows external trust
> and a registered agent identity.

Exercises `verify` with `receiptUrl` — fetches the authoritative stored
envelope (carrying the registered `agent_identity_attestation`), auto-fetches
the published witness + registration anchors, and reports `external` trust plus
the `registered` identity.

## Example flow

1. `sequesign_start_session` → `{ taskId, delegatorId, policyContext }` → returns `sessionId`.
2. `sequesign_record_action` → `{ sessionId, actionType, evidence }` → returns `actionId`.
3. (optional) `sequesign_record_counterparty_attestation` → `{ sessionId, counterpartyId, attestedActionId, attestationPurpose }`.
4. (optional) `sequesign_record_approval` → `{ sessionId, approverId, approvedActionType, approvalContext }`.
5. `sequesign_finalize` → `{ sessionId }` → returns the package directory + verification summary.
6. `sequesign_verify` → `{ packageDirectory }` → re-verify offline any time.

## License

Apache-2.0
