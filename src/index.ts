/**
 * aletheia-sandbox: run untrusted agent code against a frozen, read-only
 * capability — one programmable tool instead of N fixed ones, with the security
 * in the jail (V8 isolate, no ambient authority, allowlisted host calls, resource
 * + result caps, whole-run budget, replayable + result-bound receipts).
 */
export {
  runInSandbox,
  fingerprint,
  DEFAULT_LIMITS,
  type Capability,
  type HostMethod,
  type SandboxLimits,
  type Receipt,
  type ExecResult,
} from "./core/sandbox.js";

export {
  createPostgresCapability,
  classifyStatement,
  isSafeIdentifier,
  assertReadOnlyRole,
  skeleton,
  type PostgresProviderOptions,
  type Classification,
} from "./providers/postgres.js";
