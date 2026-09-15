import { spawnSync } from "node:child_process"
import path from "node:path"

export type BridgeFailure = Error & { kind: string }

function failure(kind: string, message: string): BridgeFailure {
  const error = new Error(message) as BridgeFailure
  error.kind = kind
  return error
}

export class BridgeClient {
  constructor(private readonly root: string, private readonly timeoutMs = 15_000) {}

  call<T>(op: string, payload: Record<string, unknown> = {}): T {
    const python = process.env.SG_PYTHON || "python3"
    const script = path.join(this.root, "bridge", "opencode_bridge.py")
    const input = JSON.stringify({ op, ...payload })
    const child = spawnSync(python, [script], { input, encoding: "utf8", timeout: this.timeoutMs, maxBuffer: 2 * 1024 * 1024, windowsHide: true })
    if (child.error) throw failure(child.error.name === "ETIMEDOUT" ? "timeout" : "process_failure", child.error.message)
    if (child.signal) throw failure("timeout", `bridge terminated by ${child.signal}`)
    if (child.status !== 0 && !child.stdout) throw failure("process_failure", `bridge exited ${child.status ?? "unknown"}`)
    let response: unknown
    try { response = JSON.parse(child.stdout || "") } catch { throw failure("invalid_response", "bridge returned invalid protocol JSON") }
    if (!response || typeof response !== "object") throw failure("invalid_response", "bridge response is not an object")
    const record = response as Record<string, unknown>
    if (record.ok !== true) {
      const error = record.error && typeof record.error === "object" ? record.error as Record<string, unknown> : {}
      throw failure(typeof error.kind === "string" ? error.kind : "bridge_error", typeof error.message === "string" ? error.message : "bridge request failed")
    }
    return record.result as T
  }
}
