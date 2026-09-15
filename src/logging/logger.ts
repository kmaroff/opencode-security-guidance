import { appendFileSync, mkdirSync, statSync, renameSync, existsSync } from "node:fs"
import path from "node:path"
import { securityLogDir } from "../paths/xdg.js"

const MAX_LOG_BYTES = 1024 * 1024
const MAX_MESSAGE = 240

type SafeFields = Record<string, string | number | boolean | undefined>

function safe(value: unknown): string {
  return String(value ?? "").replace(/[\r\n\t]/g, " ").slice(0, MAX_MESSAGE)
}

export function createLogger(debug: boolean) {
  return (operation: string, fields: SafeFields = {}): void => {
    if (!debug) return
    try {
      const dir = securityLogDir()
      mkdirSync(dir, { recursive: true, mode: 0o700 })
      const file = path.join(dir, "runtime.log")
      if (existsSync(file) && statSync(file).size > MAX_LOG_BYTES) {
        renameSync(file, `${file}.1`)
      }
      const body = Object.entries(fields)
        .filter(([, value]) => value !== undefined)
        .map(([key, value]) => `${key}=${safe(value)}`)
        .join(" ")
      appendFileSync(file, `${new Date().toISOString()} operation=${safe(operation)}${body ? ` ${body}` : ""}\n`, { mode: 0o600 })
    } catch {
      // Diagnostics must never change the OpenCode operation.
    }
  }
}
