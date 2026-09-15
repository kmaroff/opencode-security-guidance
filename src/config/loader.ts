import { existsSync, readFileSync } from "node:fs"
import path from "node:path"
import { securityConfigDir } from "../paths/xdg.js"
import { DEFAULT_CONFIG, type ReviewerConfig, type SecurityGuidanceConfig } from "./types.js"

type UnknownRecord = Record<string, unknown>

function object(value: unknown, source: string): UnknownRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${source} must be an object`)
  }
  return value as UnknownRecord
}

function parseFile(file: string): UnknownRecord | null {
  if (!existsSync(file)) return null
  try {
    const value: unknown = JSON.parse(readFileSync(file, "utf8"))
    if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("config must be an object")
    return value as UnknownRecord
  } catch (error) {
    throw new Error(`invalid security-guidance config ${file}: ${error instanceof Error ? error.message : "parse error"}`)
  }
}

function validate(value: UnknownRecord, source: string): Partial<SecurityGuidanceConfig> {
  const allowed = new Set(["enabled", "patterns", "stopReview", "commitReview", "pushReview", "reviewer", "debug"])
  for (const key of Object.keys(value)) if (!allowed.has(key)) throw new Error(`unknown config field ${source}:${key}`)
  const result: Partial<SecurityGuidanceConfig> = {}
  for (const key of ["enabled", "patterns", "stopReview", "commitReview", "pushReview", "debug"] as const) {
    if (key in value && typeof value[key] !== "boolean") throw new Error(`${source}:${key} must be boolean`)
    if (key in value) result[key] = value[key] as boolean
  }
  if ("reviewer" in value) {
    const reviewer = object(value.reviewer, `${source}:reviewer`)
    for (const key of Object.keys(reviewer)) if (!["provider", "model", "inheritParent"].includes(key)) throw new Error(`unknown config field ${source}:reviewer.${key}`)
    for (const key of ["provider", "model"] as const) if (key in reviewer && typeof reviewer[key] !== "string") throw new Error(`${source}:reviewer.${key} must be string`)
    if ("inheritParent" in reviewer && typeof reviewer.inheritParent !== "boolean") throw new Error(`${source}:reviewer.inheritParent must be boolean`)
    result.reviewer = {
      ...(typeof reviewer.provider === "string" ? { provider: reviewer.provider } : {}),
      ...(typeof reviewer.model === "string" ? { model: reviewer.model } : {}),
      ...(typeof reviewer.inheritParent === "boolean" ? { inheritParent: reviewer.inheritParent } : {}),
    }
  }
  return result
}

export function loadConfig(worktree: string): { config: SecurityGuidanceConfig; diagnostic?: string } {
  const files = [
    path.join(securityConfigDir(), "config.json"),
    path.join(worktree, ".opencode", "security-guidance.json"),
    path.join(worktree, ".opencode", "security-guidance.local.json"),
  ]
  let config: SecurityGuidanceConfig = { ...DEFAULT_CONFIG, reviewer: { ...DEFAULT_CONFIG.reviewer } }
  try {
    for (const file of files) {
      const raw = parseFile(file)
      if (!raw) continue
      const next = validate(raw, file)
      config = { ...config, ...next, reviewer: { ...config.reviewer, ...(next.reviewer ?? {}) } }
    }
    return { config }
  } catch (error) {
    return { config: { ...config, enabled: false }, diagnostic: error instanceof Error ? error.message : "invalid configuration" }
  }
}

export function resolveReviewer(config: SecurityGuidanceConfig, parent?: { providerID?: string; modelID?: string }): { providerID: string; modelID: string } | null {
  const providerID = config.reviewer.provider
  const modelID = config.reviewer.model
  if (providerID && modelID) return { providerID, modelID }
  if (config.reviewer.inheritParent && parent?.providerID && parent.modelID) return { providerID: parent.providerID, modelID: parent.modelID }
  return null
}
