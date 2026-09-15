import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs"
import path from "node:path"
import { securityStateDir } from "../paths/xdg.js"

export type SessionState = {
  baselineSha?: string
  headAtCapture?: string
  untrackedAtBaseline?: Record<string, number>
  touchedPaths: string[]
  warningKeys: string[]
  reviewedDiffHash?: string
  reviewGeneration: number
  syntheticFeedback: boolean
  stopFireCount: number
  lastIdleFingerprint?: string
  parentID?: string
  parentModel?: { providerID?: string; modelID?: string }
}

const EMPTY: SessionState = { touchedPaths: [], warningKeys: [], reviewGeneration: 0, syntheticFeedback: false, stopFireCount: 0 }

function filename(sessionID: string): string {
  const safe = sessionID.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 128)
  return path.join(securityStateDir(), `session-${safe}.json`)
}

export function loadSessionState(sessionID: string): SessionState {
  try {
    const value = JSON.parse(readFileSync(filename(sessionID), "utf8")) as Partial<SessionState>
    return { ...EMPTY, ...value, touchedPaths: Array.isArray(value.touchedPaths) ? value.touchedPaths : [], warningKeys: Array.isArray(value.warningKeys) ? value.warningKeys : [] }
  } catch { return { ...EMPTY, touchedPaths: [], warningKeys: [] } }
}

export function saveSessionState(sessionID: string, state: SessionState): void {
  try {
    const file = filename(sessionID)
    mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 })
    const temp = `${file}.${process.pid}.tmp`
    writeFileSync(temp, JSON.stringify(state), { mode: 0o600 })
    renameSync(temp, file)
  } catch { /* state persistence is fail-open; no false reviewed state follows */ }
}

export function updateSessionState(sessionID: string, update: (state: SessionState) => void): SessionState {
  const state = loadSessionState(sessionID)
  update(state)
  saveSessionState(sessionID, state)
  return state
}
