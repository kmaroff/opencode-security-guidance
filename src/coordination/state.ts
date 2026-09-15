import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs"
import path from "node:path"
import { securityStateDir } from "../paths/xdg.js"

export type FeedbackStatus = "none" | "pending" | "enqueued" | "consumed" | "failed"

export type ReviewerSessionRecord = {
  parentID: string
  generation: number
}

export type GitOperationState = {
  kind: "commit" | "push"
  repoRoot?: string
  preHead?: string
  localRef?: string
  remoteRef?: string
}

export type SessionState = {
  baselineSha?: string
  headAtCapture?: string
  untrackedAtBaseline?: Record<string, number>
  touchedPaths: string[]
  warningKeys: string[]
  reviewedDiffHash?: string
  reviewStatus: "idle" | "succeeded" | "failed"
  reviewFailureKind?: string
  failedDiffHash?: string
  reviewRetryCount: number
  reviewGeneration: number
  syntheticFeedback: boolean
  feedbackStatus: FeedbackStatus
  feedbackRetryCount: number
  pendingSyntheticMessageID?: string
  pendingFeedbackFindings: Array<Record<string, unknown>>
  stopFireCount: number
  lastIdleFingerprint?: string
  parentID?: string
  parentModel?: { providerID?: string; modelID?: string }
  reviewerSessions: Record<string, ReviewerSessionRecord>
  pendingGitOperations: Record<string, GitOperationState>
}

const EMPTY: SessionState = {
  touchedPaths: [],
  warningKeys: [],
  reviewStatus: "idle",
  reviewRetryCount: 0,
  reviewGeneration: 0,
  syntheticFeedback: false,
  feedbackStatus: "none",
  feedbackRetryCount: 0,
  pendingFeedbackFindings: [],
  stopFireCount: 0,
  reviewerSessions: {},
  pendingGitOperations: {},
}

function filename(sessionID: string): string {
  const safe = sessionID.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 128)
  return path.join(securityStateDir(), `session-${safe}.json`)
}

export function loadSessionState(sessionID: string): SessionState {
  try {
    const value = JSON.parse(readFileSync(filename(sessionID), "utf8")) as Partial<SessionState>
    const feedbackStatus = ["none", "pending", "enqueued", "consumed", "failed"].includes(value.feedbackStatus as string)
      ? value.feedbackStatus as FeedbackStatus
      : "none"
    const reviewStatus = ["idle", "succeeded", "failed"].includes(value.reviewStatus as string)
      ? value.reviewStatus as SessionState["reviewStatus"]
      : "idle"
    return {
      ...EMPTY,
      ...value,
      reviewStatus,
      feedbackStatus,
      reviewRetryCount: Number.isInteger(value.reviewRetryCount) && (value.reviewRetryCount as number) >= 0 ? value.reviewRetryCount as number : 0,
      feedbackRetryCount: Number.isInteger(value.feedbackRetryCount) && (value.feedbackRetryCount as number) >= 0 ? value.feedbackRetryCount as number : 0,
      reviewGeneration: Number.isInteger(value.reviewGeneration) && (value.reviewGeneration as number) >= 0 ? value.reviewGeneration as number : 0,
      stopFireCount: Number.isInteger(value.stopFireCount) && (value.stopFireCount as number) >= 0 ? value.stopFireCount as number : 0,
      touchedPaths: Array.isArray(value.touchedPaths) ? value.touchedPaths.filter((item): item is string => typeof item === "string").slice(0, 200) : [],
      warningKeys: Array.isArray(value.warningKeys) ? value.warningKeys.filter((item): item is string => typeof item === "string").slice(0, 500) : [],
      pendingFeedbackFindings: Array.isArray(value.pendingFeedbackFindings) ? value.pendingFeedbackFindings.filter(item => item !== null && typeof item === "object").slice(0, 50) as Array<Record<string, unknown>> : [],
      reviewerSessions: value.reviewerSessions && typeof value.reviewerSessions === "object" && !Array.isArray(value.reviewerSessions) ? value.reviewerSessions : {},
      pendingGitOperations: value.pendingGitOperations && typeof value.pendingGitOperations === "object" && !Array.isArray(value.pendingGitOperations) ? value.pendingGitOperations : {},
    }
  } catch { return { ...EMPTY, touchedPaths: [], warningKeys: [] } }
}

export function saveSessionState(sessionID: string, state: SessionState): boolean {
  try {
    const file = filename(sessionID)
    mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 })
    const temp = `${file}.${process.pid}.tmp`
    writeFileSync(temp, JSON.stringify(state), { mode: 0o600 })
    renameSync(temp, file)
    return true
  } catch { /* state persistence is fail-open; no false reviewed state follows */ return false }
}

export function updateSessionState(sessionID: string, update: (state: SessionState) => void): SessionState {
  const state = loadSessionState(sessionID)
  update(state)
  saveSessionState(sessionID, state)
  return state
}
