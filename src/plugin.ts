import { createHash, randomUUID } from "node:crypto"
import { fileURLToPath } from "node:url"
import path from "node:path"
import type { Event, OpencodeClient } from "@opencode-ai/sdk"
import type { Hooks, Plugin } from "@opencode-ai/plugin"
import { BridgeClient } from "./bridge/client.js"
import { loadConfig } from "./config/loader.js"
import { sessionCoordinator } from "./coordination/session.js"
import { loadSessionState, saveSessionState, updateSessionState, type SessionState } from "./coordination/state.js"
import { repoReviewCoordinator } from "./locking/repository-lock.js"
import { createLogger } from "./logging/logger.js"
import { safeHandler } from "./lifecycle/safe-handler.js"
import { ReviewClient, ReviewFailure } from "./review/client.js"
import { feedbackMarker, formatFeedback } from "./review/feedback.js"
type UnknownRecord = Record<string, unknown>
type ToolAfterInput = { tool: string; sessionID: string; callID: string; args: unknown }
type ToolAfterOutput = { title: string; output: string; metadata: unknown }
type IdleEvent = { sessionID: string }
type SessionInfo = { id?: string; parentID?: string; title?: string; directory?: string }

const MAX_REVIEW_RETRIES = 3
const MAX_FEEDBACK_RETRIES = 3
const REVIEW_TIMEOUT_MS = 120_000

function record(value: unknown): UnknownRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as UnknownRecord : {}
}

function textParts(parts: unknown): string {
  if (!Array.isArray(parts)) return ""
  return parts.filter(part => record(part).type === "text").map(part => {
    const text = record(part).text
    return typeof text === "string" ? text : ""
  }).join("\n")
}

function unwrap(value: unknown): unknown {
  const body = record(value)
  return "data" in body ? body.data : value
}

function stringField(value: unknown, ...keys: string[]): string | undefined {
  const body = record(value)
  for (const key of keys) if (typeof body[key] === "string" && body[key]) return body[key] as string
  return undefined
}

function listPaths(value: unknown): string[] {
  const body = record(value)
  const result: string[] = []
  for (const key of ["path", "filePath", "file_path", "filename"]) {
    if (typeof body[key] === "string" && body[key]) result.push(body[key] as string)
  }
  for (const key of ["files", "paths"]) {
    if (!Array.isArray(body[key])) continue
    for (const item of body[key]) {
      if (typeof item === "string") result.push(item)
      else {
        const file = stringField(item, "path", "file", "filePath")
        if (file) result.push(file)
      }
    }
  }
  for (const key of ["patchText", "patch", "diff"]) {
    if (typeof body[key] !== "string") continue
    const source = body[key] as string
    const patchPaths = /(?:\*\*\* (?:Add|Update|Delete) File:\s*|diff --git a\/)([^\s\n]+)/g
    for (const match of source.matchAll(patchPaths)) if (match[1]) result.push(match[1])
  }
  return [...new Set(result)]
}

function contentField(value: unknown): string | undefined {
  const body = record(value)
  for (const key of ["content", "newString", "new_string", "patchText", "patch", "diff"]) {
    if (typeof body[key] === "string" && body[key]) return body[key] as string
  }
  return undefined
}

function absolutePath(file: string, directory: string): string {
  return path.isAbsolute(file) ? path.normalize(file) : path.resolve(directory, file)
}
function exitCode(metadata: unknown): number | undefined {
  const value = record(metadata)
  for (const key of ["exitCode", "exit_code", "status"]) {
    if (typeof value[key] === "number" && Number.isInteger(value[key])) return value[key] as number
  }
  return undefined
}

function commandFrom(args: unknown): string {
  return stringField(args, "command") || ""
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => { timer = setTimeout(() => reject(new ReviewFailure("review_timeout", "security review timed out")), timeoutMs) }),
    ])
  } finally {
    clearTimeout(timer)
  }
}

function commandOutput(output: ToolAfterOutput): string {
  const metadata = record(output.metadata)
  return [output.output, stringField(metadata, "stdout", "output"), stringField(metadata, "stderr")].filter(Boolean).join("\n")
}

function hash(value: string): string {
  return createHash("sha256").update(value).digest("hex")
}

function isAssistantError(messages: unknown): boolean {
  if (!Array.isArray(messages) || messages.length === 0) return false
  const last = record(record(messages[messages.length - 1]).info)
  return last.role === "assistant" && Boolean(last.error)
}

function sessionModel(state: SessionState): { providerID?: string; modelID?: string } | undefined {
  return state.parentModel
}

async function sessionInfo(client: OpencodeClient, sessionID: string, directory: string): Promise<SessionInfo> {
  const value = unwrap(await client.session.get({ path: { id: sessionID }, query: { directory } }))
  const body = record(value)
  return { id: typeof body.id === "string" ? body.id : undefined, parentID: typeof body.parentID === "string" ? body.parentID : undefined, title: typeof body.title === "string" ? body.title : undefined, directory: typeof body.directory === "string" ? body.directory : undefined }
}

async function promptAsync(
  client: OpencodeClient,
  sessionID: string,
  directory: string,
  model: { providerID: string; modelID: string },
  text: string,
  messageID: string,
): Promise<void> {
  const prompt = client.session.promptAsync as unknown as (options: unknown) => Promise<unknown>
  await prompt.call(client.session, { path: { id: sessionID }, query: { directory }, body: { messageID, model, parts: [{ type: "text", text }] } })
}

const SecurityGuidance: Plugin = async ({ client, directory, worktree }) => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
  const loaded = loadConfig(worktree || directory)
  const config = loaded.config
  const log = createLogger(config.debug)
  if (loaded.diagnostic) {
    log("config", { errorKind: "invalid_config" })
    console.error("Security guidance plugin disabled: invalid configuration.")
  }
  log("loaded", { enabled: config.enabled, debug: config.debug })
  const bridge = new BridgeClient(root)
  const review = new ReviewClient(client, bridge, config)

  async function capturePrompt(sessionID: string, messageID: string | undefined, model: UnknownRecord | undefined, parts: unknown): Promise<void> {
    await sessionCoordinator(sessionID).enqueue(async () => {
      const state = loadSessionState(sessionID)
      const providerID = stringField(model, "providerID")
      const modelID = stringField(model, "modelID")
      if (providerID || modelID) state.parentModel = { providerID, modelID }
      if (["pending", "enqueued"].includes(state.feedbackStatus) && state.pendingSyntheticMessageID && messageID === state.pendingSyntheticMessageID) {
        state.feedbackStatus = "consumed"
        state.syntheticFeedback = false
        state.pendingSyntheticMessageID = undefined
        state.pendingFeedbackFindings = []
        updateSessionState(sessionID, next => Object.assign(next, state))
        return
      }
      if (!config.enabled) return
      const capture = bridge.call<{ baselineSha?: string; headAtCapture?: string; untrackedAtBaseline?: Record<string, number> }>("git.capture", { cwd: worktree || directory })
      state.baselineSha = capture.baselineSha
      state.headAtCapture = capture.headAtCapture
      state.untrackedAtBaseline = capture.untrackedAtBaseline || {}
      state.touchedPaths = []
      state.warningKeys = []
      state.reviewedDiffHash = undefined
      state.reviewStatus = "idle"
      state.reviewFailureKind = undefined
      state.failedDiffHash = undefined
      state.reviewRetryCount = 0
      state.stopFireCount = 0
      if (state.feedbackStatus === "consumed") {
        state.feedbackStatus = "none"
        state.pendingFeedbackFindings = []
      }
      state.syntheticFeedback = false
      updateSessionState(sessionID, next => Object.assign(next, state))
    })
  }
  async function patternAfter(input: ToolAfterInput, output: ToolAfterOutput): Promise<void> {
    if (!config.enabled) return
    const tool = input.tool.toLowerCase()
    const args = record(input.args)
    const metadata = record(output.metadata)
    const edit = ["write", "edit", "multiedit", "apply_patch", "patch"].includes(tool)
    const paths = [...new Set([...listPaths(args), ...listPaths(metadata)])].map(file => absolutePath(file, worktree || directory))
    if (!edit || paths.length === 0) return
    await sessionCoordinator(input.sessionID).enqueue(async () => {
      const state = loadSessionState(input.sessionID)
      for (const file of paths) if (!state.touchedPaths.includes(file)) state.touchedPaths.push(file)
      updateSessionState(input.sessionID, next => Object.assign(next, state))
      if (!config.patterns) return
      const content = contentField(args) || output.output || ""
      const fresh: Array<{ ruleName: string; reminder: string }> = []
      for (const file of paths) {
        let baselineContent: string | undefined
        try {
          baselineContent = bridge.call<{ content?: string }>("git.baselineContent", { cwd: worktree || directory, baselineSha: state.baselineSha, path: file }).content
        } catch { /* absence of a baseline is fail-open for pattern warnings */ }
        const result = bridge.call<{ matches: Array<{ ruleName: string; reminder: string }> }>("pattern.scan", { cwd: worktree || directory, path: file, content, baselineContent })
        for (const match of result.matches) {
          const key = `${input.sessionID}:${input.callID}:${file}:${match.ruleName}`
          if (!state.warningKeys.includes(key)) {
            state.warningKeys.push(key)
            fresh.push(match)
          }
        }
      }
      if (fresh.length > 0) {
        output.output += `\n\n${fresh.map(match => `${feedbackMarker()} ${match.reminder}`).join("\n\n")}`
        updateSessionState(input.sessionID, next => Object.assign(next, state))
      }
    })
  }

  async function reviewDiff(sessionID: string, targetDirectory: string, parentID?: string, agentic = false): Promise<void> {
    await sessionCoordinator(sessionID).enqueue(async () => {
      const state = loadSessionState(sessionID)
      if (!config.enabled || !config.stopReview) return
      if (state.feedbackStatus === "enqueued") return
      if (state.feedbackStatus === "failed" && state.pendingFeedbackFindings.length > 0) {
        if (state.feedbackRetryCount >= MAX_FEEDBACK_RETRIES) {
          console.error("Security review findings could not be delivered.")
          return
        }
        await queueFeedback(sessionID, targetDirectory, state, state.pendingFeedbackFindings)
        return
      }
      if (state.reviewStatus !== "failed" && state.stopFireCount >= 3) return
      if (state.reviewStatus === "failed" && state.reviewRetryCount >= MAX_REVIEW_RETRIES) {
        console.error("Security review could not be completed.")
        return
      }
      let currentDiffHash: string | undefined
      try {
        const prep = bridge.call<{ repoRoot?: string; diff?: string; diffFiles?: Array<[string, string]>; diffAvailable?: boolean; diffStatus?: string }>("git.reviewSet", { cwd: targetDirectory, baselineSha: state.baselineSha, headAtCapture: state.headAtCapture, untrackedAtBaseline: state.untrackedAtBaseline })
        if (!prep.repoRoot || !prep.diff || !prep.diffFiles || prep.diffFiles.length === 0) return
        currentDiffHash = hash(prep.diff)
        if (state.reviewedDiffHash === currentDiffHash && state.reviewStatus === "succeeded") return
        state.stopFireCount += 1
        updateSessionState(sessionID, next => Object.assign(next, state))
        const result = await withTimeout(review.run({
          sessionID,
          directory: targetDirectory,
          repoRoot: prep.repoRoot,
          diffFiles: prep.diffFiles,
          parentModel: sessionModel(state),
          agentic,
          registerReviewerSession: (reviewerSessionID, generation) => {
            updateSessionState(sessionID, next => {
              next.reviewerSessions[reviewerSessionID] = { parentID: sessionID, generation }
            })
          },
        }), REVIEW_TIMEOUT_MS)
        state.reviewedDiffHash = currentDiffHash
        state.reviewStatus = "succeeded"
        state.reviewFailureKind = undefined
        state.failedDiffHash = undefined
        state.reviewRetryCount = 0
        updateSessionState(sessionID, next => Object.assign(next, state))
        if (result.findings.length > 0) await queueFeedback(parentID || sessionID, targetDirectory, state, result.findings)
      } catch (error) {
        const details = record(error)
        const failure = error instanceof ReviewFailure
          ? error
          : new ReviewFailure(typeof details.kind === "string" ? details.kind : "unknown", error instanceof Error ? error.message : "review failed")
        state.reviewStatus = "failed"
        state.reviewFailureKind = failure.kind
        state.failedDiffHash = currentDiffHash
        state.reviewRetryCount += 1
        updateSessionState(sessionID, next => Object.assign(next, state))
        log("review", { sessionID, errorKind: failure.kind })
        if (state.reviewRetryCount >= MAX_REVIEW_RETRIES) console.error("Security review could not be completed.")
      }
    })
  }

  async function queueFeedback(sessionID: string, targetDirectory: string, state: SessionState, findings: Array<Record<string, unknown>>): Promise<void> {
    const model = sessionModel(state)
    if (!model?.providerID || !model.modelID) return
    const messageID = randomUUID()
    const attempt = state.feedbackRetryCount + 1
    state.syntheticFeedback = true
    state.feedbackStatus = "pending"
    state.pendingSyntheticMessageID = messageID
    state.pendingFeedbackFindings = findings.slice(0, 50)
    state.reviewGeneration += 1
    if (!saveSessionState(sessionID, state)) {
      log("feedback", { sessionID, errorKind: "state_persist_failed" })
      return
    }
    try {
      await promptAsync(client, sessionID, targetDirectory, { providerID: model.providerID, modelID: model.modelID }, formatFeedback(findings).slice(0, 64_000), messageID)
      updateSessionState(sessionID, next => {
        next.feedbackStatus = "enqueued"
        next.feedbackRetryCount = attempt
      })
    } catch (error) {
      updateSessionState(sessionID, next => {
        next.feedbackStatus = "failed"
        next.feedbackRetryCount = attempt
      })
      log("feedback", { sessionID, errorKind: error instanceof Error ? error.name : "unknown" })
      if (attempt >= MAX_FEEDBACK_RETRIES) console.error("Security review findings could not be delivered.")
    }
  }

  async function commitOrPush(input: ToolAfterInput, output: ToolAfterOutput): Promise<void> {
    const command = commandFrom(input.args)
    const lower = command.toLowerCase()
    const isCommit = /(?:^|[;&|])\s*(?:env\s+)?(?:git|gt)\b[^;&|]*(?:commit|create|modify)\b/.test(lower)
    const isPush = /(?:^|[;&|])\s*(?:env\s+)?(?:git|gt)\b[^;&|]*(?:push|submit)\b/.test(lower)
    if (!isCommit && !isPush) return
    if (isCommit && !config.commitReview) return
    if (isPush && !config.pushReview) return
    await sessionCoordinator(input.sessionID).enqueue(async () => {
      const state = loadSessionState(input.sessionID)
      const before = state.pendingGitOperations[input.callID]
      delete state.pendingGitOperations[input.callID]
      updateSessionState(input.sessionID, next => Object.assign(next, state))
      try {
        const outputText = commandOutput(output)
        const request = {
          cwd: worktree || directory,
          command,
          output: outputText,
          beforeHead: before?.preHead,
          exitCode: exitCode(output.metadata),
          interrupted: Boolean(record(output.metadata).interrupted),
        }
        const data: {
          repoRoot?: string
          shas?: string[]
          tail?: string[]
          diffFiles?: Array<[string, string]>
          base?: string
          alreadyReviewed?: boolean
          diffStatus?: string
          diffAvailable?: boolean
        } = isCommit
          ? bridge.call("git.commitData", request)
          : bridge.call("git.pushData", request)
        const shas = isCommit ? (data.shas || []) : (data.tail || [])
        if (!data.repoRoot || shas.length === 0 || (!isCommit && data.alreadyReviewed)) return
        const coordinator = repoReviewCoordinator(data.repoRoot)
        const outcome = await coordinator.enqueue(async () => {
          let findings: Array<Record<string, unknown>> = []
          if (data.diffStatus !== "VALID_EMPTY_DIFF") {
            findings = (await withTimeout(review.run({
              sessionID: input.sessionID,
              directory: worktree || directory,
              repoRoot: data.repoRoot as string,
              diffFiles: data.diffFiles || [],
              parentModel: loadSessionState(input.sessionID).parentModel,
              agentic: isCommit,
            }), REVIEW_TIMEOUT_MS)).findings
          }
          bridge.call("git.markReviewed", { repoRoot: data.repoRoot, shas, findings: findings.length })
          return findings
        })
        if (outcome.length > 0) await queueFeedback(input.sessionID, worktree || directory, loadSessionState(input.sessionID), outcome)
      } catch (error) {
        log(isCommit ? "commit_review" : "push_review", { sessionID: input.sessionID, errorKind: error instanceof ReviewFailure ? error.kind : "workflow_error" })
      }
    })
  }

  async function idle(event: IdleEvent): Promise<void> {
    if (!config.enabled) return
    const info = await sessionInfo(client, event.sessionID, worktree || directory)
    if (info.parentID) {
      const parent = loadSessionState(info.parentID)
      const registered = parent.reviewerSessions[event.sessionID]
      if (registered?.parentID === info.parentID) return
    }
    const statusValue = unwrap(await client.session.status({ query: { directory: worktree || directory } }))
    const status = record(statusValue)[event.sessionID]
    const statusType = record(status).type
    log("idle_state", { statusType: typeof statusType === "string" ? statusType : "missing", statusKeys: Object.keys(record(statusValue)).join(",") })
    if (statusType === "busy" || statusType === "retry") return
    const messages = unwrap(await client.session.messages({ path: { id: event.sessionID }, query: { directory: worktree || directory, limit: 50 } }))
    const fingerprint = hash(JSON.stringify({ count: Array.isArray(messages) ? messages.length : 0, last: record(record(Array.isArray(messages) ? messages[messages.length - 1] : undefined).info).id }))
    const state = loadSessionState(event.sessionID)
    if (state.lastIdleFingerprint === fingerprint) return
    updateSessionState(event.sessionID, next => { next.lastIdleFingerprint = fingerprint })
    if (isAssistantError(messages)) return
    await reviewDiff(event.sessionID, worktree || directory, info.parentID, Boolean(info.parentID))
  }

  const hooks: Hooks = {
    "chat.message": safeHandler("chat_hook", async (input, output) => { await capturePrompt(input.sessionID, input.messageID, input.model, output.parts) }, config.debug),
    "tool.execute.before": safeHandler("tool_before_hook", async (input, output) => {
      if (input.tool.toLowerCase() !== "bash") return
      const command = commandFrom(output.args)
      if (!/(?:^|[;&|])\s*(?:env\s+)?(?:git|gt)\b[^;&|]*(?:commit|create|modify|push|submit)\b/i.test(command)) return
      const operation = /(commit|create|modify)/i.test(command) ? "commit" : "push"
      const captured = bridge.call<{ repoRoot?: string; preHead?: string; localRef?: string; remoteRef?: string }>("git.operationBefore", { cwd: worktree || directory, command, operation })
      updateSessionState(input.sessionID, state => {
        state.pendingGitOperations[input.callID] = { kind: operation === "commit" ? "commit" : "push", ...captured }
      })
    }, config.debug),
    "tool.execute.after": safeHandler("tool_after_hook", async (input, output) => {
      const normalizedInput: ToolAfterInput = { tool: input.tool, sessionID: input.sessionID, callID: input.callID, args: input.args }
      const normalizedOutput: ToolAfterOutput = { title: output.title, output: output.output, metadata: output.metadata }
      await patternAfter(normalizedInput, normalizedOutput)
      output.output = normalizedOutput.output
      await commitOrPush(normalizedInput, normalizedOutput)
    }, config.debug),
    event: async ({ event }: { event: Event }) => {
      try {
        const candidate = event as unknown as { type?: string; properties?: unknown }
        if (candidate.type === "session.idle") {
          const properties = record(candidate.properties)
          log("event_seen", { eventType: candidate.type, sessionID: typeof properties.sessionID === "string" ? properties.sessionID : undefined })
          if (typeof properties.sessionID === "string") await idle({ sessionID: properties.sessionID })
        }
      } catch (error) {
        log("event", { errorKind: error instanceof Error ? error.name : "unknown" })
      }
    },
  }
  try { bridge.call("ping") } catch (error) { log("bridge", { errorKind: error instanceof Error ? error.name : "unknown" }) }
  return hooks
}

export default SecurityGuidance
