import { createHash } from "node:crypto"
import path from "node:path"
import type { Event, OpencodeClient } from "@opencode-ai/sdk"
import type { Hooks, Plugin } from "@opencode-ai/plugin"
import { BridgeClient } from "./bridge/client.js"
import { loadConfig, resolveReviewer } from "./config/loader.js"
import { sessionCoordinator } from "./coordination/session.js"
import { loadSessionState, updateSessionState, type SessionState } from "./coordination/state.js"
import { repoReviewCoordinator } from "./locking/repository-lock.js"
import { createLogger } from "./logging/logger.js"
import { safeHandler } from "./lifecycle/safe-handler.js"
import { ReviewClient, ReviewFailure } from "./review/client.js"
import { feedbackMarker, formatFeedback, hasFeedbackMarker } from "./review/feedback.js"
type UnknownRecord = Record<string, unknown>
type ToolAfterInput = { tool: string; sessionID: string; callID: string; args: unknown }
type ToolAfterOutput = { title: string; output: string; metadata: unknown }
type IdleEvent = { sessionID: string }
type SessionInfo = { id?: string; parentID?: string; title?: string; directory?: string }

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

async function promptAsync(client: OpencodeClient, sessionID: string, directory: string, model: { providerID: string; modelID: string }, text: string): Promise<void> {
  const prompt = client.session.promptAsync as unknown as (options: unknown) => Promise<unknown>
  await prompt.call(client.session, { path: { id: sessionID }, query: { directory }, body: { model, parts: [{ type: "text", text }] } })
}

const SecurityGuidance: Plugin = async ({ client, directory, worktree }) => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..")
  const loaded = loadConfig(worktree || directory)
  const config = loaded.config
  const log = createLogger(config.debug)
  if (loaded.diagnostic) log("config", { errorKind: "invalid_config" })
  log("loaded", { enabled: config.enabled, debug: config.debug })
  const bridge = new BridgeClient(root)
  const review = new ReviewClient(client, bridge, config)

  async function capturePrompt(sessionID: string, model: UnknownRecord | undefined, parts: unknown): Promise<void> {
    await sessionCoordinator(sessionID).enqueue(async () => {
      const state = loadSessionState(sessionID)
      const providerID = stringField(model, "providerID")
      const modelID = stringField(model, "modelID")
      if (providerID || modelID) state.parentModel = { providerID, modelID }
      if (hasFeedbackMarker(parts)) {
        state.syntheticFeedback = true
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
      state.stopFireCount = 0
      state.reviewGeneration = 0
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
      let baselineContent: string | undefined
      try { baselineContent = bridge.call<{ content?: string }>("git.baselineContent", { cwd: worktree || directory, baselineSha: state.baselineSha, path: paths[0] }).content } catch { /* no baseline is fail-open */ }
      const result = bridge.call<{ matches: Array<{ ruleName: string; reminder: string }> }>("pattern.scan", { cwd: worktree || directory, path: paths[0], content, baselineContent })
      const fresh = result.matches.filter(match => {
        const key = `${input.sessionID}:${input.callID}:${paths[0]}:${match.ruleName}`
        if (state.warningKeys.includes(key)) return false
        state.warningKeys.push(key)
        return true
      })
      if (fresh.length > 0) {
        output.output += `\n\n${fresh.map(match => `${feedbackMarker()} ${match.reminder}`).join("\n\n")}`
        updateSessionState(input.sessionID, next => Object.assign(next, state))
      }
    })
  }

  async function reviewDiff(sessionID: string, targetDirectory: string, parentID?: string, agentic = false): Promise<void> {
    await sessionCoordinator(sessionID).enqueue(async () => {
      const state = loadSessionState(sessionID)
      if (!config.enabled || !config.stopReview || state.stopFireCount >= 3) return
      if (state.syntheticFeedback) {
        updateSessionState(sessionID, next => { next.syntheticFeedback = false })
        return
      }
      const prep = bridge.call<{ repoRoot?: string; diff?: string; diffFiles?: Array<[string, string]> }>("git.reviewSet", { cwd: targetDirectory, baselineSha: state.baselineSha, headAtCapture: state.headAtCapture, untrackedAtBaseline: state.untrackedAtBaseline })
      if (!prep.repoRoot || !prep.diff || !prep.diffFiles || prep.diffFiles.length === 0) return
      const diffHash = hash(prep.diff)
      if (state.reviewedDiffHash === diffHash) return
      state.stopFireCount += 1
      updateSessionState(sessionID, next => Object.assign(next, state))
      try {
        const result = await review.run({ sessionID, directory: targetDirectory, repoRoot: prep.repoRoot, diffFiles: prep.diffFiles, parentModel: sessionModel(state), agentic })
        state.reviewedDiffHash = diffHash
        updateSessionState(sessionID, next => Object.assign(next, state))
        if (result.findings.length > 0) await queueFeedback(parentID || sessionID, targetDirectory, state, result.findings)
      } catch (error) {
        const failure = error instanceof ReviewFailure ? error : new ReviewFailure("unknown", "review failed")
        log("review", { sessionID, errorKind: failure.kind })
        // Crucially, no reviewed hash or SHA is advanced on failure.
      }
    })
  }

  async function queueFeedback(sessionID: string, targetDirectory: string, state: SessionState, findings: Array<Record<string, unknown>>): Promise<void> {
    const model = sessionModel(state)
    if (!model?.providerID || !model.modelID) return
    state.syntheticFeedback = true
    state.reviewGeneration += 1
    updateSessionState(sessionID, next => Object.assign(next, state))
    try { await promptAsync(client, sessionID, targetDirectory, { providerID: model.providerID, modelID: model.modelID }, formatFeedback(findings)) }
    catch (error) { log("feedback", { sessionID, errorKind: error instanceof Error ? error.name : "unknown" }) }
  }

  async function commitOrPush(input: ToolAfterInput, output: ToolAfterOutput): Promise<void> {
    const command = stringField(input.args, "command") || ""
    const lower = command.toLowerCase()
    const isCommit = /(?:^|[;&|])\s*(?:env\s+)?(?:git|gt)\b[^;&|]*(?:commit|create|modify)\b/.test(lower)
    const isPush = /(?:^|[;&|])\s*(?:env\s+)?(?:git|gt)\b[^;&|]*(?:push|submit)\b/.test(lower)
    if (!isCommit && !isPush) return
    if (isCommit && !config.commitReview) return
    if (isPush && !config.pushReview) return
    await sessionCoordinator(input.sessionID).enqueue(async () => {
      const outputText = commandOutput(output)
      const data = isCommit
        ? bridge.call<{ repoRoot?: string; shas?: string[]; diffFiles?: Array<[string, string]> }>("git.commitData", { cwd: worktree || directory, command, output: outputText })
        : bridge.call<{ repoRoot?: string; shas?: string[]; tail?: string[]; diffFiles?: Array<[string, string]>; base?: string; alreadyReviewed?: boolean }>("git.pushData", { cwd: worktree || directory, output: outputText })
      const pushData = data as unknown as { repoRoot?: string; shas?: string[]; tail?: string[]; diffFiles?: Array<[string, string]>; base?: string; alreadyReviewed?: boolean }
      if (!pushData.repoRoot) return
      const shas = isCommit ? (pushData.shas || []) : (pushData.tail || [])
      if (isPush && pushData.alreadyReviewed) return
      if (shas.length === 0) return
      const coordinator = repoReviewCoordinator(pushData.repoRoot)
      const outcome = await coordinator.enqueue(async () => {
        const findings = data.diffFiles && data.diffFiles.length > 0
          ? (await review.run({ sessionID: input.sessionID, directory: worktree || directory, repoRoot: pushData.repoRoot as string, diffFiles: data.diffFiles, parentModel: loadSessionState(input.sessionID).parentModel, agentic: isCommit })).findings
          : []
        bridge.call("git.markReviewed", { repoRoot: pushData.repoRoot, shas, findings: findings.length })
        return findings
      }).catch(error => {
        log(isCommit ? "commit_review" : "push_review", { sessionID: input.sessionID, errorKind: error instanceof ReviewFailure ? error.kind : "workflow_error" })
        return [] as Array<Record<string, unknown>>
      })
      if (outcome.length > 0) await queueFeedback(input.sessionID, worktree || directory, loadSessionState(input.sessionID), outcome)
    })
  }

  async function idle(event: IdleEvent): Promise<void> {
    if (!config.enabled) return
    const info = await sessionInfo(client, event.sessionID, worktree || directory)
    if (info.title?.startsWith("security-guidance reviewer")) return
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
    "chat.message": safeHandler("chat_hook", async (input, output) => { await capturePrompt(input.sessionID, input.model, output.parts) }, config.debug),
    "tool.execute.before": safeHandler("tool_before_hook", async () => {}, config.debug),
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
