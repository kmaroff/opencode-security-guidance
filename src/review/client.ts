import type { OpencodeClient } from "@opencode-ai/sdk"
import { BridgeClient } from "../bridge/client.js"
import { type SecurityGuidanceConfig } from "../config/types.js"
import { resolveReviewer } from "../config/loader.js"
import { FINDINGS_SCHEMA, SURVIVED_SCHEMA } from "./schemas.js"
import { validateFindingsResult, validateSurvivedResult } from "./validator.js"

export class ReviewFailure extends Error {
  constructor(public readonly kind: string, message: string) { super(message) }
}

type Finding = Record<string, unknown>
type ReviewInput = {
  sessionID: string
  directory: string
  repoRoot: string
  diffFiles: Array<[string, string]>
  parentModel?: { providerID?: string; modelID?: string }
  agentic?: boolean
}

type ReviewOutput = { findings: Finding[]; reviewerSessions: string[]; model: { providerID: string; modelID: string } }

function unwrap(value: unknown): any {
  if (value && typeof value === "object" && "data" in value) return (value as { data: unknown }).data
  return value
}

function structuredFrom(response: unknown): unknown {
  const body = unwrap(response) as Record<string, unknown> | null
  const info = body?.info as Record<string, unknown> | undefined
  if (info?.error) throw new ReviewFailure("provider_error", "reviewer returned an assistant error")
  if (info?.structured !== undefined) return info.structured
  const parts = Array.isArray(body?.parts) ? body.parts : []
  for (const part of parts) {
    if (!part || typeof part !== "object") continue
    const record = part as Record<string, unknown>
    if (record.structured !== undefined) return record.structured
    const state = record.state && typeof record.state === "object" ? record.state as Record<string, unknown> : {}
    if (state.output !== undefined) return state.output
    if (state.structured !== undefined) return state.structured
  }
  throw new ReviewFailure("structured_missing", "reviewer completed without structured output")
}

export class ReviewClient {
  constructor(
    private readonly client: OpencodeClient,
    private readonly bridge: BridgeClient,
    private readonly config: SecurityGuidanceConfig,
  ) {}

  async run(input: ReviewInput): Promise<ReviewOutput> {
    const model = resolveReviewer(this.config, input.parentModel)
    if (!model) throw new ReviewFailure("reviewer_not_configured", "reviewer provider/model is not configured")
    if (input.diffFiles.length === 0) return { findings: [], reviewerSessions: [], model }
    const reviewerSessions: string[] = []
    const candidates = await this.promptReviewer(input, model, FINDINGS_SCHEMA, this.investigationPrompt(input), reviewerSessions)
    let findings = candidates.findings
    if (input.agentic && findings.length > 0) {
      const refuted = await this.promptReviewer(input, model, SURVIVED_SCHEMA, this.refutationPrompt(findings, input.diffFiles), reviewerSessions)
      const survived = new Set(refuted.survived)
      findings = findings.filter((_: Finding, index: number) => survived.has(index))
    }
    const accepted = this.bridge.call<{ findings: Finding[] }>("review.accept", { findings })
    return { findings: accepted.findings, reviewerSessions, model }
  }

  private async promptReviewer(input: ReviewInput, model: { providerID: string; modelID: string }, schema: unknown, text: string, sessions: string[]): Promise<any> {
    let child: any
    try {
      child = unwrap(await this.client.session.create({
        body: { parentID: input.sessionID, title: "security-guidance reviewer" },
        query: { directory: input.directory },
      }))
      const childID = child?.id
      if (typeof childID !== "string") throw new Error("reviewer session creation returned no id")
      sessions.push(childID)
      const response = await (this.client.session.prompt as any)({
        path: { id: childID },
        query: { directory: input.directory },
        body: {
          model,
          agent: "security-guidance-reviewer",
          tools: { bash: false, edit: false, write: false, apply_patch: false },
          parts: [{ type: "text", text }],
          format: { type: "json_schema", schema, retryCount: 2 },
        },
      })
      const structured = structuredFrom(response)
      if (schema === FINDINGS_SCHEMA) validateFindingsResult(structured)
      else validateSurvivedResult(structured)
      return structured
    } catch (error) {
      if (error instanceof ReviewFailure) throw error
      throw new ReviewFailure("session_error", error instanceof Error ? error.message : "reviewer session failed")
    }
  }

  private investigationPrompt(input: ReviewInput): string {
    const diff = input.diffFiles.map(([file, body]) => `=== DIFF: ${file} ===\n${body}`).join("\n\n")
    return `You are a senior application-security reviewer. Inspect this repository change using read-only tools only. Return JSON matching the supplied schema exactly. Report only concrete exploitable vulnerabilities; include filePath, category, vulnerableCode, explanation, fix, severity, and optional confidence.\n\nChanged files:\n${input.diffFiles.map(([file]) => file).join("\n")}\n\nUnified diff:\n${diff}`
  }

  private refutationPrompt(findings: Finding[], files: Array<[string, string]>): string {
    const diff = files.map(([file, body]) => `=== DIFF: ${file} ===\n${body}`).join("\n\n")
    return `Adversarially verify the candidate findings below against the repository and diff. Return JSON matching the supplied schema. Put indexes of findings that survive in survived; put concrete refutations in refuted. Default to survived unless evidence disproves exploitability.\n\nCandidates:\n${JSON.stringify(findings)}\n\nDiff:\n${diff}`
  }
}
