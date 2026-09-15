import type { OpencodeClient } from "@opencode-ai/sdk"
import { OpencodeClient as V2OpencodeClient } from "@opencode-ai/sdk/v2"
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

function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

function unwrap(value: unknown): unknown {
  const body = object(value)
  return "data" in body ? body.data : value
}

type V2CoreClient = NonNullable<NonNullable<ConstructorParameters<typeof V2OpencodeClient>[0]>["client"]>

function v2Client(client: OpencodeClient): InstanceType<typeof V2OpencodeClient> {
  const core = (client as unknown as { _client?: V2CoreClient })._client
  if (!core) throw new ReviewFailure("client_error", "OpenCode client transport is unavailable")
  return new V2OpencodeClient({ client: core })
}
function runtimeSchema(value: unknown): Record<string, unknown> {
  const schema = { ...object(value) }
  delete schema.$schema
  delete schema.$id
  delete schema.title
  return schema
}

function structuredFrom(response: unknown): unknown {
  const body = object(unwrap(response))
  const info = object(body.info)
  if (info.error) throw new ReviewFailure("provider_error", "reviewer returned an assistant error")
  if ("structured" in info) return info.structured
  const parts = Array.isArray(body.parts) ? body.parts : []
  for (const part of parts) {
    const item = object(part)
    if ("structured" in item) return item.structured
    const state = object(item.state)
    if ("output" in state) return state.output
    if ("structured" in state) return state.structured
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
    const candidates = await this.promptReviewer(input, model, FINDINGS_SCHEMA, this.investigationPrompt(input), reviewerSessions) as { findings: Finding[] }
    let findings = candidates.findings
    if (input.agentic && findings.length > 0) {
      const refuted = await this.promptReviewer(input, model, SURVIVED_SCHEMA, this.refutationPrompt(findings, input.diffFiles), reviewerSessions) as { survived: number[] }
      const survived = new Set(refuted.survived)
      findings = findings.filter((_, index: number) => survived.has(index))
    }
    const accepted = this.bridge.call<{ findings: Finding[] }>("review.accept", { findings })
    return { findings: accepted.findings, reviewerSessions, model }
  }

  private async promptReviewer(input: ReviewInput, model: { providerID: string; modelID: string }, schema: unknown, text: string, sessions: string[]): Promise<unknown> {
    try {
      const v2 = v2Client(this.client)
      const child = object(unwrap(await v2.session.create({
        parentID: input.sessionID,
        title: "security-guidance reviewer",
        directory: input.directory,
      })))
      const childID = child.id
      if (typeof childID !== "string") throw new Error("reviewer session creation returned no id")
      sessions.push(childID)
      const response = await v2.session.prompt({
        sessionID: childID,
        directory: input.directory,
        model,
        parts: [{ type: "text", text }],
        format: { type: "json_schema", schema: runtimeSchema(schema), retryCount: 2 },
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
