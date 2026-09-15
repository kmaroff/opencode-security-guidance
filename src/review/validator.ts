import { Ajv2020 } from "ajv/dist/2020.js"
import { FINDINGS_SCHEMA, SURVIVED_SCHEMA } from "./schemas.js"

const ajv = new Ajv2020({ allErrors: true, strict: true })
const validateFindings = ajv.compile(FINDINGS_SCHEMA)
const validateSurvived = ajv.compile(SURVIVED_SCHEMA)

const MAX_FINDINGS = 100
const MAX_FINDING_STRING = 16_384

function validateIndexSet(value: { survived: number[]; refuted?: Array<Record<string, unknown>> }, candidateCount: number): void {
  const survived = value.survived
  const refuted = value.refuted ?? []
  if (survived.some(index => index < 0 || index >= candidateCount)) throw new Error("semantic_validation_error: survived index out of range")
  const refutedIndexes = refuted.map(item => item.idx)
  if (refutedIndexes.some(index => typeof index !== "number" || !Number.isInteger(index) || index < 0 || index >= candidateCount)) {
    throw new Error("semantic_validation_error: refuted index out of range")
  }
  if (new Set(survived).size !== survived.length) throw new Error("semantic_validation_error: duplicate survived index")
  if (new Set(refutedIndexes).size !== refutedIndexes.length) throw new Error("semantic_validation_error: duplicate refuted index")
  if (survived.some(index => refutedIndexes.includes(index))) throw new Error("semantic_validation_error: index both survived and refuted")
  const accounted = new Set([...survived, ...refutedIndexes])
  if (accounted.size !== candidateCount) throw new Error("semantic_validation_error: candidate index missing")
}

export function validateFindingsResult(value: unknown): asserts value is { findings: Array<Record<string, unknown>> } {
  if (!validateFindings(value)) throw new Error(`schema_validation_error: ${ajv.errorsText(validateFindings.errors)}`)
  const findings = (value as { findings: Array<Record<string, unknown>> }).findings
  if (findings.length > MAX_FINDINGS) throw new Error("semantic_validation_error: finding count exceeds limit")
  for (const finding of findings) {
    for (const key of ["filePath", "category", "vulnerableCode", "explanation", "fix"] as const) {
      if (typeof finding[key] === "string" && finding[key].length > MAX_FINDING_STRING) throw new Error(`semantic_validation_error: ${key} exceeds limit`)
    }
  }
}

export function validateSurvivedResult(value: unknown, candidateCount = 0): asserts value is { survived: number[]; refuted?: Array<Record<string, unknown>> } {
  if (!validateSurvived(value)) throw new Error(`schema_validation_error: ${ajv.errorsText(validateSurvived.errors)}`)
  validateIndexSet(value as { survived: number[]; refuted?: Array<Record<string, unknown>> }, candidateCount)
}
