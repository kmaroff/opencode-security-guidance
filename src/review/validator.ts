import { Ajv2020 } from "ajv/dist/2020.js"
import { FINDINGS_SCHEMA, SURVIVED_SCHEMA } from "./schemas.js"

const ajv = new Ajv2020({ allErrors: true, strict: true })
const validateFindings = ajv.compile(FINDINGS_SCHEMA)
const validateSurvived = ajv.compile(SURVIVED_SCHEMA)

export function validateFindingsResult(value: unknown): asserts value is { findings: Array<Record<string, unknown>> } {
  if (!validateFindings(value)) throw new Error(`schema_validation_error: ${ajv.errorsText(validateFindings.errors)}`)
}

export function validateSurvivedResult(value: unknown): asserts value is { survived: number[]; refuted?: Array<Record<string, unknown>> } {
  if (!validateSurvived(value)) throw new Error(`schema_validation_error: ${ajv.errorsText(validateSurvived.errors)}`)
}
