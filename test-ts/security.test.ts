import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { mkdtemp, mkdir, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { test } from "node:test"
import { loadConfig } from "../src/config/loader.js"
import { RepositoryLock } from "../src/locking/repository-lock.js"
import { validateFindingsResult, validateSurvivedResult } from "../src/review/validator.js"

test("survivor validation requires every candidate to be classified exactly once", () => {
  assert.doesNotThrow(() => validateSurvivedResult({ survived: [0], refuted: [{ idx: 1, reason: "safe" }] }, 2))
  assert.throws(() => validateSurvivedResult({ survived: [0, 0], refuted: [{ idx: 1, reason: "safe" }] }, 2), /duplicate survived/)
  assert.throws(() => validateSurvivedResult({ survived: [0] }, 2), /candidate index missing/)
  assert.throws(() => validateSurvivedResult({ survived: [0], refuted: [{ idx: 0, reason: "overlap" }] }, 1), /both survived and refuted/)
})

test("findings validation rejects oversized provider payloads", () => {
  const finding = { filePath: "x.ts", category: "injection", vulnerableCode: "x", explanation: "x", fix: "x", severity: "high" }
  assert.doesNotThrow(() => validateFindingsResult({ findings: [finding] }))
  assert.throws(() => validateFindingsResult({ findings: [{ ...finding, explanation: "x".repeat(16_385) }] }), /explanation exceeds limit/)
})

test("malformed reviewer configuration disables the plugin", async () => {
  const project = await mkdtemp(path.join(os.tmpdir(), "sg-config-"))
  await mkdir(path.join(project, ".opencode"), { recursive: true })
  await writeFile(path.join(project, ".opencode", "security-guidance.json"), JSON.stringify({ reviewer: null }))
  const loaded = loadConfig(project)
  assert.equal(loaded.config.enabled, false)
  assert.match(loaded.diagnostic ?? "", /reviewer must be an object/)
})

test("repository review lock serializes work and releases after failure", async () => {
  const project = await mkdtemp(path.join(os.tmpdir(), "sg-lock-"))
  execFileSync("git", ["init", "-q", "-b", "main"], { cwd: project })
  const lock = new RepositoryLock(project, 2_000)
  const order: string[] = []
  let releaseFirst!: () => void
  const firstStarted = new Promise<void>(resolve => {
    releaseFirst = resolve
  })
  const first = lock.run(async () => {
    order.push("first-start")
    await firstStarted
    order.push("first-end")
    throw new Error("expected")
  })
  await Promise.resolve()
  const second = lock.run(async () => { order.push("second") })
  releaseFirst()
  await assert.rejects(first, /expected/)
  await second
  assert.deepEqual(order, ["first-start", "first-end", "second"])
})
