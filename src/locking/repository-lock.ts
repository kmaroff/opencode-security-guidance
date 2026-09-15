import { closeSync, mkdirSync, openSync, readFileSync, statSync, unlinkSync, writeFileSync } from "node:fs"
import { execFileSync } from "node:child_process"
import { randomUUID } from "node:crypto"
import path from "node:path"

export const REPOSITORY_LOCK_TIMEOUT_MS = 30_000
export const REPOSITORY_LOCK_STALE_MS = 10 * 60 * 1000
const RETRY_MS = 50

type LockRecord = { token: string; pid: number; createdAt: number }

function commonGitDir(repoRoot: string): string {
  const raw = execFileSync("git", ["rev-parse", "--git-common-dir"], { cwd: repoRoot, encoding: "utf8", timeout: 5_000 }).trim()
  if (!raw) throw new Error("git_common_dir_unresolved")
  return path.resolve(repoRoot, raw)
}

function readOwner(lock: string): LockRecord | undefined {
  try {
    const value: unknown = JSON.parse(readFileSync(lock, "utf8"))
    if (!value || typeof value !== "object" || Array.isArray(value)) return undefined
    const record = value as Record<string, unknown>
    if (typeof record.token !== "string" || typeof record.pid !== "number" || typeof record.createdAt !== "number") return undefined
    return { token: record.token, pid: record.pid, createdAt: record.createdAt }
  } catch { return undefined }
}

function lockAgeMs(lock: string): number {
  try { return Date.now() - statSync(lock).mtimeMs }
  catch { return 0 }
}

function processAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false
  try { process.kill(pid, 0); return true }
  catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM" }
}

function releaseIfOwned(lock: string, owner: LockRecord): void {
  const current = readOwner(lock)
  if (current?.token !== owner.token || current.pid !== owner.pid) return
  try { unlinkSync(lock) } catch { /* another owner already released it */ }
}

export class RepositoryLock {
  constructor(private readonly repoRoot: string, private readonly timeoutMs = REPOSITORY_LOCK_TIMEOUT_MS) {}

  async run<T>(work: () => Promise<T>): Promise<T> {
    const gitDir = commonGitDir(this.repoRoot)
    mkdirSync(gitDir, { recursive: true })
    const lock = path.join(gitDir, "security-guidance-review.lock")
    const owner: LockRecord = { token: randomUUID(), pid: process.pid, createdAt: Date.now() }
    const deadline = Date.now() + Math.max(1, this.timeoutMs)
    let acquired = false
    let fd: number | undefined
    while (!acquired) {
      try {
        fd = openSync(lock, "wx", 0o600)
        writeFileSync(fd, JSON.stringify(owner), "utf8")
        acquired = true
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error
        const current = readOwner(lock)
        const ageMs = current ? Date.now() - current.createdAt : lockAgeMs(lock)
        if (ageMs > REPOSITORY_LOCK_STALE_MS && (!current || !processAlive(current.pid))) {
          try { unlinkSync(lock) } catch { /* another contender won the removal race */ }
          continue
        }
        if (Date.now() >= deadline) throw new Error("repository_review_lock_timeout")
        await new Promise(resolve => setTimeout(resolve, RETRY_MS))
      }
    }
    try { return await work() }
    finally {
      if (fd !== undefined) closeSync(fd)
      releaseIfOwned(lock, owner)
    }
  }
}

const tails = new Map<string, Promise<void>>()

export class RepoReviewCoordinator {
  constructor(private readonly repoRoot: string, private readonly timeoutMs = REPOSITORY_LOCK_TIMEOUT_MS) {}

  enqueue<T>(work: () => Promise<T>): Promise<T> {
    const previous = tails.get(this.repoRoot) ?? Promise.resolve()
    const current = previous.then(() => new RepositoryLock(this.repoRoot, this.timeoutMs).run(work))
    tails.set(this.repoRoot, current.then(() => undefined, () => undefined))
    return current
  }
}

export function repoReviewCoordinator(repoRoot: string): RepoReviewCoordinator {
  return new RepoReviewCoordinator(repoRoot)
}
