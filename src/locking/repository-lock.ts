import { closeSync, existsSync, mkdirSync, openSync, readFileSync, statSync, unlinkSync, writeFileSync } from "node:fs"
import path from "node:path"

const RETRY_MS = 50
const STALE_MS = 10 * 60 * 1000

export class RepositoryLock {
  constructor(private readonly repoRoot: string) {}

  async run<T>(work: () => Promise<T>): Promise<T> {
    const gitDir = path.join(this.repoRoot, ".git")
    const lock = path.join(gitDir, "security-guidance-review.lock")
    mkdirSync(gitDir, { recursive: true })
    let fd: number | undefined
    for (;;) {
      try {
        fd = openSync(lock, "wx", 0o600)
        writeFileSync(fd, JSON.stringify({ pid: process.pid, created: Date.now() }))
        break
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error
        try {
          if (Date.now() - statSync(lock).mtimeMs > STALE_MS) unlinkSync(lock)
        } catch { /* another process owns or removed it */ }
        await new Promise(resolve => setTimeout(resolve, RETRY_MS))
      }
    }
    try { return await work() } finally {
      if (fd !== undefined) closeSync(fd)
      try { unlinkSync(lock) } catch { /* cleanup is best effort */ }
    }
  }
}

const locks = new Map<string, RepositoryLock>()
const tails = new Map<string, Promise<void>>()
export class RepoReviewCoordinator {
  constructor(private readonly repoRoot: string) {}

  enqueue<T>(work: () => Promise<T>): Promise<T> {
    const previous = tails.get(this.repoRoot) ?? Promise.resolve()
    const current = previous.then(() => new RepositoryLock(this.repoRoot).run(work))
    tails.set(this.repoRoot, current.then(() => undefined, () => undefined))
    return current
  }
}

export function repoReviewCoordinator(repoRoot: string): RepoReviewCoordinator {
  // The map is intentionally only a process-local optimization; RepositoryLock
  // remains the correctness boundary across plugin processes.
  let lock = locks.get(repoRoot)
  if (!lock) { lock = new RepositoryLock(repoRoot); locks.set(repoRoot, lock) }
  return new RepoReviewCoordinator(repoRoot)
}
