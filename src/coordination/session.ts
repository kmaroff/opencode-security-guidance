export class SessionCoordinator {
  private tail: Promise<void> = Promise.resolve()
  private pending = 0

  enqueue<T>(work: () => Promise<T>): Promise<T> {
    this.pending += 1
    const run = this.tail.then(work)
    this.tail = run.then(() => undefined, () => undefined).finally(() => { this.pending -= 1 })
    return run
  }

  get size(): number { return this.pending }
}

const coordinators = new Map<string, SessionCoordinator>()
export function sessionCoordinator(sessionID: string): SessionCoordinator {
  let coordinator = coordinators.get(sessionID)
  if (!coordinator) {
    coordinator = new SessionCoordinator()
    coordinators.set(sessionID, coordinator)
  }
  return coordinator
}
