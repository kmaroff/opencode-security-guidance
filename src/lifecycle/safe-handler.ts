import { createLogger } from "../logging/logger.js"

type AsyncHandler<Args extends unknown[], Result> = (...args: Args) => Promise<Result>

export function safeHandler<Args extends unknown[], Result>(operation: string, handler: AsyncHandler<Args, Result>, debug = false): AsyncHandler<Args, Result> {
  const log = createLogger(debug)
  return (async (...args: Args) => {
    try { return await handler(...args) }
    catch (error) {
      log(operation, { errorKind: error instanceof Error ? error.name : "unknown" })
      return undefined as Result
    }
  }) as AsyncHandler<Args, Result>
}
