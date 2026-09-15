import { createLogger } from "../logging/logger.js"

export function safeHandler<T extends (...args: any[]) => Promise<any>>(operation: string, handler: T, debug = false): T {
  const log = createLogger(debug)
  return (async (...args: Parameters<T>) => {
    try { return await handler(...args) }
    catch (error) {
      log(operation, { errorKind: error instanceof Error ? error.name : "unknown" })
      return undefined
    }
  }) as T
}
