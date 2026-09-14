import Argv from '../../argv'
import Parse from '../../parse'
import type Types from '../../types'
import { STATUS_PATH_OFFSET } from './status-path-offset'

/**
 * Every path dirty in the working tree right now, tracked changes and
 * untracked files alike, as `git status -z` lists them; null unread.
 *
 * Read once when the backend is pinned, so a fetch can tell a path that
 * was already dirty when the session began from one that turned up since
 * (GitDeps `baseline`). Renames are not paired: each side is its own path.
 *
 * @param run runs git against the pinned repository
 * @returns the paths, root-relative, or null on a failed or cut listing
 */
export async function dirtyPathsOf(
  run: Types.GitRun,
): Promise<ReadonlySet<string> | null> {
  const listing = await run([
    Argv.NO_OPTIONAL_LOCKS,
    'status',
    '--porcelain',
    '-z',
    '--untracked-files=all',
    '--no-renames',
    '--ignore-submodules=dirty',
  ])

  const records = listing.stdout.split('\0').filter(record => record !== '')

  return Parse.isWholeAnswer(listing)
    ? new Set(records.map(record => record.slice(STATUS_PATH_OFFSET)))
    : null
}
