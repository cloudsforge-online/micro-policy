/**
 * Background work.
 *
 * Rule 8 of docs/ecosystem/03 §2: every background timer is a leased job. There is no
 * `setInterval` in this repository doing domain work, and adding one fails review — the estate
 * runs eight of them today, each guarded only by a module-local boolean, which is a variable that
 * by construction cannot be seen by a second process.
 *
 * **The lease key names the contended resource, not the row.** Both jobs below are estate-wide
 * sweeps over one table each, so both key on `global`: what would break if two ran at once is
 * that they would delete each other's rows and each report a count that is wrong. Keying on, say,
 * a subject would let N replicas sweep N subjects in parallel and is the right answer for a job
 * that is per-subject — neither of these is.
 */

import { JobRunner, type JobQueue, type RunnerEvent } from '@cloudsforge/jobs'
import type { Logger } from '@cloudsforge/telemetry'
import type { Db } from './store.ts'

export const RETENTION_KIND = 'policy.decisions.retention'
export const COUNTER_PRUNE_KIND = 'policy.counters.prune'

/**
 * Jobs that must exist whether or not anything enqueued them, and how often they repeat.
 *
 * A recurring job is a producer plus a leased job, never a timer. The producer here is the boot
 * seed below plus the reschedule on completion — so the interval survives a restart, is visible
 * in a table an operator can query, and is claimed by exactly one replica.
 */
export const RECURRING: ReadonlyArray<{ kind: string; key: string; everyMs: number }> = [
  { kind: RETENTION_KIND, key: 'global', everyMs: 3_600_000 },
  { kind: COUNTER_PRUNE_KIND, key: 'global', everyMs: 900_000 },
]

/** Enqueue the recurring set at boot. `keep` means N replicas booting together produce one row. */
export async function seedRecurring(queue: JobQueue): Promise<void> {
  for (const job of RECURRING) {
    await queue.enqueue({ kind: job.kind, key: job.key, onConflict: 'keep' })
  }
}

/**
 * Re-arm a recurring job once it has finished.
 *
 * It cannot re-arm itself from inside its own handler: the runner deletes the row on success
 * *after* the handler returns, so a self-enqueue would be deleted a moment later and the schedule
 * would stop. Doing it from the completion event is the only point at which the row is gone.
 *
 * A dead-lettered recurring job is deliberately **not** re-armed. The row stays, `jobs_dead_total`
 * increments and `jobs_overdue` climbs, which is how an operator finds out. Silently rescheduling
 * a job that has failed its full attempt budget hides a permanent fault behind a busy loop.
 */
export function rescheduleRecurring(queue: JobQueue, logger: Logger): (event: RunnerEvent) => void {
  const byKind = new Map(RECURRING.map((r) => [r.kind, r]))
  return (event) => {
    if (event.type !== 'completed') return
    const recurring = event.kind ? byKind.get(event.kind) : undefined
    if (!recurring) return
    void queue
      .enqueue({
        kind: recurring.kind,
        key: recurring.key,
        runAt: new Date(Date.now() + recurring.everyMs),
        onConflict: 'earliest',
      })
      .catch((err: unknown) => logger.error('failed to re-arm recurring job', { kind: recurring.kind, err }))
  }
}

export interface JobDeps {
  readonly sql: Db
  readonly logger: Logger
  readonly decisionRetentionDays: number
  readonly counterRetentionHours: number
}

export function registerHandlers(runner: JobRunner, deps: JobDeps): JobRunner {
  /**
   * Delete decisions past the dispute window.
   *
   * Deleted in bounded batches rather than one statement. A single `DELETE` over two years of
   * decisions takes a long-running transaction and a lock that stalls every decision being
   * written while it runs — a retention sweep that causes an outage is worse than a table that is
   * larger than it needs to be for another hour.
   */
  runner.register(RETENTION_KIND, async (_job, ctx) => {
    let removed = 0
    for (let pass = 0; pass < 100; pass += 1) {
      if (ctx.signal.aborted) break
      const rows = await deps.sql<{ n: number }[]>`
        with doomed as (
          select id from policy_decisions
           where evaluated_at < now() - make_interval(days => ${deps.decisionRetentionDays})
           limit 1000
        )
        delete from policy_decisions using doomed where policy_decisions.id = doomed.id
        returning 1 as n
      `
      removed += rows.length
      if (rows.length === 0) break
      await ctx.heartbeat()
    }
    if (removed > 0) deps.logger.info('decision retention sweep', { removed })
  })

  /**
   * Drop velocity buckets whose window closed long ago.
   *
   * These are the highest-churn rows in the service and none of them is evidence of anything once
   * the window has passed — the decision that consumed the budget is the durable record, and it
   * is kept for two years.
   */
  runner.register(COUNTER_PRUNE_KIND, async (_job, ctx) => {
    if (ctx.signal.aborted) return
    const rows = await deps.sql<{ n: number }[]>`
      delete from velocity_counters
       where window_start < now() - make_interval(hours => ${deps.counterRetentionHours})
      returning 1 as n
    `
    if (rows.length > 0) deps.logger.info('velocity counter prune', { removed: rows.length })
  })

  return runner
}
