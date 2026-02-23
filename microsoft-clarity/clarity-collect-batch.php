<?php

// Batch helpers for collect events.

const CLARITY_COLLECT_BATCH_SIZE = 50;
const CLARITY_COLLECT_CRON_INTERVAL = 300;
const CLARITY_COLLECT_CRON_SCHEDULE = 'clarity_request_recurrence';
const CLARITY_COLLECT_CRON_HOOK = 'clarity_collect_batch_cron';

/**
 * Registers a 5-minute cron schedule.
 *
 * @param array $schedules Existing schedules.
 * @return array Updated schedules.
 */
function clarity_register_collect_schedule($schedules)
{
    if (!isset($schedules[CLARITY_COLLECT_CRON_SCHEDULE])) {
        $schedules[CLARITY_COLLECT_CRON_SCHEDULE] = array(
            'interval' => CLARITY_COLLECT_CRON_INTERVAL,
            'display'  => 'Every ' . CLARITY_COLLECT_CRON_INTERVAL . ' seconds'
        );
    }

    return $schedules;
}

// Registering the Clarity collect schedule to the list of cron schedules
// This is done through a filter registering to $schedules.
add_filter('cron_schedules', 'clarity_register_collect_schedule');

/**
 * Schedules the recurring batch worker.
 */
function clarity_schedule_collect_recurring()
{
    if (wp_next_scheduled(CLARITY_COLLECT_CRON_HOOK)) {
        return;
    }

    wp_schedule_event(time(), CLARITY_COLLECT_CRON_SCHEDULE, CLARITY_COLLECT_CRON_HOOK);
}

/**
 * Flushes pending events and clears the recurring batch worker.
 */
function clarity_flush_and_clear_collect_recurring()
{
    clarity_send_collect_event_batch_worker();
    wp_clear_scheduled_hook(CLARITY_COLLECT_CRON_HOOK);
}

/**
 * Runs the batch sender on cron.
 */
function clarity_send_collect_event_batch_worker()
{
    if (!clarity_collect_events_table_ready()) {
        return;
    }

    $rows = clarity_fetch_and_delete_pending_events_transactionally();
    if (empty($rows)) {
        return;
    }

    $events = clarity_build_events_from_rows($rows);
    if (empty($events)) {
        return;
    }

    foreach (array_chunk($events, CLARITY_COLLECT_BATCH_SIZE) as $batch) {
        clarity_send_collect_event_batch($batch);
    }
}

add_action(CLARITY_COLLECT_CRON_HOOK, 'clarity_send_collect_event_batch_worker');

/**
 * Builds event payloads from pending rows.
 *
 * @param array $rows Pending rows.
 * @return array Payloads to send.
 */
function clarity_build_events_from_rows($rows)
{
    $events = array();
    foreach ($rows as $row) {
        $payload = json_decode($row['payload'], true);
        if (is_array($payload)) {
            $events[] = $payload;
        }
    }

    return $events;
}
