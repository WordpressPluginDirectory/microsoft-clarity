<?php

// Storage helpers for collect event batching.

const CLARITY_COLLECT_TABLE_NAME = 'clarity_collect_events';

/**
 * Creates the collect events table.
 */
function clarity_create_collect_events_table()
{
    global $wpdb;

    if (!$wpdb->ready) {
        return;
    }

    $table = clarity_get_collect_events_table_name();
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table (
        id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        payload longtext NOT NULL,
        created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY  (id)
    ) ENGINE=InnoDB $charset_collate;";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql);
}

/**
 * Drops the collect events table.
 */
function clarity_drop_collect_events_table()
{
    global $wpdb;

    if (!$wpdb->ready) {
        return;
    }

    $table = clarity_get_collect_events_table_name();
    $wpdb->query("DROP TABLE IF EXISTS $table");
}

/**
 * Inserts a collect event payload.
 *
 * @param array $event The event payload to store.
 * @return bool True when stored successfully.
 */
function clarity_insert_collect_event($event)
{
    global $wpdb;

    if (!$wpdb->ready) {
        return false;
    }

    $payload = wp_json_encode($event);
    if ($payload === false) { // wp_json_encode returns false on failure
        return false;
    }

    $table = clarity_get_collect_events_table_name();
    $result = $wpdb->insert(
        $table,
        array(
            'payload'    => $payload,
        ),
        array('%s') // payload is a JSON string
    );

    return $result !== false;
}

/**
 * Fetches and deletes pending events in one transaction.
 *
 * @return array Rows fetched for processing.
 */
function clarity_fetch_and_delete_pending_events_transactionally()
{
    global $wpdb;

    $table = clarity_get_collect_events_table_name();
    $committed = false; 

    try {
        // Uses READ COMMITTED isolation and row locks to avoid concurrent processing
        // of the same rows while allowing concurrent inserts.
        $wpdb->query('SET TRANSACTION ISOLATION LEVEL READ COMMITTED');
        $wpdb->query('START TRANSACTION');

        $rows = $wpdb->get_results(
            "SELECT id, payload FROM $table ORDER BY id ASC FOR UPDATE",
            ARRAY_A // Return as associative array so columns (like 'payload') can be accessed by name
        );

        if (!is_array($rows) || empty($rows)) {
            return array();
        }

        $rows_count = count($rows);
        $max_id = $rows[$rows_count - 1]['id'];
        $deleted = $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM $table WHERE id <= %d",
                $max_id
            )
        );

        if ($deleted === false || $deleted !== $rows_count) {
            return array();
        }

        $wpdb->query('COMMIT');
        $committed = true;
        return $rows;
    } finally {
        // Rollback if unexpected error thrown or any issue before committing.
        if (!$committed) {
            $wpdb->query('ROLLBACK');
        }
    }
}

/**
 * Returns the collect events table name for the current site.
 *
 * @return string Table name.
 */
function clarity_get_collect_events_table_name()
{
    global $wpdb;

    return $wpdb->prefix . CLARITY_COLLECT_TABLE_NAME;
}

/**
 * Checks whether the collect events table exists.
 *
 * @return bool True when the table exists.
 */
function clarity_collect_events_table_exists()
{
    static $table_exists = null;

    if ($table_exists !== null) {
        return $table_exists;
    }

    global $wpdb;
    $table = clarity_get_collect_events_table_name();
    $like = $wpdb->esc_like($table);
    $table_exists = ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $like)) === $table);

    return $table_exists;
}

/**
 * Checks whether the collect events table is ready for use.
 *
 * @return bool True when ready.
 */
function clarity_collect_events_table_ready()
{
    global $wpdb;

    return $wpdb->ready && clarity_collect_events_table_exists();
}

