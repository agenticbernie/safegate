BEGIN;
CREATE INDEX CONCURRENTLY widgets_id_idx
    ON widgets (id);
COMMIT;
