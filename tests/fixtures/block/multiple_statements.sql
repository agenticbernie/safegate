-- First statement is safe.
CREATE TABLE new_widgets (id bigint);

CREATE INDEX new_widgets_id_idx
    ON new_widgets (id);
