ALTER TABLE widgets
    ADD CONSTRAINT widgets_owner_fk
    FOREIGN KEY (owner_id) REFERENCES owners (id);
