ALTER TABLE widgets
    ADD COLUMN created_at timestamptz DEFAULT now();
