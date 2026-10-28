DO $body$
BEGIN
    RAISE NOTICE 'CREATE INDEX fake_idx ON widgets (id); DROP TABLE widgets;';
END
$body$;
