MERGE INTO public.accounts AS target USING public.incoming AS source
ON target.id = source.id WHEN MATCHED THEN UPDATE SET balance = source.balance;

INSERT INTO public.accounts (id, balance) VALUES (1, 42)
ON CONFLICT (id) DO UPDATE SET balance = EXCLUDED.balance;

UPDATE public.accounts AS target SET balance = source.balance
FROM public.incoming AS source WHERE target.id = source.id;

DELETE FROM public.accounts AS target USING public.incoming AS source
WHERE target.id = source.id;

DROP TABLE public.old_sessions;
