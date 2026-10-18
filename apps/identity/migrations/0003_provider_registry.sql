ALTER TABLE providers
  ADD COLUMN protocol TEXT NOT NULL DEFAULT 'openai'
  CHECK (protocol IN ('openai', 'anthropic'));

ALTER TABLE providers
  ADD COLUMN base_url TEXT NOT NULL DEFAULT 'https://api.openai.com/v1/'
  CHECK (length(base_url) BETWEEN 1 AND 2048);

ALTER TABLE providers
  ADD COLUMN custom INTEGER NOT NULL DEFAULT 0
  CHECK (custom IN (0, 1));

UPDATE providers
SET protocol = CASE provider
  WHEN 'anthropic' THEN 'anthropic'
  ELSE 'openai'
END,
base_url = CASE provider
  WHEN 'anthropic' THEN 'https://api.anthropic.com/v1/'
  ELSE 'https://api.openai.com/v1/'
END,
custom = 0
WHERE provider IN ('openai', 'anthropic');

UPDATE providers
SET enabled = 0
WHERE provider NOT IN ('openai', 'anthropic');
