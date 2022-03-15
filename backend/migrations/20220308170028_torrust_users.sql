DROP TABLE IF EXISTS temp;

CREATE TABLE temp AS SELECT user_id, username, password, administrator FROM torrust_users;

DROP TABLE torrust_users;

ALTER TABLE temp RENAME TO torrust_users;