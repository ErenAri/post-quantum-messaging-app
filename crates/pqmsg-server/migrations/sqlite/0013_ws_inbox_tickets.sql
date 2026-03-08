CREATE TABLE ws_inbox_tickets (
    ticket TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    since INTEGER NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX idx_ws_inbox_tickets_expires_at
    ON ws_inbox_tickets (expires_at);
