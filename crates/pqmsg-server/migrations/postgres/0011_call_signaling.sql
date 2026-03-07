-- Call signaling tables for WebRTC call establishment (PostgreSQL)

CREATE TABLE IF NOT EXISTS call_sessions (
    call_id TEXT PRIMARY KEY,
    caller_user_id TEXT NOT NULL,
    callee_user_id TEXT NOT NULL,
    call_type TEXT NOT NULL DEFAULT 'audio',
    status TEXT NOT NULL DEFAULT 'ringing',
    created_at TEXT NOT NULL,
    answered_at TEXT,
    ended_at TEXT,
    end_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_call_sessions_callee
ON call_sessions(callee_user_id, status);

CREATE INDEX IF NOT EXISTS idx_call_sessions_caller
ON call_sessions(caller_user_id, status);

CREATE TABLE IF NOT EXISTS call_signals (
    signal_id BIGSERIAL PRIMARY KEY,
    call_id TEXT NOT NULL,
    signal_type TEXT NOT NULL,
    from_user_id TEXT NOT NULL,
    payload_base64 TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_call_signals_call_id
ON call_signals(call_id, signal_id);
