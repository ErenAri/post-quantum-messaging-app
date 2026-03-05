PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS groups (
    group_id TEXT PRIMARY KEY,
    owner_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    added_by_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    joined_at TEXT NOT NULL,
    removed_at TEXT,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_group_members_group_active
ON group_members(group_id, removed_at, joined_at, user_id);

CREATE INDEX IF NOT EXISTS idx_group_members_user_active
ON group_members(user_id, removed_at, group_id);
