-- Stories (24-hour ephemeral broadcasts) and Channels (admin-only broadcast groups)

CREATE TABLE IF NOT EXISTS stories (
    story_id TEXT PRIMARY KEY,
    author_user_id TEXT NOT NULL,
    content_base64 TEXT NOT NULL,
    media_type TEXT NOT NULL DEFAULT 'text',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_stories_author
ON stories(author_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_stories_expires
ON stories(expires_at);

CREATE TABLE IF NOT EXISTS story_views (
    story_id TEXT NOT NULL,
    viewer_user_id TEXT NOT NULL,
    viewed_at TEXT NOT NULL,
    PRIMARY KEY (story_id, viewer_user_id)
);

CREATE TABLE IF NOT EXISTS channels (
    channel_id TEXT PRIMARY KEY,
    owner_user_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_channels_owner
ON channels(owner_user_id);

CREATE TABLE IF NOT EXISTS channel_subscribers (
    channel_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    subscribed_at TEXT NOT NULL,
    PRIMARY KEY (channel_id, user_id)
);

CREATE TABLE IF NOT EXISTS channel_messages (
    message_id BIGSERIAL PRIMARY KEY,
    channel_id TEXT NOT NULL,
    content_base64 TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_channel_messages_channel
ON channel_messages(channel_id, message_id DESC);
