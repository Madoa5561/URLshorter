-- URLマッピングテーブル
CREATE TABLE IF NOT EXISTS url_mapping (
    shortened TEXT PRIMARY KEY,
    original TEXT NOT NULL,
    og_title TEXT,
    og_description TEXT,
    og_image TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    access_count INTEGER DEFAULT 0,
    access_limit INTEGER DEFAULT NULL,
    expires_at TIMESTAMP DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS idx_url_mapping_created_at ON url_mapping(created_at);
CREATE INDEX IF NOT EXISTS idx_url_mapping_access_count ON url_mapping(access_count);

-- アクセスログ・システムログテーブル
CREATE TABLE IF NOT EXISTS access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    message TEXT NOT NULL,
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp ON access_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_access_logs_type ON access_logs(type);
