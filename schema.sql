-- SQLite Database Schema for Web Crawler
-- This script creates the tables needed by the crawler
-- Run: sqlite3 crawler.db < schema.sql

-- Table: pages
-- Stores information about each crawled page
CREATE TABLE IF NOT EXISTS pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,              -- Domain or IP address
    path TEXT NOT NULL,              -- URL path
    query TEXT,                      -- Query string parameters
    full_url TEXT NOT NULL,          -- Complete URL
    status_code INTEGER,             -- HTTP response status code
    content_length INTEGER,          -- Response body size in bytes
    content_type TEXT,               -- Content-Type header
    crawled_at DATETIME DEFAULT CURRENT_TIMESTAMP  -- When the page was crawled
);

-- Create indexes for faster queries
CREATE INDEX IF NOT EXISTS idx_host ON pages(host);
CREATE INDEX IF NOT EXISTS idx_status ON pages(status_code);
CREATE INDEX IF NOT EXISTS idx_crawled_at ON pages(crawled_at);

-- Table: url_params
-- Stores individual URL parameters extracted from pages
CREATE TABLE IF NOT EXISTS url_params (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    page_id INTEGER NOT NULL,        -- Foreign key to pages table
    param_name TEXT NOT NULL,        -- Parameter name
    param_value TEXT,                -- Parameter value (URL decoded)
    
    FOREIGN KEY (page_id) REFERENCES pages(id) ON DELETE CASCADE
);

-- Create indexes for faster queries
CREATE INDEX IF NOT EXISTS idx_page ON url_params(page_id);
CREATE INDEX IF NOT EXISTS idx_param_name ON url_params(param_name);

-- Table: assets
-- Stores assets (images, scripts, stylesheets) found on pages
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    page_id INTEGER NOT NULL,        -- Foreign key to pages table
    asset_url TEXT NOT NULL,         -- Asset URL
    asset_type TEXT,                 -- Type: image, script, stylesheet, etc.
    
    FOREIGN KEY (page_id) REFERENCES pages(id) ON DELETE CASCADE
);

-- Create indexes for faster queries
CREATE INDEX IF NOT EXISTS idx_asset_page ON assets(page_id);

-- Useful views for analysis

-- View: Summary of pages by status code
CREATE VIEW IF NOT EXISTS v_status_summary AS
SELECT 
    status_code,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM pages), 2) as percentage
FROM pages
GROUP BY status_code
ORDER BY count DESC;

-- View: Top parameter names found across all pages
CREATE VIEW IF NOT EXISTS v_top_params AS
SELECT 
    param_name,
    COUNT(*) as occurrence_count,
    COUNT(DISTINCT page_id) as page_count
FROM url_params
GROUP BY param_name
ORDER BY occurrence_count DESC
LIMIT 50;

-- View: Pages with most parameters
CREATE VIEW IF NOT EXISTS v_pages_with_params AS
SELECT 
    p.id,
    p.host,
    p.path,
    p.full_url,
    p.status_code,
    COUNT(up.id) as param_count
FROM pages p
LEFT JOIN url_params up ON p.id = up.page_id
GROUP BY p.id
HAVING param_count > 0
ORDER BY param_count DESC;

-- View: Asset types distribution
CREATE VIEW IF NOT EXISTS v_asset_types AS
SELECT 
    asset_type,
    COUNT(*) as count
FROM assets
WHERE asset_type IS NOT NULL AND asset_type != ''
GROUP BY asset_type
ORDER BY count DESC;
