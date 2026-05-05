-- MySQL Database Schema for Web Crawler
-- Run this script to create the database and tables manually if needed

-- Create database
CREATE DATABASE IF NOT EXISTS web_crawler;
USE web_crawler;

-- Create user (optional, modify password as needed)
CREATE USER IF NOT EXISTS 'crawler'@'localhost' IDENTIFIED BY 'crawler_pass';
GRANT ALL PRIVILEGES ON web_crawler.* TO 'crawler'@'localhost';
FLUSH PRIVILEGES;

-- Table: pages
-- Stores information about each crawled page
CREATE TABLE IF NOT EXISTS pages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    host VARCHAR(255) NOT NULL COMMENT 'Domain or IP address',
    path VARCHAR(1024) NOT NULL COMMENT 'URL path',
    query TEXT COMMENT 'Query string parameters',
    full_url TEXT NOT NULL COMMENT 'Complete URL',
    status_code INT COMMENT 'HTTP response status code',
    content_length BIGINT COMMENT 'Response body size in bytes',
    content_type VARCHAR(255) COMMENT 'Content-Type header',
    crawled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When the page was crawled',
    
    INDEX idx_host (host),
    INDEX idx_status (status_code),
    INDEX idx_crawled_at (crawled_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Crawled pages log';

-- Table: url_params
-- Stores individual URL parameters extracted from pages
CREATE TABLE IF NOT EXISTS url_params (
    id INT AUTO_INCREMENT PRIMARY KEY,
    page_id INT NOT NULL COMMENT 'Foreign key to pages table',
    param_name VARCHAR(255) NOT NULL COMMENT 'Parameter name',
    param_value TEXT COMMENT 'Parameter value (URL decoded)',
    
    FOREIGN KEY (page_id) REFERENCES pages(id) ON DELETE CASCADE,
    INDEX idx_page (page_id),
    INDEX idx_param_name (param_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='URL parameters from crawled pages';

-- Table: assets
-- Stores assets (images, scripts, stylesheets) found on pages
CREATE TABLE IF NOT EXISTS assets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    page_id INT NOT NULL COMMENT 'Foreign key to pages table',
    asset_url TEXT NOT NULL COMMENT 'Asset URL',
    asset_type VARCHAR(64) COMMENT 'Type: image, script, stylesheet, etc.',
    
    FOREIGN KEY (page_id) REFERENCES pages(id) ON DELETE CASCADE,
    INDEX idx_page (page_id),
    INDEX idx_asset_type (asset_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Assets found on crawled pages';

-- Useful views for analysis

-- View: Summary statistics per host
CREATE OR REPLACE VIEW v_host_summary AS
SELECT 
    host,
    COUNT(*) as total_pages,
    SUM(CASE WHEN status_code = 200 THEN 1 ELSE 0 END) as success_count,
    SUM(CASE WHEN status_code = 403 THEN 1 ELSE 0 END) as forbidden_count,
    SUM(CASE WHEN status_code = 500 THEN 1 ELSE 0 END) as error_count,
    MIN(crawled_at) as first_crawled,
    MAX(crawled_at) as last_crawled
FROM pages
GROUP BY host;

-- View: All unique parameter names across all pages
CREATE OR REPLACE VIEW v_unique_params AS
SELECT DISTINCT
    param_name,
    COUNT(*) as usage_count
FROM url_params
GROUP BY param_name
ORDER BY usage_count DESC;

-- View: Asset types distribution
CREATE OR REPLACE VIEW v_asset_distribution AS
SELECT 
    asset_type,
    COUNT(*) as count
FROM assets
GROUP BY asset_type
ORDER BY count DESC;

-- Sample queries for analysis

-- Find all pages with a specific parameter
-- SELECT p.* FROM pages p 
-- JOIN url_params up ON p.id = up.page_id 
-- WHERE up.param_name = 'id';

-- Find all pages that returned 403 Forbidden
-- SELECT * FROM pages WHERE status_code = 403;

-- Find all JavaScript assets
-- SELECT * FROM assets WHERE asset_type = 'script';

-- Get crawl progress by hour
-- SELECT DATE_FORMAT(crawled_at, '%Y-%m-%d %H:00') as hour, COUNT(*) as pages
-- FROM pages GROUP BY hour ORDER BY hour;
