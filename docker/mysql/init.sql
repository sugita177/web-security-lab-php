-- Web Security Lab 初期化SQL
SET NAMES utf8mb4;
CREATE DATABASE IF NOT EXISTS security_lab CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE security_lab;


-- 1. ユーザーテーブル（認証回避・UNIONインジェクションで狙われる標的）
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL, -- 学習用平文（Phase 3で安全なハッシュ化を学習）
    email VARCHAR(100) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    secret_api_key VARCHAR(64) NOT NULL
);

INSERT INTO users (username, password, email, role, secret_api_key) VALUES
('admin', 'SuperSecretAdminPass2026!', 'admin@security-lab.local', 'admin', 'sk_live_99999_ADMIN_MASTER_KEY_XYZ'),
('alice', 'alicePass123', 'alice@example.com', 'user', 'sk_live_11111_alice_api_key_abc'),
('bob',   'bobPass456',   'bob@example.com',   'user', 'sk_live_22222_bob_api_key_def');

-- 2. 商品テーブル（動的検索・ソート検証用）
DROP TABLE IF EXISTS products;
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    price INT NOT NULL,
    stock INT NOT NULL,
    category VARCHAR(50) NOT NULL
);

INSERT INTO products (name, price, stock, category) VALUES
('安全なWeb開発 入門書', 3200, 50, 'Book'),
('暗号学プログラミング', 4500, 20, 'Book'),
('セキュリティ監査用ノートPC', 180000, 5, 'Hardware'),
('ハードウェアセキュリティキー', 6500, 100, 'Hardware'),
('耐衝撃バックパック', 12000, 30, 'Goods');
