
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');

const db = new sqlite3.Database('./stock.db');
const app = express();
const PORT = 3000;
const saltRounds = 10;

app.use(express.json());
app.use(express.static('public'));
app.use(cookieParser());
app.use(session({
    secret: 'a-very-secret-key-that-should-be-in-env', // In a real app, use an environment variable
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // For http, set to true if you use https
}));

// --- データベースと初期データの準備 (ユーザー管理対応) ---
db.serialize(() => {
    // 1. 工場テーブル
    db.run(`CREATE TABLE IF NOT EXISTS shops (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE
    )`);

    // 2. 部品マスタテーブル
    db.run(`CREATE TABLE IF NOT EXISTS parts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        part_number TEXT NOT NULL UNIQUE,
        part_name TEXT NOT NULL
    )`);

    // 3. 在庫テーブル
    db.run(`CREATE TABLE IF NOT EXISTS inventories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        part_id INTEGER NOT NULL,
        shop_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        min_reorder_level INTEGER NOT NULL,
        location_info TEXT,
        FOREIGN KEY (part_id) REFERENCES parts(id),
        FOREIGN KEY (shop_id) REFERENCES shops(id),
        UNIQUE(part_id, shop_id)
    )`);

    // 4. 使用履歴テーブル
    db.run(`CREATE TABLE IF NOT EXISTS usage_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        part_id INTEGER NOT NULL,
        shop_id INTEGER NOT NULL,
        usage_time TEXT NOT NULL,
        mechanic_name TEXT,
        FOREIGN KEY (part_id) REFERENCES parts(id),
        FOREIGN KEY (shop_id) REFERENCES shops(id)
    )`);

    // 5. ユーザーテーブル
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        shop_id INTEGER,
        role TEXT NOT NULL, -- 'admin' or 'shop_user'
        FOREIGN KEY (shop_id) REFERENCES shops(id)
    )`);

    // --- 初期データの投入 (初回起動時のみ) ---
    db.get("SELECT COUNT(*) AS count FROM shops", (err, row) => {
        if (row && row.count === 0) {
            console.log("Seeding initial data...");
            // (shops, parts, inventories seed logic as before)
            const shops = ["A整備工場", "B整備工場"];
            const parts = [
                { number: "OF-001", name: "オイルフィルター X10" },
                { number: "BP-002", name: "ブレーキパッド R20" },
                { number: "BT-003", name: "バッテリー V60" }
            ];
            const shopStmt = db.prepare("INSERT INTO shops (name) VALUES (?)");
            shops.forEach(shop => shopStmt.run(shop));
            shopStmt.finalize();
            const partStmt = db.prepare("INSERT INTO parts (part_number, part_name) VALUES (?, ?)");
            parts.forEach(p => partStmt.run(p.number, p.name));
            partStmt.finalize();
            const invStmt = db.prepare("INSERT INTO inventories (part_id, shop_id, quantity, min_reorder_level, location_info) VALUES (?, ?, ?, ?, ?)");
            invStmt.run(1, 1, 15, 5, "棚A-1");
            invStmt.run(2, 1, 8, 3, "棚A-2");
            invStmt.run(1, 2, 20, 5, "ラック1");
            invStmt.run(3, 2, 5, 2, "ラック2");
            invStmt.finalize();
            console.log("Shops, parts, and inventories seeded.");

            // 管理者ユーザーを追加
            bcrypt.hash('password', saltRounds, (err, hash) => {
                if (err) {
                    return console.error("Error hashing password for admin user", err);
                }
                db.run("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", ['admin', hash, 'admin'], (err) => {
                    if (err) {
                        return console.error("Error seeding admin user", err);
                    }
                    console.log("Admin user created with username 'admin' and password 'password'");
                });
            });
        } else {
            console.log("Database already contains data. Skipping seed.");
        }
    });
});

// (API implementations will go here in the next steps)

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
