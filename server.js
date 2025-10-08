//test
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

// API for Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Server error' });
        }
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        bcrypt.compare(password, user.password_hash, (err, result) => {
            if (result) {
                // Passwords match
                req.session.user = {
                    id: user.id,
                    username: user.username,
                    role: user.role,
                    shop_id: user.shop_id
                };
                res.json({ message: 'Login successful', user: req.session.user });
            } else {
                // Passwords don't match
                res.status(401).json({ error: 'Invalid credentials' });
            }
        });
    });
});

// API for Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ error: 'Could not log out' });
        }
        res.clearCookie('connect.sid');
        res.json({ message: 'Logout successful' });
    });
});

// API to check login status
app.get('/api/auth/status', (req, res) => {
    if (req.session.user) {
        res.json({ loggedIn: true, user: req.session.user });
    } else {
        res.json({ loggedIn: false });
    }
});

// Middleware to protect routes
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
}

function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ error: 'Forbidden: Admin access required' });
    }
}

function isShopUser(req, res, next) {
    if (req.session.user && req.session.user.role === 'shop_user' && req.session.user.shop_id) {
        next();
    } else {
        res.status(403).json({ error: 'Forbidden: Shop user access required' });
    }
}

// -------------------------------------------------
// API (ステップ2: 新DB構造対応) - Existing APIs, now protected
// -------------------------------------------------

// API 1: 全ての工場リストを取得 (Admin only, or for shop selection on login page)
app.get('/api/shops', isAuthenticated, (req, res) => { // Protected
    // If admin, show all shops. If shop_user, show only their shop.
    if (req.session.user.role === 'admin') {
        db.all("SELECT id, name FROM shops ORDER BY name", [], (err, rows) => {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json(rows);
        });
    } else if (req.session.user.role === 'shop_user' && req.session.user.shop_id) {
        db.get("SELECT id, name FROM shops WHERE id = ?", [req.session.user.shop_id], (err, row) => {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json(row ? [row] : []); // Return as array for consistency
        });
    } else {
        res.status(403).json({ error: 'Forbidden: Invalid role or shop_id' });
    }
});

// API 2: 指定された工場の在庫部品リストを取得 (Protected, shop_user can only see their own shop)
app.get('/api/shops/:shopId/inventory', isAuthenticated, (req, res) => { // Protected
    const { shopId } = req.params;

    // Shop users can only view their own shop's inventory
    if (req.session.user.role === 'shop_user' && parseInt(shopId) !== req.session.user.shop_id) {
        return res.status(403).json({ error: 'Forbidden: You can only view your own shop\'s inventory' });
    }

    const sql = `
        SELECT
            p.id,
            p.part_number,
            p.part_name,
            i.quantity,
            i.location_info
        FROM parts p
        JOIN inventories i ON p.id = i.part_id
        WHERE i.shop_id = ? AND i.quantity > 0
        ORDER BY p.part_name;
    `;
    db.all(sql, [shopId], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// API 3: 部品の使用を記録 (Protected, shop_user can only use parts from their own shop)
app.post('/api/use-part', isAuthenticated, (req, res) => { // Protected
    const { part_id, shop_id, mechanic_name } = req.body;

    if (!part_id || !shop_id) {
        return res.status(400).json({ error: "部品IDと工場IDは必須です" });
    }

    // Shop users can only use parts from their own shop
    if (req.session.user.role === 'shop_user' && parseInt(shop_id) !== req.session.user.shop_id) {
        return res.status(403).json({ error: 'Forbidden: You can only use parts from your own shop' });
    }

    db.serialize(() => {
        db.run("BEGIN TRANSACTION;");

        // 在庫を1つ減らす
        const updateQuery = "UPDATE inventories SET quantity = quantity - 1 WHERE part_id = ? AND shop_id = ? AND quantity > 0";
        db.run(updateQuery, [part_id, shop_id], function(err) {
            if (err) {
                db.run("ROLLBACK;");
                return res.status(500).json({ error: "在庫更新エラー: " + err.message });
            }
            if (this.changes === 0) {
                db.run("ROLLBACK;");
                return res.status(400).json({ error: "在庫がないか、指定された部品/工場が見つかりません。" });
            }

            // 使用履歴をインサート
            const historyQuery = "INSERT INTO usage_history (part_id, shop_id, usage_time, mechanic_name) VALUES (?, ?, datetime('now', 'localtime'), ?)";
            db.run(historyQuery, [part_id, shop_id, mechanic_name || '不明'], function(err) {
                if (err) {
                    db.run("ROLLBACK;");
                    return res.status(500).json({ error: "履歴記録エラー: " + err.message });
                }

                // 更新後の在庫数と発注点を確認
                const selectQuery = `
                    SELECT i.quantity, i.min_reorder_level, p.part_name
                    FROM inventories i
                    JOIN parts p ON i.part_id = p.id
                    WHERE i.part_id = ? AND i.shop_id = ?
                `;
                db.get(selectQuery, [part_id, shop_id], (err, row) => {
                    if (err) {
                        console.error("Could not retrieve stock level for reorder alert:", err.message);
                        db.run("COMMIT;");
                        return res.json({ message: "使用記録が完了しました。", stock_left: "不明" });
                    }

                    if (row && row.quantity < row.min_reorder_level) {
                        console.log(`!!! 再発注アラート: [工場ID: ${shop_id}] ${row.part_name} が最低発注レベル (${row.min_reorder_level})を下回りました。現在の在庫: ${row.quantity}`);
                    }
                    db.run("COMMIT;");
                    res.json({ message: "使用記録が完了しました。", stock_left: row.quantity });
                });
            });
        });
    });
});



// -------------------------------------------------
// API (Admin Dashboard) - All protected by isAdmin middleware
// -------------------------------------------------

// --- Shop Management (Admin) ---
app.get('/api/admin/shops', isAuthenticated, isAdmin, (req, res) => {
    db.all("SELECT id, name FROM shops ORDER BY id", [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

app.post('/api/admin/shops', isAuthenticated, isAdmin, (req, res) => {
    const { name } = req.body;
    if (!name) {
        return res.status(400).json({ error: 'Shop name is required' });
    }
    db.run("INSERT INTO shops (name) VALUES (?)", [name], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ id: this.lastID, name });
    });
});

// --- Part Management (Admin) ---
app.get('/api/admin/parts', isAuthenticated, isAdmin, (req, res) => {
    db.all("SELECT id, part_number, part_name FROM parts ORDER BY id", [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

app.post('/api/admin/parts', isAuthenticated, isAdmin, (req, res) => {
    const { part_number, part_name } = req.body;
    if (!part_number || !part_name) {
        return res.status(400).json({ error: 'Part number and name are required' });
    }
    db.run("INSERT INTO parts (part_number, part_name) VALUES (?, ?)", [part_number, part_name], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ id: this.lastID, part_number, part_name });
    });
});

// --- User Management (Admin) ---
app.get('/api/admin/users', isAuthenticated, isAdmin, (req, res) => {
    db.all("SELECT id, username, role, shop_id FROM users ORDER BY id", [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

app.post('/api/admin/users', isAuthenticated, isAdmin, (req, res) => {
    const { username, password, role, shop_id } = req.body;
    if (!username || !password || !role) {
        return res.status(400).json({ error: 'Username, password, and role are required' });
    }
    if (role === 'shop_user' && !shop_id) {
        return res.status(400).json({ error: 'Shop ID is required for shop users' });
    }

    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) {
            return res.status(500).json({ error: 'Error hashing password' });
        }
        const finalShopId = role === 'admin' ? null : shop_id;
        db.run("INSERT INTO users (username, password_hash, role, shop_id) VALUES (?, ?, ?, ?)", [username, hash, role, finalShopId], function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ id: this.lastID, username, role, shop_id: finalShopId });
        });
    });
});

// --- Inventory Management (Admin) ---
app.get('/api/admin/all-inventory', isAuthenticated, isAdmin, (req, res) => {
    const sql = `
        SELECT s.name AS shop_name, p.part_number, p.part_name, i.quantity, i.min_reorder_level, i.location_info
        FROM inventories i
        JOIN shops s ON i.shop_id = s.id
        JOIN parts p ON i.part_id = p.id
        ORDER BY s.name, p.part_name
    `;
    db.all(sql, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

app.post('/api/admin/inventory', isAuthenticated, isAdmin, (req, res) => {
    const { shop_id, part_id, quantity, min_reorder_level, location_info } = req.body;
    if (!shop_id || !part_id || quantity === undefined || min_reorder_level === undefined) {
        return res.status(400).json({ error: 'Shop, part, quantity, and min_reorder_level are required' });
    }

    const sql = `
        INSERT INTO inventories (shop_id, part_id, quantity, min_reorder_level, location_info)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(part_id, shop_id) DO UPDATE SET
            quantity = excluded.quantity,
            min_reorder_level = excluded.min_reorder_level,
            location_info = excluded.location_info
    `;
    db.run(sql, [shop_id, part_id, quantity, min_reorder_level, location_info || ''], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: 'Inventory updated successfully' });
    });
});

// --- Reports (Admin) ---
app.get('/api/admin/all-usage-history', isAuthenticated, isAdmin, (req, res) => {
    const sql = `
        SELECT s.name AS shop_name, p.part_number, p.part_name, h.usage_time, h.mechanic_name
        FROM usage_history h
        JOIN shops s ON h.shop_id = s.id
        JOIN parts p ON h.part_id = p.id
        ORDER BY h.usage_time DESC
    `;
    db.all(sql, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});


app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

