const express = require('express');
require('dotenv').config(); // Load environment variables from .env file
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const multer = require('multer');

// --- Multer Setup for CSV upload ---
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const dbPath = process.env.NODE_ENV === 'test' ? ':memory:' : (process.env.DATABASE_PATH || './data/stock.db');

if (dbPath !== ':memory:') {
    const dbDir = path.dirname(dbPath);
    if (!fs.existsSync(dbDir)) {
        fs.mkdirSync(dbDir, { recursive: true });
    }
}

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error('Could not connect to database', err);
    else console.log('Connected to database at', dbPath);
});

const app = express();
const PORT = 3000;
const saltRounds = 10;

app.use(express.json());
app.use(express.static('public'));
app.use(cookieParser());
app.use(session({
    secret: 'a-very-secret-key-that-should-be-in-env',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

const dbRun = (sql, params = []) => new Promise((resolve, reject) => { db.run(sql, params, function(err) { if (err) reject(err); else resolve(this); }); });
const dbGet = (sql, params = []) => new Promise((resolve, reject) => { db.get(sql, params, (err, row) => { if (err) reject(err); else resolve(row); }); });
const dbAll = (sql, params = []) => new Promise((resolve, reject) => { db.all(sql, params, (err, rows) => { if (err) reject(err); else resolve(rows); }); });

const initializeDatabase = async () => {
    await dbRun(`CREATE TABLE IF NOT EXISTS shops (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE)`);
    await dbRun(`CREATE TABLE IF NOT EXISTS categories (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE)`);
    await dbRun(`CREATE TABLE IF NOT EXISTS parts (id INTEGER PRIMARY KEY AUTOINCREMENT, part_number TEXT NOT NULL UNIQUE, part_name TEXT NOT NULL, category_id INTEGER, FOREIGN KEY (category_id) REFERENCES categories(id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS inventories (id INTEGER PRIMARY KEY AUTOINCREMENT, part_id INTEGER NOT NULL, shop_id INTEGER NOT NULL, quantity INTEGER NOT NULL, min_reorder_level INTEGER NOT NULL, location_info TEXT, FOREIGN KEY (part_id) REFERENCES parts(id), FOREIGN KEY (shop_id) REFERENCES shops(id), UNIQUE(part_id, shop_id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS employees (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, shop_id INTEGER NOT NULL, is_active INTEGER DEFAULT 1, FOREIGN KEY (shop_id) REFERENCES shops(id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS usage_history (id INTEGER PRIMARY KEY AUTOINCREMENT, part_id INTEGER NOT NULL, shop_id INTEGER NOT NULL, employee_id INTEGER NOT NULL, usage_time TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', FOREIGN KEY (part_id) REFERENCES parts(id), FOREIGN KEY (shop_id) REFERENCES shops(id), FOREIGN KEY (employee_id) REFERENCES employees(id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, shop_id INTEGER, role TEXT NOT NULL, FOREIGN KEY (shop_id) REFERENCES shops(id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS cancellation_history (id INTEGER PRIMARY KEY AUTOINCREMENT, usage_history_id INTEGER NOT NULL, cancelled_by_user_id INTEGER NOT NULL, cancelled_at TEXT NOT NULL, reason TEXT, FOREIGN KEY (usage_history_id) REFERENCES usage_history(id), FOREIGN KEY (cancelled_by_user_id) REFERENCES users(id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS stocktake_history (id INTEGER PRIMARY KEY AUTOINCREMENT, part_id INTEGER NOT NULL, shop_id INTEGER NOT NULL, user_id INTEGER NOT NULL, stocktake_time TEXT NOT NULL, quantity_before INTEGER NOT NULL, quantity_after INTEGER NOT NULL, notes TEXT, FOREIGN KEY (part_id) REFERENCES parts(id), FOREIGN KEY (shop_id) REFERENCES shops(id), FOREIGN KEY (user_id) REFERENCES users(id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS replenishment_history (id INTEGER PRIMARY KEY AUTOINCREMENT, part_id INTEGER NOT NULL, shop_id INTEGER NOT NULL, user_id INTEGER NOT NULL, replenished_at TEXT NOT NULL, quantity_added INTEGER NOT NULL, FOREIGN KEY (part_id) REFERENCES parts(id), FOREIGN KEY (shop_id) REFERENCES shops(id), FOREIGN KEY (user_id) REFERENCES users(id))`);

    const shopsCount = await dbGet("SELECT COUNT(*) AS count FROM shops");
    if (shopsCount.count === 0) {
        console.log("Seeding initial data...");
        const shops = ["A整備工場", "B整備工場"];
        const categories = ["エンジン消耗品", "ブレーキ関連", "電装・点火系", "冷却系", "足回り・駆動系", "外装・その他", "ケミカル類"];
        const parts = [
            { pn: "EO-001", name: "エンジンオイル 5W-30 SN 4L", cat: 1 }, { pn: "EO-002", name: "エンジンオイル 0W-20 SP 4L", cat: 1 },
            { pn: "OF-001", name: "オイルフィルター トヨタ/ダイハツ用", cat: 1 }, { pn: "OF-002", name: "オイルフィルター ホンダ用", cat: 1 },
            { pn: "BP-001", name: "ディスクブレーキパッド フロント 軽自動車用", cat: 2 }, { pn: "BP-002", name: "ディスクブレーキパッド フロント 普通車用", cat: 2 },
            { pn: "BF-001", name: "ブレーキフルード DOT4 1L", cat: 2 }, { pn: "BT-001", name: "バッテリー 40B19L", cat: 3 },
            { pn: "BT-002", name: "バッテリー 60B24L", cat: 3 }, { pn: "SP-001", name: "スパークプラグ 標準 (BKR5E-11)", cat: 3 },
            { pn: "LLC-001", name: "ロングライフクーラント 緑 2L", cat: 4 }, { pn: "WB-001", name: "ワイパーブレード 450mm", cat: 6 },
            { pn: "PC-001", name: "パーツクリーナー 840ml", cat: 7 }
        ];

        for (const shop of shops) { await dbRun("INSERT INTO shops (name) VALUES (?)", [shop]); }
        for (const category of categories) { await dbRun("INSERT INTO categories (name) VALUES (?)", [category]); }
        for (const part of parts) { await dbRun("INSERT INTO parts (part_number, part_name, category_id) VALUES (?, ?, ?)", [part.pn, part.name, part.cat]); }

        await dbRun("INSERT INTO inventories (part_id, shop_id, quantity, min_reorder_level, location_info) VALUES (?, ?, ?, ?, ?)", [1, 1, 20, 5, "棚A-1"]);
        await dbRun("INSERT INTO inventories (part_id, shop_id, quantity, min_reorder_level, location_info) VALUES (?, ?, ?, ?, ?)", [3, 1, 15, 5, "棚A-2"]);
        await dbRun("INSERT INTO inventories (part_id, shop_id, quantity, min_reorder_level, location_info) VALUES (?, ?, ?, ?, ?)", [7, 1, 5, 2, "棚B-2"]);
        await dbRun("INSERT INTO inventories (part_id, shop_id, quantity, min_reorder_level, location_info) VALUES (?, ?, ?, ?, ?)", [8, 1, 8, 3, "棚C-1"]);
        await dbRun("INSERT INTO inventories (part_id, shop_id, quantity, min_reorder_level, location_info) VALUES (?, ?, ?, ?, ?)", [2, 2, 25, 5, "ラック1"]);
        await dbRun("INSERT INTO inventories (part_id, shop_id, quantity, min_reorder_level, location_info) VALUES (?, ?, ?, ?, ?)", [4, 2, 18, 5, "ラック1"]);

        const hash = await bcrypt.hash('password', saltRounds);
        await dbRun("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", ['admin', hash, 'admin']);
        console.log("Initial data seeded.");
    }
};

// --- Auth APIs ---
app.post('/api/login', async (req, res) => { const { username, password } = req.body; if (!username || !password) { return res.status(400).json({ error: 'Username and password are required' }); } try { const user = await dbGet("SELECT * FROM users WHERE username = ?", [username]); if (!user) { return res.status(401).json({ error: 'Invalid credentials' }); } const match = await bcrypt.compare(password, user.password_hash); if (match) { req.session.user = { id: user.id, username: user.username, role: user.role, shop_id: user.shop_id }; res.json({ message: 'Login successful', user: req.session.user }); } else { res.status(401).json({ error: 'Invalid credentials' }); } } catch (err) { res.status(500).json({ error: 'Server error' }); } });
app.post('/api/logout', (req, res) => { req.session.destroy(err => { if (err) { return res.status(500).json({ error: 'Could not log out' }); } res.clearCookie('connect.sid'); res.json({ message: 'Logout successful' }); }); });
app.get('/api/auth/status', (req, res) => { if (req.session.user) { res.json({ loggedIn: true, user: req.session.user }); } else { res.json({ loggedIn: false }); } });

app.get('/api/employees', isAuthenticated, isShopUser, async (req, res) => {
    try {
        const employees = await dbAll(
            "SELECT id, name, is_active FROM employees WHERE shop_id = ? ORDER BY name",
            [req.session.user.shop_id]
        );
        res.json(employees);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/employees', isAuthenticated, isShopUser, async (req, res) => {
    const { name } = req.body;
    const shop_id = req.session.user.shop_id;
    if (!name) {
        return res.status(400).json({ error: 'Employee name is required' });
    }
    try {
        const result = await dbRun("INSERT INTO employees (name, shop_id) VALUES (?, ?)", [name, shop_id]);
        res.status(201).json({ id: result.lastID, name, shop_id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/employees/:id', isAuthenticated, isShopUser, async (req, res) => {
    const { id } = req.params;
    const { name, is_active } = req.body;
    const shop_id = req.session.user.shop_id;

    if (!name || is_active === undefined) {
        return res.status(400).json({ error: 'Name and is_active are required' });
    }

    try {
        // Ensure the employee belongs to the user's shop before updating
        const employee = await dbGet("SELECT id FROM employees WHERE id = ? AND shop_id = ?", [id, shop_id]);
        if (!employee) {
            return res.status(404).json({ error: 'Employee not found in your shop' });
        }

        const result = await dbRun("UPDATE employees SET name = ?, is_active = ? WHERE id = ?", [name, is_active, id]);
        if (result.changes === 0) {
            return res.status(404).json({ error: 'Employee not found' });
        }
        res.json({ message: 'Employee updated successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- Middleware ---
function isAuthenticated(req, res, next) { if (req.session.user) { next(); } else { res.status(401).json({ error: 'Unauthorized' }); } }
function isAdmin(req, res, next) { if (req.session.user && req.session.user.role === 'admin') { next(); } else { res.status(403).json({ error: 'Forbidden: Admin access required' }); } }
function isShopUser(req, res, next) { if (req.session.user && req.session.user.role === 'shop_user' && req.session.user.shop_id) { next(); } else { res.status(403).json({ error: 'Forbidden: Shop user access required' }); } }

// --- General User APIs ---
app.get('/api/shops', isAuthenticated, async (req, res) => { try { if (req.session.user.role === 'admin') { const rows = await dbAll("SELECT id, name FROM shops ORDER BY name"); res.json(rows); } else if (req.session.user.role === 'shop_user' && req.session.user.shop_id) { const row = await dbGet("SELECT id, name FROM shops WHERE id = ?", [req.session.user.shop_id]); res.json(row ? [row] : []); } else { res.status(403).json({ error: 'Forbidden: Invalid role or shop_id' }); } } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/shops/:shopId/inventory', isAuthenticated, async (req, res) => { const { shopId } = req.params;
 if (req.session.user.role === 'shop_user' && parseInt(shopId) !== req.session.user.shop_id) {
 return res.status(403).json({ error: "Forbidden: You can only view your own shop's inventory" });
 }
 const sql = `
        SELECT 
            p.id, 
            p.part_number, 
            p.part_name, 
            c.id as category_id, 
            c.name as category_name, 
            i.quantity, 
            i.min_reorder_level, 
            i.location_info 
        FROM 
            parts p 
        JOIN 
            inventories i ON p.id = i.part_id 
        LEFT JOIN 
            categories c ON p.category_id = c.id 
        WHERE i.shop_id = ? 
        ORDER BY c.name, p.part_name;`;
 try {
 const rows = await dbAll(sql, [shopId]);
 res.json(rows);
 } catch (err) {
 res.status(500).json({ error: err.message });
 }
});
app.post('/api/use-part', isAuthenticated, async (req, res) => { const { part_id, shop_id, employee_id } = req.body;
 if (!part_id || !shop_id || !employee_id) {
 return res.status(400).json({ error: "部品ID、工場ID、従業員IDは必須です" });
 }
 if (req.session.user.role === 'shop_user' && parseInt(shop_id) !== req.session.user.shop_id) {
 return res.status(403).json({ error: 'Forbidden: You can only use parts from your own shop' });
 }
 try {
 await dbRun("BEGIN TRANSACTION;");
 const result = await dbRun("UPDATE inventories SET quantity = quantity - 1 WHERE part_id = ? AND shop_id = ? AND quantity > 0", [part_id, shop_id]);
 if (result.changes === 0) {
 await dbRun("ROLLBACK;");
 return res.status(400).json({ error: "在庫がないか、在庫更新に失敗しました。" });
 }
 await dbRun("INSERT INTO usage_history (part_id, shop_id, usage_time, employee_id) VALUES (?, ?, datetime('now', 'localtime'), ?)", [part_id, shop_id, employee_id]);
 const row = await dbGet(`SELECT i.quantity, i.min_reorder_level, p.part_name FROM inventories i JOIN parts p ON i.part_id = p.id WHERE i.part_id = ? AND i.shop_id = ?`, [part_id, shop_id]);
 if (row && row.quantity < row.min_reorder_level) {
 console.log(`!!! 再発注アラート: [工場ID: ${shop_id}] ${row.part_name} が最低発注レベル (${row.min_reorder_level})を下回りました。現在の在庫: ${row.quantity}`);
 }
 await dbRun("COMMIT;");
 res.json({ message: "使用記録が完了しました。", stock_left: row ? row.quantity : 0 });
 } catch (err) {
 await dbRun("ROLLBACK;");
 res.status(500).json({ error: "トランザクションエラー: " + err.message });
 }
});
app.get('/api/usage-history', isAuthenticated, isShopUser, async (req, res) => { const shop_id = req.session.user.shop_id;
 let { month } = req.query;
 if (!month) {
 const now = new Date();
 month = `${now.getFullYear()}-${(now.getMonth() + 1).toString().padStart(2, '0')}`;
 }
 const sql = `SELECT h.id, p.part_number, p.part_name, h.usage_time, e.name as employee_name, h.status FROM usage_history h JOIN parts p ON h.part_id = p.id JOIN employees e ON h.employee_id = e.id WHERE h.shop_id = ? AND STRFTIME('%Y-%m', h.usage_time) = ? ORDER BY h.usage_time DESC`;
 try {
 const rows = await dbAll(sql, [shop_id, month]);
 res.json(rows);
 } catch (err) {
 res.status(500).json({ error: err.message });
 }
});
app.post('/api/cancel-usage', isAuthenticated, async (req, res) => { const { usage_id, reason } = req.body;
 const cancelled_by_user_id = req.session.user.id;
 if (!usage_id) {
 return res.status(400).json({ error: 'Usage ID is required.' });
 }
 try {
 await dbRun("BEGIN TRANSACTION;");
 const usage = await dbGet("SELECT * FROM usage_history WHERE id = ? AND status = 'active'", [usage_id]);
 if (!usage) {
 await dbRun("ROLLBACK;");
 return res.status(404).json({ error: "Active usage record not found or already cancelled." });
 }
 await dbRun("UPDATE usage_history SET status = 'cancelled' WHERE id = ?", [usage_id]);
 await dbRun("UPDATE inventories SET quantity = quantity + 1 WHERE part_id = ? AND shop_id = ?", [usage.part_id, usage.shop_id]);
 await dbRun(`INSERT INTO cancellation_history (usage_history_id, cancelled_by_user_id, cancelled_at, reason) VALUES (?, ?, datetime('now', 'localtime'), ?)`, [usage_id, cancelled_by_user_id, reason]);
 await dbRun("COMMIT;");
 res.json({ message: "Usage successfully cancelled and inventory restored." });
 } catch (err) {
 await dbRun("ROLLBACK;");
 res.status(500).json({ error: "Transaction failed during cancellation.", details: err.message });
 }
});

// --- Admin APIs ---
app.get('/api/admin/shops', isAuthenticated, isAdmin, async (req, res) => { try { const rows = await dbAll("SELECT id, name FROM shops ORDER BY id"); res.json(rows); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/shops', isAuthenticated, isAdmin, async (req, res) => { const { name } = req.body;
 if (!name) {
 return res.status(400).json({ error: 'Shop name is required' });
 }
 try {
 const result = await dbRun("INSERT INTO shops (name) VALUES (?)", [name]);
 res.json({ id: result.lastID, name });
 } catch (err) {
 res.status(500).json({ error: err.message });
 }
});
app.put('/api/admin/shops/:id', isAuthenticated, isAdmin, async (req, res) => { const { id } = req.params;
 const { name } = req.body;
 if (!name) {
 return res.status(400).json({ error: 'Shop name is required' });
 }
 try {
 await dbRun("UPDATE shops SET name = ? WHERE id = ?", [name, id]);
 res.json({ message: 'Shop updated successfully' });
 } catch (err) {
 res.status(500).json({ error: err.message });
 }
});
app.delete('/api/admin/shops/:id', isAuthenticated, isAdmin, async (req, res) => { const { id } = req.params;
 try {
 const userCount = await dbGet("SELECT COUNT(*) AS count FROM users WHERE shop_id = ?", [id]);
 if (userCount.count > 0) {
 return res.status(400).json({ error: 'Cannot delete shop: Users are still assigned to it.' });
 }
 const invCount = await dbGet("SELECT COUNT(*) AS count FROM inventories WHERE shop_id = ?", [id]);
 if (invCount.count > 0) {
 return res.status(400).json({ error: 'Cannot delete shop: Inventory is still assigned to it.' });
 }
 const result = await dbRun("DELETE FROM shops WHERE id = ?", [id]);
 if (result.changes === 0) {
 return res.status(404).json({ error: 'Shop not found' });
 }
 res.json({ message: 'Shop deleted successfully' });
 } catch (err) {
 res.status(500).json({ error: err.message });
 }
});

app.get('/api/admin/categories', isAuthenticated, isAdmin, async (req, res) => { try { const rows = await dbAll("SELECT id, name FROM categories ORDER BY id"); res.json(rows); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/categories', isAuthenticated, isAdmin, async (req, res) => { const { name } = req.body;
 if (!name) {
 return res.status(400).json({ error: 'Category name is required' });
 }
 try {
 const result = await dbRun("INSERT INTO categories (name) VALUES (?)", [name]);
 res.json({ id: result.lastID, name });
 } catch (err) {
 res.status(500).json({ error: err.message });
 }
});
app.put('/api/admin/categories/:id', isAuthenticated, isAdmin, async (req, res) => { const { id } = req.params;
 const { name } = req.body;
 if (!name) {
 return res.status(400).json({ error: 'Category name is required' });
 }
 try {
 await dbRun("UPDATE categories SET name = ? WHERE id = ?", [name, id]);
 res.json({ message: 'Category updated successfully' });
 } catch (err) {
 res.status(500).json({ error: err.message });
 }
});
app.delete('/api/admin/categories/:id', isAuthenticated, isAdmin, async (req, res) => { const { id } = req.params;
 try {
 const partCount = await dbGet("SELECT COUNT(*) AS count FROM parts WHERE category_id = ?", [id]);
 if (partCount.count > 0) {
 return res.status(400).json({ error: 'Cannot delete category: Parts are still assigned to it.' });
 }
 const result = await dbRun("DELETE FROM categories WHERE id = ?", [id]);
 if (result.changes === 0) {
 return res.status(404).json({ error: 'Category not found' });
 }
 res.json({ message: 'Category deleted successfully' });
 } catch (err) {
 res.status(500).json({ error: err.message });
 }
});

app.get('/api/admin/parts', isAuthenticated, isAdmin, async (req, res) => { const sql = `SELECT p.id, p.part_number, p.part_name, p.category_id, c.name as category_name FROM parts p LEFT JOIN categories c ON p.category_id = c.id ORDER BY p.id`; try { const rows = await dbAll(sql); res.json(rows); } catch (err) { res.status(500).json({ error: err.message }); } });

app.get('/api/admin/parts/uncategorized', isAuthenticated, isAdmin, async (req, res) => {
    const sql = `SELECT id, part_number, part_name FROM parts WHERE category_id IS NULL ORDER BY id`;
    try {
        const rows = await dbAll(sql);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.post('/api/admin/parts', isAuthenticated, isAdmin, async (req, res) => { const { part_number, part_name, category_id } = req.body;
 if (!part_number || !part_name) {
 return res.status(400).json({ error: 'Part number and name are required' });
 }
 try {
 const result = await dbRun("INSERT INTO parts (part_number, part_name, category_id) VALUES (?, ?, ?)", [part_number, part_name, category_id]);
 res.json({ id: result.lastID, part_number, part_name, category_id });
 } catch (err) {
 res.status(500).json({ error: err.message });
 }
});
app.put('/api/admin/parts/:id', isAuthenticated, isAdmin, async (req, res) => { const { id } = req.params;
 const { part_number, part_name, category_id } = req.body;
 if (!part_number || !part_name) {
 return res.status(400).json({ error: 'Part number and name are required' });
 }
 try {
 await dbRun("UPDATE parts SET part_number = ?, part_name = ?, category_id = ? WHERE id = ?", [part_number, part_name, category_id, id]);
 res.json({ message: 'Part updated successfully' });
 } catch (err) {
 res.status(500).json({ error: err.message });
 }
});

app.put('/api/admin/parts/:id/category', isAuthenticated, isAdmin, async (req, res) => {
    const { id } = req.params;
    const { categoryId } = req.body;
    try {
        await dbRun("UPDATE parts SET category_id = ? WHERE id = ?", [categoryId, id]);
        res.json({ message: 'Category updated successfully.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.delete('/api/admin/parts/:id', isAuthenticated, isAdmin, async (req, res) => { const { id } = req.params;
 try {
 const invCount = await dbGet("SELECT COUNT(*) AS count FROM inventories WHERE part_id = ?", [id]);
 if (invCount.count > 0) {
 return res.status(400).json({ error: 'Cannot delete part: It still exists in some inventories.' });
 }
 const result = await dbRun("DELETE FROM parts WHERE id = ?", [id]);
 if (result.changes === 0) {
 return res.status(404).json({ error: 'Part not found' });
 }
 res.json({ message: 'Part deleted successfully' });
 } catch (err) {
 res.status(500).json({ error: err.message });
 }
});

app.delete('/api/admin/parts', isAuthenticated, isAdmin, async (req, res) => {
    const { partIds } = req.body;
    if (!partIds || !Array.isArray(partIds) || partIds.length === 0) {
        return res.status(400).json({ error: 'partIds array is required.' });
    }

    try {
        // Check if any of the parts are in use
        const placeholders = partIds.map(() => '?').join(',');
        const invCountSql = `SELECT COUNT(*) AS count FROM inventories WHERE part_id IN (${placeholders})`;
        const invCount = await dbGet(invCountSql, partIds);
        if (invCount.count > 0) {
            return res.status(400).json({ error: '削除できません: 選択された部品のいくつかは、いずれかの工場の在庫として登録されています。' });
        }

        // Proceed with deletion
        const deleteSql = `DELETE FROM parts WHERE id IN (${placeholders})`;
        const result = await dbRun(deleteSql, partIds);

        if (result.changes === 0) {
            return res.status(404).json({ error: '削除対象の部品が見つかりませんでした。' });
        }
        res.json({ message: `${result.changes}件の部品を削除しました。` });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/parts/csv', isAuthenticated, isAdmin, async (req, res) => { const sql = `SELECT p.id, p.part_number, p.part_name, c.name as category_name FROM parts p LEFT JOIN categories c ON p.category_id = c.id ORDER BY p.id`; try { const rows = await dbAll(sql); if (!rows || rows.length === 0) { return res.status(404).send('No parts to export.'); } const header = 'ID,Part Number,Part Name,Category Name\n'; const csvRows = rows.map(row => `"${row.id}","${row.part_number}","${row.part_name}","${row.category_name || ''}"`);  const csvString = header + csvRows.join('\n');
        const bom = '\uFEFF';
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="parts-master.csv"');
        res.status(200).send(Buffer.from(bom + csvString, 'utf8')); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/parts/csv', isAuthenticated, isAdmin, upload.single('csvFile'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'CSVファイルがアップロードされていません。' });
    }

    const csvData = req.file.buffer.toString('utf-8');
    const rows = csvData.split('\n').map(row => row.trim()).filter(row => row);
    if (rows.length < 2) {
        return res.status(400).json({ error: 'CSVにヘッダー行とデータ行が含まれていません。' });
    }

    const header = rows.shift().toLowerCase().split(',').map(h => h.trim().replace(/^"|"$/g, ''));

    const partNumberAliases = ['part_number', 'part-number', 'part number', '部品番号', '品番'];
    const partNameAliases = ['part_name', 'part-name', 'part name', '部品名', '品名'];
    const categoryNameAliases = ['category_name', 'category', 'カテゴリー名', 'カテゴリー'];

    let partNumberIndex = -1;
    let partNameIndex = -1;
    let categoryNameIndex = -1;

    header.forEach((h, i) => {
        if (partNumberAliases.includes(h)) partNumberIndex = i;
        if (partNameAliases.includes(h)) partNameIndex = i;
        if (categoryNameAliases.includes(h)) categoryNameIndex = i;
    });

    if (partNumberIndex === -1) {
        return res.status(400).json({ error: `CSVヘッダーに部品番号を示す列が見つかりません。次のいずれかの列名を使用してください: ${partNumberAliases.join(', ')}` });
    }
    if (partNameIndex === -1) {
        return res.status(400).json({ error: `CSVヘッダーに部品名を示す列が見つかりません。次のいずれかの列名を使用してください: ${partNameAliases.join(', ')}` });
    }

    try {
        await dbRun("BEGIN TRANSACTION;");

        let uncategorized = await dbGet("SELECT id FROM categories WHERE name = ?", ['未分類']);
        if (!uncategorized) {
            const result = await dbRun("INSERT INTO categories (name) VALUES (?)", ['未分類']);
            uncategorized = { id: result.lastID };
        }
        const uncategorizedId = uncategorized.id;

        let successCount = 0;
        let errorCount = 0;
        const errors = [];

        for (const [index, row] of rows.entries()) {
            const fields = row.split(',').map(field => field.trim().replace(/^"|"$/g, ''));
            const part_number = fields[partNumberIndex];

            if (!part_number) {
                errors.push(`行 ${index + 2}: 部品番号が空です。`);
                errorCount++;
                continue;
            }

            const part_name = fields[partNameIndex] || part_number;
            const category_name = (categoryNameIndex !== -1) ? fields[categoryNameIndex] : null;
            let categoryId = uncategorizedId;

            if (category_name) {
                const category = await dbGet("SELECT id FROM categories WHERE name = ?", [category_name]);
                if (category) {
                    categoryId = category.id;
                } else {
                    const result = await dbRun("INSERT INTO categories (name) VALUES (?)", [category_name]);
                    categoryId = result.lastID;
                }
            }

            const existingPart = await dbGet("SELECT id FROM parts WHERE part_number = ?", [part_number]);
            if (existingPart) {
                await dbRun("UPDATE parts SET part_name = ?, category_id = ? WHERE id = ?", [part_name, categoryId, existingPart.id]);
            } else {
                await dbRun("INSERT INTO parts (part_number, part_name, category_id) VALUES (?, ?, ?)", [part_number, part_name, categoryId]);
            }
            successCount++;
        }

        if (errorCount > 0) {
            await dbRun("ROLLBACK;");
            return res.status(400).json({ error: "CSVインポートはエラーのため中断されました。", details: errors });
        }

        await dbRun("COMMIT;");
        res.json({ message: "CSVインポートが正常に完了しました。", summary: `処理件数: ${successCount}件。` });
    } catch (err) {
        await dbRun("ROLLBACK;");
        res.status(500).json({ error: '予期せぬサーバーエラーが発生しました。', details: err.message });
    }
});

app.get('/api/admin/users', isAuthenticated, isAdmin, async (req, res) => { try { const rows = await dbAll("SELECT id, username, role, shop_id FROM users ORDER BY id"); res.json(rows); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/users', isAuthenticated, isAdmin, async (req, res) => { const { username, password, role, shop_id } = req.body;
 if (!username || !password || !role) {
 return res.status(400).json({ error: 'Username, password, and role are required' });
 }
 if (role === 'shop_user' && !shop_id) {
 return res.status(400).json({ error: 'Shop ID is required for shop users' });
 }
 try {
 const hash = await bcrypt.hash(password, saltRounds);
 const finalShopId = role === 'admin' ? null : shop_id;
 const result = await dbRun("INSERT INTO users (username, password_hash, role, shop_id) VALUES (?, ?, ?, ?)", [username, hash, role, finalShopId]);
 res.json({ id: result.lastID, username, role, shop_id: finalShopId });
 } catch (err) {
 res.status(500).json({ error: err.message });
 }
});
app.put('/api/admin/users/:id', isAuthenticated, isAdmin, async (req, res) => { const { id } = req.params;
 const { username, role, shop_id, password } = req.body;
 if (!username || !role) {
 return res.status(400).json({ error: 'Username and role are required' });
 }
 if (role === 'shop_user' && !shop_id) {
 return res.status(400).json({ error: 'Shop ID is required for shop users' });
 }
 try {
 if (password) {
 const hash = await bcrypt.hash(password, saltRounds);
 const finalShopId = role === 'admin' ? null : shop_id;
 await dbRun("UPDATE users SET username = ?, password_hash = ?, role = ?, shop_id = ? WHERE id = ?", [username, hash, role, finalShopId, id]);
 } else {
 const finalShopId = role === 'admin' ? null : shop_id;
 await dbRun("UPDATE users SET username = ?, role = ?, shop_id = ? WHERE id = ?", [username, role, finalShopId, id]);
 }
 res.json({ message: 'User updated successfully' });
 } catch (err) {
 res.status(500).json({ error: err.message });
 }
});
app.delete('/api/admin/users/:id', isAuthenticated, isAdmin, async (req, res) => { const { id } = req.params;
 if (parseInt(id, 10) === req.session.user.id) {
 return res.status(400).json({ error: 'You cannot delete your own account.' });
 }
 try {
 const result = await dbRun("DELETE FROM users WHERE id = ?", [id]);
 if (result.changes === 0) {
 return res.status(404).json({ error: 'User not found' });
 }
 res.json({ message: 'User deleted successfully' });
 } catch (err) {
 res.status(500).json({ error: err.message });
 }
});

// --- Admin Employee Management ---
app.get('/api/admin/employees', isAuthenticated, isAdmin, async (req, res) => {
    const { shop_id } = req.query;
    let sql = `SELECT e.id, e.name, e.shop_id, s.name as shop_name, e.is_active FROM employees e JOIN shops s ON e.shop_id = s.id`;
    const params = [];
    if (shop_id) {
        sql += ' WHERE e.shop_id = ?';
        params.push(shop_id);
    }
    sql += ' ORDER BY s.name, e.name';
    try {
        const rows = await dbAll(sql, params);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/employees', isAuthenticated, isAdmin, async (req, res) => {
    const { name, shop_id } = req.body;
    if (!name || !shop_id) {
        return res.status(400).json({ error: 'Employee name and shop_id are required' });
    }
    try {
        const result = await dbRun("INSERT INTO employees (name, shop_id) VALUES (?, ?)", [name, shop_id]);
        res.status(201).json({ id: result.lastID, name, shop_id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/admin/employees/:id', isAuthenticated, isAdmin, async (req, res) => {
    const { id } = req.params;
    const { name, shop_id, is_active } = req.body;
    if (!name || !shop_id || is_active === undefined) {
        return res.status(400).json({ error: 'Name, shop_id, and is_active are required' });
    }
    try {
        const result = await dbRun("UPDATE employees SET name = ?, shop_id = ?, is_active = ? WHERE id = ?", [name, shop_id, is_active, id]);
        if (result.changes === 0) {
            return res.status(404).json({ error: 'Employee not found' });
        }
        res.json({ message: 'Employee updated successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/employees/:id', isAuthenticated, isAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        // We might want to check for usage history before deleting.
        // For now, we'll just delete.
        const result = await dbRun("DELETE FROM employees WHERE id = ?", [id]);
        if (result.changes === 0) {
            return res.status(404).json({ error: 'Employee not found' });
        }
        res.json({ message: 'Employee deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


app.get('/api/admin/inventory/locations', isAuthenticated, isAdmin, async (req, res) => { try { const rows = await dbAll("SELECT DISTINCT location_info FROM inventories WHERE location_info IS NOT NULL AND location_info != '' ORDER BY location_info"); res.json(rows.map(r => r.location_info)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/admin/all-inventory', isAuthenticated, isAdmin, async (req, res) => { const sql = `SELECT i.part_id, i.shop_id, s.name AS shop_name, p.part_number, p.part_name, i.quantity, i.min_reorder_level, i.location_info FROM inventories i JOIN shops s ON i.shop_id = s.id JOIN parts p ON i.part_id = p.id ORDER BY s.name, p.part_name`; try { const rows = await dbAll(sql); res.json(rows); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/inventory', isAuthenticated, isAdmin, async (req, res) => { const { shop_id, part_id, quantity, min_reorder_level, location_info } = req.body;
 if (!shop_id || !part_id || quantity === undefined || min_reorder_level === undefined) {
 return res.status(400).json({ error: 'Shop, part, quantity, and min_reorder_level are required' });
 }
 const sql = `INSERT INTO inventories (shop_id, part_id, quantity, min_reorder_level, location_info) VALUES (?, ?, ?, ?, ?) ON CONFLICT(part_id, shop_id) DO UPDATE SET quantity = excluded.quantity, min_reorder_level = excluded.min_reorder_level, location_info = excluded.location_info`;
 try {
 await dbRun(sql, [shop_id, part_id, quantity, min_reorder_level, location_info || '']);
 res.json({ message: 'Inventory updated successfully' });
 } catch (err) {
 res.status(500).json({ error: err.message });
 }
});

app.delete('/api/admin/inventory', isAuthenticated, isAdmin, async (req, res) => {
    const { shop_id, part_id } = req.body;
    if (!shop_id || !part_id) {
        return res.status(400).json({ error: 'shop_id and part_id are required' });
    }
    try {
        const result = await dbRun("DELETE FROM inventories WHERE shop_id = ? AND part_id = ?", [shop_id, part_id]);
        if (result.changes === 0) {
            return res.status(404).json({ error: 'Inventory entry not found' });
        }
        res.json({ message: 'Inventory entry deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.post('/api/admin/inventory/csv', isAuthenticated, isAdmin, async (req, res) => { const { csvData } = req.body;
 if (!csvData) {
 return res.status(400).json({ error: 'CSV data is missing.' });
 }
 const rows = csvData.split('\n').map(row => row.trim()).filter(row => row);
 rows.shift();
 try {
 await dbRun("BEGIN TRANSACTION;");
 let successCount = 0;
 let errorCount = 0;
 const errors = [];
 for (const [index, row] of rows.entries()) {
 const [part_number, shop_name, quantity, min_reorder_level, location_info] = row.split(',').map(field => field.trim().replace(/^"|"$/g, ''));
 if (!part_number || !shop_name || quantity === undefined || min_reorder_level === undefined) {
 errors.push(`Row ${index + 1}: Invalid data - ${row}`);
 errorCount++;
 continue;
 }
 const part = await dbGet("SELECT id FROM parts WHERE part_number = ?", [part_number]);
 const shop = await dbGet("SELECT id FROM shops WHERE name = ?", [shop_name]);
 if (!part) {
 errors.push(`Row ${index + 1}: Part number not found - ${part_number}`);
 errorCount++;
 continue;
 }
 if (!shop) {
 errors.push(`Row ${index + 1}: Shop name not found - ${shop_name}`);
 errorCount++;
 continue;
 }
 const sql = `INSERT INTO inventories (part_id, shop_id, quantity, min_reorder_level, location_info) VALUES (?, ?, ?, ?, ?) ON CONFLICT(part_id, shop_id) DO UPDATE SET quantity = excluded.quantity, min_reorder_level = excluded.min_reorder_level, location_info = excluded.location_info;`;
 await dbRun(sql, [part.id, shop.id, parseInt(quantity), parseInt(min_reorder_level), location_info || '']);
 successCount++;
 }
 if (errorCount > 0) {
 await dbRun("ROLLBACK;");
 return res.status(400).json({ error: "CSV import failed due to errors. No data was imported.", details: errors });
 }
 await dbRun("COMMIT;");
 res.json({ message: "Inventory CSV import successful.", summary: `Success: ${successCount}, Failed: ${errorCount}` });
 } catch (err) {
 await dbRun("ROLLBACK;");
 res.status(500).json({ error: 'An unexpected error occurred.', details: err.message });
 }
});
app.post('/api/admin/inventory/stocktake', isAuthenticated, isAdmin, async (req, res) => { const { shop_id, stocktakeData } = req.body;
 const user_id = req.session.user.id;
 if (!shop_id || !Array.isArray(stocktakeData)) {
 return res.status(400).json({ error: 'Shop ID and stocktake data are required.' });
 }
 try {
 await dbRun("BEGIN TRANSACTION;");
 let updatedCount = 0;
 for (const item of stocktakeData) {
 if (item.part_id == null || item.actual_quantity == null) continue;
 const row = await dbGet("SELECT quantity FROM inventories WHERE part_id = ? AND shop_id = ?", [item.part_id, shop_id]);
 if (row && row.quantity !== item.actual_quantity) {
 await dbRun("UPDATE inventories SET quantity = ? WHERE part_id = ? AND shop_id = ?", [item.actual_quantity, item.part_id, shop_id]);
 const historySql = `INSERT INTO stocktake_history (part_id, shop_id, user_id, stocktake_time, quantity_before, quantity_after, notes) VALUES (?, ?, ?, datetime('now', 'localtime'), ?, ?, ?)`;
 await dbRun(historySql, [item.part_id, shop_id, user_id, row.quantity, item.actual_quantity, '棚卸しによる更新']);
 updatedCount++;
 }
 }
 await dbRun("COMMIT;");
 res.json({ message: `Stocktake completed successfully. ${updatedCount} items updated.` });
 } catch (err) {
 console.error('Stocktake transaction failed:', err);
 try {
 await dbRun("ROLLBACK;");
 res.status(500).json({ error: 'Stocktake failed and was rolled back.', details: err.message });
 } catch (rollbackErr) {
 console.error('Rollback failed:', rollbackErr);
 res.status(500).json({ error: 'A critical error occurred during transaction rollback.' });
 }
 }
});

app.post('/api/admin/inventory/replenish', isAuthenticated, isAdmin, async (req, res) => {
    const { shop_id, part_id, quantity_added } = req.body;
    const user_id = req.session.user.id;

    if (!shop_id || !part_id || !quantity_added) {
        return res.status(400).json({ error: '工場、部品、および補充数量は必須です。' });
    }

    const quantity = parseInt(quantity_added, 10);
    if (isNaN(quantity) || quantity <= 0) {
        return res.status(400).json({ error: '補充数量は正の整数である必要があります。' });
    }

    try {
        await dbRun("BEGIN TRANSACTION;");

        // Check if inventory entry exists
        const inventory = await dbGet("SELECT id FROM inventories WHERE part_id = ? AND shop_id = ?", [part_id, shop_id]);
        
        if (inventory) {
            // Update existing inventory
            await dbRun("UPDATE inventories SET quantity = quantity + ? WHERE id = ?", [quantity, inventory.id]);
        } else {
            // Create new inventory entry if it doesn't exist. Default min_reorder_level to 0.
            await dbRun("INSERT INTO inventories (part_id, shop_id, quantity, min_reorder_level, location_info) VALUES (?, ?, ?, 0, '')", [part_id, shop_id, quantity]);
        }

        // Log the replenishment
        await dbRun(
            `INSERT INTO replenishment_history (part_id, shop_id, user_id, replenished_at, quantity_added) VALUES (?, ?, ?, datetime('now', 'localtime'), ?)`,
            [part_id, shop_id, user_id, quantity]
        );

        await dbRun("COMMIT;");
        
        const new_quantity = await dbGet("SELECT quantity FROM inventories WHERE part_id = ? AND shop_id = ?", [part_id, shop_id]);

        res.json({ message: '在庫の補充が正常に完了しました。', new_quantity: new_quantity.quantity });
    } catch (err) {
        await dbRun("ROLLBACK;");
        res.status(500).json({ error: '補充処理中にエラーが発生しました。', details: err.message });
    }
});


app.get('/api/admin/all-usage-history', isAuthenticated, isAdmin, async (req, res) => { const { startDate, endDate, shopId, partId } = req.query;
 let sql = `SELECT 
                s.name AS shop_name, 
                p.part_number, 
                p.part_name, 
                h.usage_time, 
                e.name as employee_name,
                h.status,
                ch.reason as cancellation_reason
            FROM 
                usage_history h
            LEFT JOIN 
                shops s ON h.shop_id = s.id 
            LEFT JOIN 
                parts p ON h.part_id = p.id 
            LEFT JOIN 
                employees e ON h.employee_id = e.id
            LEFT JOIN
                cancellation_history ch ON h.id = ch.usage_history_id`;
 const whereClauses = [];
 const params = [];
 if (startDate) {
 whereClauses.push("h.usage_time >= ?");
 params.push(startDate);
 }
 if (endDate) {
 whereClauses.push("h.usage_time <= ?");
 params.push(endDate + ' 23:59:59');
 }
 if (shopId) {
 whereClauses.push("h.shop_id = ?");
 params.push(shopId);
 }
 if (partId) {
 whereClauses.push("h.part_id = ?");
 params.push(partId);
 }
 if (whereClauses.length > 0) {
 sql += " WHERE " + whereClauses.join(" AND ");
 }
 sql += " ORDER BY h.usage_time DESC";
 try {
 const rows = await dbAll(sql, params);
 res.json(rows);
 } catch (err) {
 res.status(500).json({ error: err.message });
 }
});
app.get('/api/admin/reorder-list', isAuthenticated, isAdmin, async (req, res) => { const sql = `SELECT s.name AS shop_name, p.part_number, p.part_name, i.quantity, i.min_reorder_level, (i.min_reorder_level - i.quantity) AS shortage FROM inventories i JOIN shops s ON i.shop_id = s.id JOIN parts p ON i.part_id = p.id WHERE i.quantity < i.min_reorder_level ORDER BY s.name, shortage DESC, p.part_name`; try { const rows = await dbAll(sql); res.json(rows); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/admin/reorder-list/csv', isAuthenticated, isAdmin, async (req, res) => { const sql = `SELECT s.name AS shop_name, p.part_number, p.part_name, i.quantity, i.min_reorder_level, (i.min_reorder_level - i.quantity) AS shortage FROM inventories i JOIN shops s ON i.shop_id = s.id JOIN parts p ON i.part_id = p.id WHERE i.quantity < i.min_reorder_level ORDER BY s.name, shortage DESC, p.part_name`; try { const rows = await dbAll(sql); if (!rows || rows.length === 0) { return res.status(404).send('No items to export.'); } const header = '工場名,品番,部品名,現在庫数,最低発注レベル,不足数\n'; const csvRows = rows.map(row => `"${row.shop_name}","${row.part_number}","${row.part_name}",${row.quantity},${row.min_reorder_level},${row.shortage}`); const csvString = header + csvRows.join('\n');
        const bom = '\uFEFF';
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="reorder-list.csv"');
        res.status(200).send(Buffer.from(bom + csvString, 'utf8')); } catch (err) { res.status(500).json({ error: err.message }); } });

// --- Server Start ---
const startServer = async () => {
    await initializeDatabase();
    if (require.main === module) {
        app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
    }
};

if (process.env.NODE_ENV !== 'test') {
    startServer();
}

module.exports = { app, initializeDatabase, db };