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
// ルートURLへのアクセス時にlogin.htmlを直接表示
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.use(express.static('public'));
app.use(cookieParser());
if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1); // Nginx, ngrokなどのリバースプロキシを信頼する
}

app.use(session({
    secret: 'a-very-secret-key-that-should-be-in-env',
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // 本番環境ではhttpsのみ
        httpOnly: true, // クライアントサイドJSからのアクセスを禁止
        sameSite: 'lax' // CSRF対策
    }
}));

const dbRun = (sql, params = []) => new Promise((resolve, reject) => { db.run(sql, params, function(err) { if (err) reject(err); else resolve(this); }); });
const dbGet = (sql, params = []) => new Promise((resolve, reject) => { db.get(sql, params, (err, row) => { if (err) reject(err); else resolve(row); }); });
const dbAll = (sql, params = []) => new Promise((resolve, reject) => { db.all(sql, params, (err, rows) => { if (err) reject(err); else resolve(rows); }); });

const initializeDatabase = async () => {
    await dbRun(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, shop_id INTEGER, role TEXT NOT NULL, FOREIGN KEY (shop_id) REFERENCES shops(id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS shops (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, supplier_user_id INTEGER REFERENCES users(id), UNIQUE(name, supplier_user_id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS categories (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, supplier_user_id INTEGER REFERENCES users(id), UNIQUE(name, supplier_user_id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS parts (id INTEGER PRIMARY KEY AUTOINCREMENT, part_number TEXT NOT NULL, part_name TEXT NOT NULL, category_id INTEGER, supplier_user_id INTEGER REFERENCES users(id), FOREIGN KEY (category_id) REFERENCES categories(id), UNIQUE(part_number, supplier_user_id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS inventories (id INTEGER PRIMARY KEY AUTOINCREMENT, part_id INTEGER NOT NULL, shop_id INTEGER NOT NULL, quantity INTEGER NOT NULL, min_reorder_level INTEGER NOT NULL, location_info TEXT, FOREIGN KEY (part_id) REFERENCES parts(id), FOREIGN KEY (shop_id) REFERENCES shops(id), UNIQUE(part_id, shop_id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS employees (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, shop_id INTEGER NOT NULL, is_active INTEGER DEFAULT 1, FOREIGN KEY (shop_id) REFERENCES shops(id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS usage_history (id INTEGER PRIMARY KEY AUTOINCREMENT, part_id INTEGER NOT NULL, shop_id INTEGER NOT NULL, employee_id INTEGER NOT NULL, usage_time TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', FOREIGN KEY (part_id) REFERENCES parts(id), FOREIGN KEY (shop_id) REFERENCES shops(id), FOREIGN KEY (employee_id) REFERENCES employees(id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS cancellation_history (id INTEGER PRIMARY KEY AUTOINCREMENT, usage_history_id INTEGER NOT NULL, cancelled_by_user_id INTEGER NOT NULL, cancelled_at TEXT NOT NULL, reason TEXT, FOREIGN KEY (usage_history_id) REFERENCES usage_history(id), FOREIGN KEY (cancelled_by_user_id) REFERENCES users(id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS stocktake_history (id INTEGER PRIMARY KEY AUTOINCREMENT, part_id INTEGER NOT NULL, shop_id INTEGER NOT NULL, user_id INTEGER NOT NULL, stocktake_time TEXT NOT NULL, quantity_before INTEGER NOT NULL, quantity_after INTEGER NOT NULL, notes TEXT, FOREIGN KEY (part_id) REFERENCES parts(id), FOREIGN KEY (shop_id) REFERENCES shops(id), FOREIGN KEY (user_id) REFERENCES users(id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS replenishment_history (id INTEGER PRIMARY KEY AUTOINCREMENT, part_id INTEGER NOT NULL, shop_id INTEGER NOT NULL, user_id INTEGER NOT NULL, replenished_at TEXT NOT NULL, quantity_added INTEGER NOT NULL, FOREIGN KEY (part_id) REFERENCES parts(id), FOREIGN KEY (shop_id) REFERENCES shops(id), FOREIGN KEY (user_id) REFERENCES users(id))`);

    const adminCount = await dbGet("SELECT COUNT(*) AS count FROM users WHERE username = 'admin'");
    if (adminCount.count === 0) {
        console.log("Seeding initial admin user...");
        const hash = await bcrypt.hash('password', saltRounds);
        await dbRun("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", ['admin', hash, 'admin']);
        
        console.log("Seeding initial global data...");
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

        for (const shop of shops) { await dbRun("INSERT INTO shops (name, supplier_user_id) VALUES (?, NULL)", [shop]); }
        for (const category of categories) { await dbRun("INSERT INTO categories (name, supplier_user_id) VALUES (?, NULL)", [category]); }
        for (const part of parts) { await dbRun("INSERT INTO parts (part_number, part_name, category_id, supplier_user_id) VALUES (?, ?, ?, NULL)", [part.pn, part.name, part.cat]); }

        await dbRun("INSERT INTO inventories (part_id, shop_id, quantity, min_reorder_level, location_info) VALUES (?, ?, ?, ?, ?)", [1, 1, 20, 5, "棚A-1"]);
        await dbRun("INSERT INTO inventories (part_id, shop_id, quantity, min_reorder_level, location_info) VALUES (?, ?, ?, ?, ?)", [3, 1, 15, 5, "棚A-2"]);
        await dbRun("INSERT INTO inventories (part_id, shop_id, quantity, min_reorder_level, location_info) VALUES (?, ?, ?, ?, ?)", [7, 1, 5, 2, "棚B-2"]);
        await dbRun("INSERT INTO inventories (part_id, shop_id, quantity, min_reorder_level, location_info) VALUES (?, ?, ?, ?, ?)", [8, 1, 8, 3, "棚C-1"]);
        await dbRun("INSERT INTO inventories (part_id, shop_id, quantity, min_reorder_level, location_info) VALUES (?, ?, ?, ?, ?)", [2, 2, 25, 5, "ラック1"]);
        await dbRun("INSERT INTO inventories (part_id, shop_id, quantity, min_reorder_level, location_info) VALUES (?, ?, ?, ?, ?)", [4, 2, 18, 5, "ラック1"]);
        
        console.log("Initial data seeded.");
    }
};

// --- Auth APIs ---
app.post('/api/login', async (req, res) => { const { username, password } = req.body; if (!username || !password) { return res.status(400).json({ error: 'Username and password are required' }); } try { const user = await dbGet("SELECT * FROM users WHERE username = ?", [username]); if (!user) { return res.status(401).json({ error: 'Invalid credentials' }); } const match = await bcrypt.compare(password, user.password_hash); if (match) { req.session.user = { id: user.id, username: user.username, role: user.role, shop_id: user.shop_id }; res.json({ message: 'Login successful', user: req.session.user }); } else { res.status(401).json({ error: 'Invalid credentials' }); } } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); } });
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
        console.error(err);
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
        console.error(err);
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
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// --- Middleware ---
function isAuthenticated(req, res, next) { if (req.session.user) { next(); } else { res.status(401).json({ error: 'Unauthorized' }); } }
function isAdmin(req, res, next) { if (req.session.user && req.session.user.role === 'admin') { next(); } else { res.status(403).json({ error: 'Forbidden: Admin access required' }); } }
function isShopUser(req, res, next) { if (req.session.user && req.session.user.role === 'shop_user' && req.session.user.shop_id) { next(); } else { res.status(403).json({ error: 'Forbidden: Shop user access required' }); } }
function isAdminOrSupplier(req, res, next) { if (req.session.user && (req.session.user.role === 'admin' || req.session.user.role === 'supplier')) { next(); } else { res.status(403).json({ error: 'Forbidden: Admin or Supplier access required' }); } }

// --- General User APIs ---
app.get('/api/shops', isAuthenticated, async (req, res) => { try { if (req.session.user.role === 'admin' || req.session.user.role === 'supplier') { const rows = await dbAll("SELECT id, name FROM shops ORDER BY name"); res.json(rows); } else if (req.session.user.role === 'shop_user' && req.session.user.shop_id) { const row = await dbGet("SELECT id, name FROM shops WHERE id = ?", [req.session.user.shop_id]); res.json(row ? [row] : []); } else { res.status(403).json({ error: 'Forbidden: Invalid role or shop_id' }); } } catch (err) { console.error(err); res.status(500).json({ error: err.message }); } });
app.get('/api/shops/:shopId/inventory', isAuthenticated, async (req, res) => { 
    const { shopId } = req.params;
    if (req.session.user.role === 'shop_user' && parseInt(shopId) !== req.session.user.shop_id) {
        return res.status(403).json({ error: "Forbidden: You can only view your own shop's inventory" });
    }

    const supplierId = req.session.user.role === 'supplier' ? req.session.user.id : null;

    let sql = `
        SELECT 
            p.id, p.part_number, p.part_name, 
            c.id as category_id, c.name as category_name, 
            i.quantity, i.min_reorder_level, i.location_info 
        FROM inventories i
        JOIN parts p ON i.part_id = p.id
        LEFT JOIN categories c ON p.category_id = c.id 
        WHERE i.shop_id = ?`;
    
    const params = [shopId];

    if (supplierId) {
        sql += ` AND p.supplier_user_id = ?`;
        params.push(supplierId);
    }

    sql += ` ORDER BY c.name, p.part_name;`;

    try {
        const rows = await dbAll(sql, params);
        res.json(rows);
    } catch (err) {
        console.error(err);
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
        console.error(err);
 res.status(500).json({ error: "トランザクションエラー: " + err.message });
 }
});
app.get('/api/usage-history', isAuthenticated, isShopUser, async (req, res) => {
    const shop_id = req.session.user.shop_id;
    let { month, startDate, endDate } = req.query;

    let sql = `SELECT h.id, p.part_number, p.part_name, h.usage_time, e.name as employee_name, h.status FROM usage_history h JOIN parts p ON h.part_id = p.id JOIN employees e ON h.employee_id = e.id`;
    const whereClauses = ["h.shop_id = ?"];
    const params = [shop_id];

    if (month) {
        whereClauses.push("STRFTIME('%Y-%m', h.usage_time) = ?");
        params.push(month);
    } else if (startDate && endDate) {
        whereClauses.push("h.usage_time BETWEEN ? AND ?");
        params.push(startDate, endDate + ' 23:59:59');
    } else {
        // Default to current month if no range is provided
        const now = new Date();
        month = `${now.getFullYear()}-${(now.getMonth() + 1).toString().padStart(2, '0')}`;
        whereClauses.push("STRFTIME('%Y-%m', h.usage_time) = ?");
        params.push(month);
    }

    sql += ` WHERE ${whereClauses.join(' AND ')} ORDER BY h.usage_time DESC`;

    try {
        const rows = await dbAll(sql, params);
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/usage-history/csv', isAuthenticated, isShopUser, async (req, res) => {
    const shop_id = req.session.user.shop_id;
    let { month, startDate, endDate } = req.query;

    let sql = `SELECT h.id, p.part_number, p.part_name, h.usage_time, e.name as employee_name, h.status, ch.reason as cancellation_reason 
             FROM usage_history h 
             JOIN parts p ON h.part_id = p.id 
             JOIN employees e ON h.employee_id = e.id
             LEFT JOIN cancellation_history ch ON h.id = ch.usage_history_id`;
    const whereClauses = ["h.shop_id = ?"];
    const params = [shop_id];

    if (month) {
        whereClauses.push("STRFTIME('%Y-%m', h.usage_time) = ?");
        params.push(month);
    } else if (startDate && endDate) {
        whereClauses.push("h.usage_time BETWEEN ? AND ?");
        params.push(startDate, endDate + ' 23:59:59');
    }

    sql += ` WHERE ${whereClauses.join(' AND ')} ORDER BY h.usage_time DESC`;

    try {
        const rows = await dbAll(sql, params);
        if (!rows || rows.length === 0) {
            return res.status(404).send('No usage history to export for the selected criteria.');
        }

        const header = 'ID,品番,部品名,使用日時,従業員名,状態,取消理由\n';
        const csvRows = rows.map(row => {
            const status = row.status === 'cancelled' ? '取消済' : '使用中';
            const values = [ row.id, row.part_number, row.part_name, row.usage_time, row.employee_name, status, row.cancellation_reason || '' ];
            const escapedValues = values.map(v => {
                const stringValue = String(v || '');
                // Escape double quotes by doubling them
                const escaped = stringValue.replace(/"/g, '""');
                return `"${escaped}"`;
            });
            return escapedValues.join(',');
        });

        const csv = header + csvRows.join('\n');
        res.header('Content-Type', 'text/csv; charset=utf-8');
        res.send('\uFEFF' + csv); // Add BOM for Excel
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// --- Admin APIs ---
app.get('/api/admin/shops', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    try {
        let sql = "SELECT id, name FROM shops";
        const params = [];
        if (req.session.user.role === 'supplier') {
            sql += " WHERE supplier_user_id = ? OR supplier_user_id IS NULL";
            params.push(req.session.user.id);
        }
        sql += " ORDER BY id";
        const rows = await dbAll(sql, params);
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/shops', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { name } = req.body;
    if (!name) {
        return res.status(400).json({ error: 'Shop name is required' });
    }
    const supplier_user_id = req.session.user.role === 'supplier' ? req.session.user.id : null;
    try {
        const result = await dbRun("INSERT INTO shops (name, supplier_user_id) VALUES (?, ?)", [name, supplier_user_id]);
        res.json({ id: result.lastID, name, supplier_user_id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/admin/shops/:id', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { id } = req.params;
    const { name } = req.body;
    if (!name) {
        return res.status(400).json({ error: 'Shop name is required' });
    }
    
    let sql = "UPDATE shops SET name = ? WHERE id = ?";
    const params = [name, id];

    if (req.session.user.role === 'supplier') {
        sql += " AND supplier_user_id = ?";
        params.push(req.session.user.id);
    }

    try {
        const result = await dbRun(sql, params);
        if (result.changes === 0) {
            return res.status(404).json({ error: 'Shop not found or you do not have permission to edit it.' });
        }
        res.json({ message: 'Shop updated successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/shops/:id', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { id } = req.params;
    try {
        const userCount = await dbGet("SELECT COUNT(*) AS count FROM users WHERE shop_id = ?", [id]);
        if (userCount.count > 0) {
            return res.status(400).json({ error: 'Cannot delete shop: Users are still assigned to it.' });
        }
        const invCount = await dbGet("SELECT COUNT(*) AS count FROM inventories WHERE shop_id = ?", [id]);
        if (invCount.count > 0) {
            return res.status(400).json({ error: 'Cannot delete shop: Inventory is still assigned to it.' });
        }

        let sql = "DELETE FROM shops WHERE id = ?";
        const params = [id];
        if (req.session.user.role === 'supplier') {
            sql += " AND supplier_user_id = ?";
            params.push(req.session.user.id);
        }

        const result = await dbRun(sql, params);
        if (result.changes === 0) {
            return res.status(404).json({ error: 'Shop not found or you do not have permission to delete it.' });
        }
        res.json({ message: 'Shop deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/categories', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    try {
        let sql = "SELECT id, name FROM categories";
        const params = [];
        if (req.session.user.role === 'supplier') {
            sql += " WHERE supplier_user_id = ? OR supplier_user_id IS NULL";
            params.push(req.session.user.id);
        }
        sql += " ORDER BY id";
        const rows = await dbAll(sql, params);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/categories', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { name } = req.body;
    if (!name) {
        return res.status(400).json({ error: 'Category name is required' });
    }
    const supplier_user_id = req.session.user.role === 'supplier' ? req.session.user.id : null;
    try {
        const result = await dbRun("INSERT INTO categories (name, supplier_user_id) VALUES (?, ?)", [name, supplier_user_id]);
        res.json({ id: result.lastID, name, supplier_user_id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/admin/categories/:id', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { id } = req.params;
    const { name } = req.body;
    if (!name) {
        return res.status(400).json({ error: 'Category name is required' });
    }
    
    let sql = "UPDATE categories SET name = ? WHERE id = ?";
    const params = [name, id];
    if (req.session.user.role === 'supplier') {
        sql += " AND supplier_user_id = ?";
        params.push(req.session.user.id);
    }

    try {
        const result = await dbRun(sql, params);
        if (result.changes === 0) {
            return res.status(404).json({ error: 'Category not found or you do not have permission to edit it.' });
        }
        res.json({ message: 'Category updated successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/categories/:id', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { id } = req.params;
    try {
        const partCount = await dbGet("SELECT COUNT(*) AS count FROM parts WHERE category_id = ?", [id]);
        if (partCount.count > 0) {
            return res.status(400).json({ error: 'Cannot delete category: Parts are still assigned to it.' });
        }

        let sql = "DELETE FROM categories WHERE id = ?";
        const params = [id];
        if (req.session.user.role === 'supplier') {
            sql += " AND supplier_user_id = ?";
            params.push(req.session.user.id);
        }

        const result = await dbRun(sql, params);
        if (result.changes === 0) {
            return res.status(404).json({ error: 'Category not found or you do not have permission to delete it.' });
        }
        res.json({ message: 'Category deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/parts', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    let sql = `SELECT p.id, p.part_number, p.part_name, p.category_id, c.name as category_name FROM parts p LEFT JOIN categories c ON p.category_id = c.id`;
    const params = [];
    if (req.session.user.role === 'supplier') {
        sql += " WHERE p.supplier_user_id = ? OR p.supplier_user_id IS NULL";
        params.push(req.session.user.id);
    }
    sql += " ORDER BY p.id";
    try {
        const rows = await dbAll(sql, params);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/parts/uncategorized', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    try {
        const supplierId = req.session.user.role === 'supplier' ? req.session.user.id : null;
        
        let uncategorizedCategory;
        if (supplierId) {
            uncategorizedCategory = await dbGet("SELECT id FROM categories WHERE name = ? AND (supplier_user_id = ? OR supplier_user_id IS NULL)", ['未分類', supplierId]);
        } else {
            uncategorizedCategory = await dbGet("SELECT id FROM categories WHERE name = ? AND supplier_user_id IS NULL", ['未分類']);
        }
        const uncategorizedId = uncategorizedCategory ? uncategorizedCategory.id : -1;

        let sql = `SELECT id, part_number, part_name FROM parts WHERE category_id IS NULL OR category_id = ?`;
        const params = [uncategorizedId];

        if (supplierId) {
            sql += " AND (supplier_user_id = ? OR supplier_user_id IS NULL)";
            params.push(supplierId);
        }
        sql += " ORDER BY id";

        const rows = await dbAll(sql, params);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.post('/api/admin/parts', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { part_number, part_name, category_id } = req.body;
    if (!part_number || !part_name) {
        return res.status(400).json({ error: 'Part number and name are required' });
    }
    const supplier_user_id = req.session.user.role === 'supplier' ? req.session.user.id : null;
    try {
        const result = await dbRun("INSERT INTO parts (part_number, part_name, category_id, supplier_user_id) VALUES (?, ?, ?, ?)", [part_number, part_name, category_id, supplier_user_id]);
        res.json({ id: result.lastID, part_number, part_name, category_id, supplier_user_id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.put('/api/admin/parts/:id', isAuthenticated, isAdminOrSupplier, async (req, res) => { 
    const { id } = req.params;
    const { part_number, part_name, category_id } = req.body;
    if (!part_number || !part_name) {
        return res.status(400).json({ error: 'Part number and name are required' });
    }
    
    let sql = "UPDATE parts SET part_number = ?, part_name = ?, category_id = ? WHERE id = ?";
    const params = [part_number, part_name, category_id, id];

    if (req.session.user.role === 'supplier') {
        sql += " AND supplier_user_id = ?";
        params.push(req.session.user.id);
    }

    try {
        const result = await dbRun(sql, params);
        if (result.changes === 0) {
            return res.status(404).json({ error: 'Part not found or you do not have permission to edit it.' });
        }
        res.json({ message: 'Part updated successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/admin/parts/:id/category', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { id } = req.params;
    const { categoryId } = req.body;
    
    let sql = "UPDATE parts SET category_id = ? WHERE id = ?";
    const params = [categoryId, id];

    if (req.session.user.role === 'supplier') {
        sql += " AND supplier_user_id = ?";
        params.push(req.session.user.id);
    }

    try {
        const result = await dbRun(sql, params);
        if (result.changes === 0) {
            return res.status(404).json({ error: 'Part not found or you do not have permission to edit it.' });
        }
        res.json({ message: 'Category updated successfully.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.delete('/api/admin/parts/:id', isAuthenticated, isAdminOrSupplier, async (req, res) => { 
    const { id } = req.params;
    try {
        const invCount = await dbGet("SELECT COUNT(*) AS count FROM inventories WHERE part_id = ?", [id]);
        if (invCount.count > 0) {
            return res.status(400).json({ error: 'Cannot delete part: It still exists in some inventories.' });
        }

        let sql = "DELETE FROM parts WHERE id = ?";
        const params = [id];
        if (req.session.user.role === 'supplier') {
            sql += " AND supplier_user_id = ?";
            params.push(req.session.user.id);
        }

        const result = await dbRun(sql, params);
        if (result.changes === 0) {
            return res.status(404).json({ error: 'Part not found or you do not have permission to delete it.' });
        }
        res.json({ message: 'Part deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/parts', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { partIds } = req.body;
    if (!partIds || !Array.isArray(partIds) || partIds.length === 0) {
        return res.status(400).json({ error: 'partIds array is required.' });
    }

    const placeholders = partIds.map(() => '?').join(',');

    try {
        const invCountSql = `SELECT COUNT(*) AS count FROM inventories WHERE part_id IN (${placeholders})`;
        const invCount = await dbGet(invCountSql, partIds);
        if (invCount.count > 0) {
            return res.status(400).json({ error: '削除できません: 選択された部品のいくつかが、いずれかの工場の在庫として登録されています。' });
        }

        let deleteSql = `DELETE FROM parts WHERE id IN (${placeholders})`;
        const deleteParams = [...partIds];
        if (req.session.user.role === 'supplier') {
            deleteSql += " AND supplier_user_id = ?";
            deleteParams.push(req.session.user.id);
        }

        const result = await dbRun(deleteSql, deleteParams);

        if (result.changes === 0) {
            return res.status(404).json({ error: '削除対象の部品が見つからないか、権限がありません。' });
        }
        res.json({ message: `${result.changes}件の部品を削除しました。` });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/parts/csv', isAuthenticated, isAdminOrSupplier, async (req, res) => { const sql = `SELECT p.id, p.part_number, p.part_name, c.name as category_name FROM parts p LEFT JOIN categories c ON p.category_id = c.id ORDER BY p.id`; try { const rows = await dbAll(sql); if (!rows || rows.length === 0) { return res.status(404).send('No parts to export.'); } const header = 'ID,Part Number,Part Name,Category Name\n'; const csvRows = rows.map(row => `"${row.id}","${row.part_number}","${row.part_name}","${row.category_name || ''}"`);  const csvString = header + csvRows.join('\n');
        const bom = '\uFEFF';
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="parts-master.csv"');
        res.status(200).send(Buffer.from(bom + csvString, 'utf8')); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/parts/csv', isAuthenticated, isAdminOrSupplier, upload.single('csvFile'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'CSVファイルがアップロードされていません。' });
    }

    const supplierId = req.session.user.role === 'supplier' ? req.session.user.id : null;
    const csvData = req.file.buffer.toString('utf-8');
    const rows = csvData.split('\n').map(row => row.trim()).filter(row => row);
    if (rows.length < 2) {
        return res.status(400).json({ error: 'CSVにヘッダー行とデータ行が含まれていません。' });
    }

    const header = rows.shift().toLowerCase().split(',').map(h => h.trim().replace(/^"|"$/g, ''));
    const partNumberAliases = ['part_number', 'part-number', 'part number', '部品品番', '品番'];
    const partNameAliases = ['part_name', 'part-name', 'part name', '部品品名', '品名'];
    const categoryNameAliases = ['category_name', 'category', 'カテゴリー名', 'カテゴリー'];

    let partNumberIndex = -1, partNameIndex = -1, categoryNameIndex = -1;
    header.forEach((h, i) => {
        if (partNumberAliases.includes(h)) partNumberIndex = i;
        if (partNameAliases.includes(h)) partNameIndex = i;
        if (categoryNameAliases.includes(h)) categoryNameIndex = i;
    });

    if (partNumberIndex === -1 || partNameIndex === -1) {
        return res.status(400).json({ error: `部品品番と部品品名の列が必須です。` });
    }

    try {
        await dbRun("BEGIN TRANSACTION;");

        let uncategorizedId;
        const uncategorized = await dbGet("SELECT id FROM categories WHERE name = ? AND (supplier_user_id = ? OR supplier_user_id IS NULL)", ['未分類', supplierId]);
        if (uncategorized) {
            uncategorizedId = uncategorized.id;
        } else {
            const result = await dbRun("INSERT INTO categories (name, supplier_user_id) VALUES (?, ?)", ['未分類', supplierId]);
            uncategorizedId = result.lastID;
        }

        let successCount = 0, errorCount = 0;
        const errors = [];

        for (const [index, row] of rows.entries()) {
            const fields = row.split(',').map(field => field.trim().replace(/^"|"$/g, ''));
            const part_number = fields[partNumberIndex];
            if (!part_number) {
                errors.push(`行 ${index + 2}: 部品品番が空です。`);
                errorCount++;
                continue;
            }

            const part_name = fields[partNameIndex] || part_number;
            const category_name = (categoryNameIndex !== -1) ? fields[categoryNameIndex] : null;
            let categoryId = uncategorizedId;

            if (category_name) {
                const category = await dbGet("SELECT id FROM categories WHERE name = ? AND (supplier_user_id = ? OR supplier_user_id IS NULL)", [category_name, supplierId]);
                if (category) {
                    categoryId = category.id;
                } else {
                    const result = await dbRun("INSERT INTO categories (name, supplier_user_id) VALUES (?, ?)", [category_name, supplierId]);
                    categoryId = result.lastID;
                }
            }

            const existingPart = await dbGet("SELECT id FROM parts WHERE part_number = ? AND (supplier_user_id = ? OR (? IS NULL AND supplier_user_id IS NULL))", [part_number, supplierId, supplierId]);
            if (existingPart) {
                await dbRun("UPDATE parts SET part_name = ?, category_id = ? WHERE id = ?", [part_name, categoryId, existingPart.id]);
            } else {
                await dbRun("INSERT INTO parts (part_number, part_name, category_id, supplier_user_id) VALUES (?, ?, ?, ?)", [part_number, part_name, categoryId, supplierId]);
            }
            successCount++;
        }

        if (errorCount > 0) {
            await dbRun("ROLLBACK;");
            return res.status(400).json({ error: "CSVインポートがエラーのため中断されました。", details: errors });
        }

        await dbRun("COMMIT;");
        res.json({ message: "CSVインポートが正常に完了しました。", summary: `成功件数: ${successCount}件。` });
    } catch (err) {
        await dbRun("ROLLBACK;");
        res.status(500).json({ error: '予期せぬサーバーエラーが発生しました。', details: err.message });
    }
});

app.get('/api/admin/users', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    try {
        let sql = "SELECT id, username, role, shop_id FROM users";
        const params = [];
        if (req.session.user.role === 'supplier') {
            // Suppliers can only see users of shops they manage
            sql += " WHERE shop_id IN (SELECT id FROM shops WHERE supplier_user_id = ?)";
            params.push(req.session.user.id);
        }
        sql += " ORDER BY id";
        const rows = await dbAll(sql, params);
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});
app.post('/api/admin/users', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { username, password, role, shop_id } = req.body;
    if (!username || !password || !role) {
        return res.status(400).json({ error: 'Username, password, and role are required' });
    }
    if (role === 'shop_user' && !shop_id) {
        return res.status(400).json({ error: 'Shop ID is required for shop users' });
    }

    try {
        if (req.session.user.role === 'supplier') {
            // Suppliers can only create shop_users for their own shops
            if (role !== 'shop_user') {
                return res.status(403).json({ error: 'Forbidden: Suppliers can only create shop_user accounts.' });
            }
            const shop = await dbGet("SELECT id FROM shops WHERE id = ? AND supplier_user_id = ?", [shop_id, req.session.user.id]);
            if (!shop) {
                return res.status(403).json({ error: 'Forbidden: You can only assign users to a shop you manage.' });
            }
        }

        const hash = await bcrypt.hash(password, saltRounds);
        const finalShopId = (role === 'admin' || role === 'supplier') ? null : shop_id;
        const result = await dbRun("INSERT INTO users (username, password_hash, role, shop_id) VALUES (?, ?, ?, ?)", [username, hash, role, finalShopId]);
        res.json({ id: result.lastID, username, role, shop_id: finalShopId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});
app.put('/api/admin/users/:id', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { id } = req.params;
    const { username, role, shop_id, password } = req.body;

    if (!username || !role) {
        return res.status(400).json({ error: 'Username and role are required' });
    }
    if (role === 'shop_user' && !shop_id) {
        return res.status(400).json({ error: 'Shop ID is required for shop users' });
    }

    try {
        if (req.session.user.role === 'supplier') {
            // First, verify the user being edited belongs to a shop managed by this supplier
            const userToEdit = await dbGet(`
                SELECT u.id FROM users u
                JOIN shops s ON u.shop_id = s.id
                WHERE u.id = ? AND s.supplier_user_id = ?`,
                [id, req.session.user.id]
            );
            if (!userToEdit) {
                return res.status(403).json({ error: 'Forbidden: You can only edit users in shops you manage.' });
            }

            // Suppliers can only manage shop_users
            if (role !== 'shop_user') {
                return res.status(403).json({ error: 'Forbidden: Suppliers can only manage shop_user accounts.' });
            }

            // Verify the new shop_id also belongs to the supplier
            const shop = await dbGet("SELECT id FROM shops WHERE id = ? AND supplier_user_id = ?", [shop_id, req.session.user.id]);
            if (!shop) {
                return res.status(403).json({ error: 'Forbidden: You can only assign users to a shop you manage.' });
            }
        }

        const finalShopId = (role === 'admin' || role === 'supplier') ? null : shop_id;
        if (password) {
            const hash = await bcrypt.hash(password, saltRounds);
            await dbRun("UPDATE users SET username = ?, password_hash = ?, role = ?, shop_id = ? WHERE id = ?", [username, hash, role, finalShopId, id]);
        } else {
            await dbRun("UPDATE users SET username = ?, role = ?, shop_id = ? WHERE id = ?", [username, role, finalShopId, id]);
        }
        res.json({ message: 'User updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});
app.delete('/api/admin/users/:id', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { id } = req.params;
    if (parseInt(id, 10) === req.session.user.id) {
        return res.status(400).json({ error: 'You cannot delete your own account.' });
    }

    try {
        if (req.session.user.role === 'supplier') {
            // Verify the user being deleted belongs to a shop managed by this supplier
            const userToDelete = await dbGet(`
                SELECT u.id FROM users u
                JOIN shops s ON u.shop_id = s.id
                WHERE u.id = ? AND s.supplier_user_id = ?`,
                [id, req.session.user.id]
            );
            if (!userToDelete) {
                return res.status(403).json({ error: 'Forbidden: You can only delete users in shops you manage.' });
            }
        }

        const result = await dbRun("DELETE FROM users WHERE id = ?", [id]);
        if (result.changes === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ message: 'User deleted successfully' });
    } catch (err) {
        console.error(err);
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


app.get('/api/admin/inventory/locations', isAuthenticated, isAdminOrSupplier, async (req, res) => { try { const rows = await dbAll("SELECT DISTINCT location_info FROM inventories WHERE location_info IS NOT NULL AND location_info != '' ORDER BY location_info"); res.json(rows.map(r => r.location_info)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/admin/all-inventory', isAuthenticated, isAdminOrSupplier, async (req, res) => { 
    let sql = `SELECT i.part_id, i.shop_id, s.name AS shop_name, p.part_number, p.part_name, i.quantity, i.min_reorder_level, i.location_info FROM inventories i JOIN shops s ON i.shop_id = s.id JOIN parts p ON i.part_id = p.id`;
    const params = [];
    if (req.session.user.role === 'supplier') {
        sql += " WHERE p.supplier_user_id = ? OR p.supplier_user_id IS NULL";
        params.push(req.session.user.id);
    }
    sql += " ORDER BY s.name, p.part_name";
    try { 
        const rows = await dbAll(sql, params); 
        res.json(rows); 
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    } 
});
app.post('/api/admin/inventory', isAuthenticated, isAdminOrSupplier, async (req, res) => { const { shop_id, part_id, quantity, min_reorder_level, location_info } = req.body;
 if (!shop_id || !part_id || quantity === undefined || min_reorder_level === undefined) {
 return res.status(400).json({ error: 'Shop, part, quantity, and min_reorder_level are required' });
 }

 if (req.session.user.role === 'supplier') {
    const part = await dbGet("SELECT id FROM parts WHERE id = ? AND (supplier_user_id = ? OR supplier_user_id IS NULL)", [part_id, req.session.user.id]);
    if (!part) {
        return res.status(403).json({ error: 'Forbidden: You can only manage inventory for your own parts.' });
    }
 }

 const sql = `INSERT INTO inventories (shop_id, part_id, quantity, min_reorder_level, location_info) VALUES (?, ?, ?, ?, ?) ON CONFLICT(part_id, shop_id) DO UPDATE SET quantity = excluded.quantity, min_reorder_level = excluded.min_reorder_level, location_info = excluded.location_info`;
 try {
 await dbRun(sql, [shop_id, part_id, quantity, min_reorder_level, location_info || '']);
 res.json({ message: 'Inventory updated successfully' });
 } catch (err) {
 res.status(500).json({ error: err.message });
 }
});

app.delete('/api/admin/inventory', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { shop_id, part_id } = req.body;
    if (!shop_id || !part_id) {
        return res.status(400).json({ error: 'shop_id and part_id are required' });
    }

    if (req.session.user.role === 'supplier') {
        const part = await dbGet("SELECT id FROM parts WHERE id = ? AND supplier_user_id = ?", [part_id, req.session.user.id]);
        if (!part) {
            return res.status(403).json({ error: 'Forbidden: You can only delete inventory for your own parts.' });
        }
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
app.post('/api/admin/inventory/csv', isAuthenticated, isAdminOrSupplier, async (req, res) => { const { csvData } = req.body;
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
 const supplierId = req.session.user.role === 'supplier' ? req.session.user.id : null;

 for (const [index, row] of rows.entries()) {
 const [part_number, shop_name, quantity, min_reorder_level, location_info] = row.split(',').map(field => field.trim().replace(/^"|"$/g, ''));
 if (!part_number || !shop_name || quantity === undefined || min_reorder_level === undefined) {
 errors.push(`Row ${index + 1}: Invalid data - ${row}`);
 errorCount++;
 continue;
 }
 
 let part;
 if(supplierId) {
    part = await dbGet("SELECT id FROM parts WHERE part_number = ? AND (supplier_user_id = ? OR supplier_user_id IS NULL)", [part_number, supplierId]);
 } else {
    part = await dbGet("SELECT id FROM parts WHERE part_number = ? AND supplier_user_id IS NULL", [part_number]);
 }

 const shop = await dbGet("SELECT id FROM shops WHERE name = ?", [shop_name]);
 if (!part) {
 errors.push(`Row ${index + 1}: Part number not found or not accessible - ${part_number}`);
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
app.post('/api/admin/inventory/stocktake', isAuthenticated, isAdminOrSupplier, async (req, res) => { const { shop_id, stocktakeData } = req.body;
 const user_id = req.session.user.id;
 if (!shop_id || !Array.isArray(stocktakeData)) {
 return res.status(400).json({ error: 'Shop ID and stocktake data are required.' });
 }
 try {
 await dbRun("BEGIN TRANSACTION;");
 let updatedCount = 0;
 for (const item of stocktakeData) {
 if (item.part_id == null || item.actual_quantity == null) continue;

 if (req.session.user.role === 'supplier') {
    const part = await dbGet("SELECT id FROM parts WHERE id = ? AND (supplier_user_id = ? OR supplier_user_id IS NULL)", [item.part_id, req.session.user.id]);
    if (!part) {
        // Maybe just skip this item instead of failing the whole transaction?
        // For now, let's skip.
        console.log(`Skipping stocktake for part ID ${item.part_id} as it is not accessible by supplier ${req.session.user.id}`);
        continue;
    }
 }

 const row = await dbGet("SELECT quantity FROM inventories WHERE part_id = ? AND shop_id = ?", [item.part_id, shop_id]);
 if (row && row.quantity !== item.actual_quantity) {
 await dbRun("UPDATE inventories SET quantity = ? WHERE part_id = ? AND shop_id = ?", [item.actual_quantity, item.part_id, shop_id]);
 const historySql = `INSERT INTO stocktake_history (part_id, shop_id, user_id, stocktake_time, quantity_before, quantity_after, notes) VALUES (?, ?, ?, datetime('now', 'localtime'), ?, ?, ?)`;
 await dbRun(historySql, [item.part_id, shop_id, user_id, row.quantity, item.actual_quantity, '棚卸しによる調整']);
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

app.post('/api/admin/inventory/replenish', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { shop_id, part_id, quantity_added } = req.body;
    const user_id = req.session.user.id;

    if (!shop_id || !part_id || !quantity_added) {
        return res.status(400).json({ error: '工場、部品、および補充数量は必須です。' });
    }

    if (req.session.user.role === 'supplier') {
        const part = await dbGet("SELECT id FROM parts WHERE id = ? AND (supplier_user_id = ? OR supplier_user_id IS NULL)", [part_id, req.session.user.id]);
        if (!part) {
            return res.status(403).json({ error: 'Forbidden: You can only replenish your own parts.' });
        }
    }

    const quantity = parseInt(quantity_added, 10);
    if (isNaN(quantity) || quantity <= 0) {
        return res.status(400).json({ error: '補充数量は正の整数である必要があります。' });
    }

    try {
        await dbRun("BEGIN TRANSACTION;");

        const inventory = await dbGet("SELECT id FROM inventories WHERE part_id = ? AND shop_id = ?", [part_id, shop_id]);
        
        if (inventory) {
            await dbRun("UPDATE inventories SET quantity = quantity + ? WHERE id = ?", [quantity, inventory.id]);
        } else {
            await dbRun("INSERT INTO inventories (part_id, shop_id, quantity, min_reorder_level, location_info) VALUES (?, ?, ?, 0, '')", [part_id, shop_id, quantity]);
        }

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


app.get('/api/admin/all-usage-history', isAuthenticated, isAdminOrSupplier, async (req, res) => { 
    const { startDate, endDate, shopId, partId } = req.query;
    let sql = `SELECT s.name AS shop_name, p.part_number, p.part_name, h.usage_time, e.name as employee_name, h.status, ch.reason as cancellation_reason
               FROM usage_history h
               LEFT JOIN shops s ON h.shop_id = s.id 
               LEFT JOIN parts p ON h.part_id = p.id 
               LEFT JOIN employees e ON h.employee_id = e.id
               LEFT JOIN cancellation_history ch ON h.id = ch.usage_history_id`;
    const whereClauses = [];
    const params = [];

    if (req.session.user.role === 'supplier') {
        whereClauses.push("(p.supplier_user_id = ? OR p.supplier_user_id IS NULL)");
        params.push(req.session.user.id);
    }
    if (startDate) { whereClauses.push("h.usage_time >= ?"); params.push(startDate); }
    if (endDate) { whereClauses.push("h.usage_time <= ?"); params.push(endDate + ' 23:59:59'); }
    if (shopId) { whereClauses.push("h.shop_id = ?"); params.push(shopId); }
    if (partId) { whereClauses.push("h.part_id = ?"); params.push(partId); }
    
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

app.get('/api/admin/all-usage-history/csv', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { startDate, endDate, shopId, partId } = req.query;
    let sql = `SELECT s.name AS shop_name, p.part_number, p.part_name, h.usage_time, e.name as employee_name, h.status, ch.reason as cancellation_reason
               FROM usage_history h
               LEFT JOIN shops s ON h.shop_id = s.id 
               LEFT JOIN parts p ON h.part_id = p.id 
               LEFT JOIN employees e ON h.employee_id = e.id
               LEFT JOIN cancellation_history ch ON h.id = ch.usage_history_id`;
    
    const whereClauses = [];
    const params = [];

    if (req.session.user.role === 'supplier') {
        whereClauses.push("(p.supplier_user_id = ? OR p.supplier_user_id IS NULL)");
        params.push(req.session.user.id);
    }
    if (startDate) { whereClauses.push("h.usage_time >= ?"); params.push(startDate); }
    if (endDate) { whereClauses.push("h.usage_time <= ?"); params.push(endDate + ' 23:59:59'); }
    if (shopId) { whereClauses.push("h.shop_id = ?"); params.push(shopId); }
    if (partId) { whereClauses.push("h.part_id = ?"); params.push(partId); }
    
    if (whereClauses.length > 0) { sql += " WHERE " + whereClauses.join(" AND "); }
    sql += " ORDER BY h.usage_time DESC";

    try {
        const rows = await dbAll(sql, params);
        if (!rows || rows.length === 0) {
            return res.status(404).send('No usage history to export for the selected criteria.');
        }

        const header = '工場名,品番,部品品名,使用日時,従業員名,状態,取消理由\n';
        const csvRows = rows.map(row => {
            const status = row.status === 'cancelled' ? '取消済' : '使用中';
            const values = [ row.shop_name, row.part_number, row.part_name, row.usage_time, row.employee_name, status, row.cancellation_reason || '' ];
            return values.map(v => `"${String(v || '').replace(/"/g, '""')}"`).join(',');
        });

        const csvString = header + csvRows.join('\n');
        const bom = '\uFEFF';
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="usage-history.csv"');
        res.status(200).send(Buffer.from(bom + csvString, 'utf8'));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.get('/api/admin/reorder-list', isAuthenticated, isAdminOrSupplier, async (req, res) => { 
    let sql = `SELECT s.name AS shop_name, p.part_number, p.part_name, i.quantity, i.min_reorder_level, (i.min_reorder_level - i.quantity) AS shortage 
               FROM inventories i 
               JOIN shops s ON i.shop_id = s.id 
               JOIN parts p ON i.part_id = p.id 
               WHERE i.quantity < i.min_reorder_level`;
    const params = [];
    if (req.session.user.role === 'supplier') {
        sql += " AND (p.supplier_user_id = ? OR p.supplier_user_id IS NULL)";
        params.push(req.session.user.id);
    }
    sql += " ORDER BY s.name, shortage DESC, p.part_name";
    try { 
        const rows = await dbAll(sql, params); 
        res.json(rows); 
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    } 
});
app.get('/api/admin/reorder-list/csv', isAuthenticated, isAdminOrSupplier, async (req, res) => { 
    let sql = `SELECT s.name AS shop_name, p.part_number, p.part_name, i.quantity, i.min_reorder_level, (i.min_reorder_level - i.quantity) AS shortage 
               FROM inventories i 
               JOIN shops s ON i.shop_id = s.id 
               JOIN parts p ON i.part_id = p.id 
               WHERE i.quantity < i.min_reorder_level`;
    const params = [];
    if (req.session.user.role === 'supplier') {
        sql += " AND (p.supplier_user_id = ? OR p.supplier_user_id IS NULL)";
        params.push(req.session.user.id);
    }
    sql += " ORDER BY s.name, shortage DESC, p.part_name";
    try { 
        const rows = await dbAll(sql, params); 
        if (!rows || rows.length === 0) { 
            return res.status(404).send('No items to export.'); 
        } 
        const header = '工場名,品番,部品品名,現在庫数,最少再発注レベル,不足数\n'; 
        const csvRows = rows.map(row => `"${row.shop_name}","${row.part_number}","${row.part_name}",${row.quantity},${row.min_reorder_level},${row.shortage}`); 
        const csvString = header + csvRows.join('\n');
        const bom = '\uFEFF';
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="reorder-list.csv"');
        res.status(200).send(Buffer.from(bom + csvString, 'utf8')); 
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    } 
});

// --- Replenishment History ---
const getReplenishmentHistoryQuery = (queryParams, user) => {
    const { startDate, endDate, shopId, partId } = queryParams;
    let sql = `SELECT rh.id, s.name AS shop_name, p.part_number, p.part_name, u.username AS user_name, rh.replenished_at, rh.quantity_added
               FROM replenishment_history rh
               LEFT JOIN shops s ON rh.shop_id = s.id 
               LEFT JOIN parts p ON rh.part_id = p.id 
               LEFT JOIN users u ON rh.user_id = u.id`;
    const whereClauses = [];
    const params = [];
    if (user.role === 'supplier') {
        whereClauses.push("(p.supplier_user_id = ? OR p.supplier_user_id IS NULL)");
        params.push(user.id);
    }
    if (startDate) { whereClauses.push("rh.replenished_at >= ?"); params.push(startDate); }
    if (endDate) { whereClauses.push("rh.replenished_at <= ?"); params.push(endDate + ' 23:59:59'); }
    if (shopId) { whereClauses.push("rh.shop_id = ?"); params.push(shopId); }
    if (partId) { whereClauses.push("rh.part_id = ?"); params.push(partId); }
    if (whereClauses.length > 0) { sql += " WHERE " + whereClauses.join(" AND "); }
    sql += " ORDER BY rh.replenished_at DESC";
    return { sql, params };
};

app.get('/api/admin/replenishment-history', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    try {
        const { sql, params } = getReplenishmentHistoryQuery(req.query, req.session.user);
        const rows = await dbAll(sql, params);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/replenishment-history/csv', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    try {
        const { sql, params } = getReplenishmentHistoryQuery(req.query, req.session.user);
        const rows = await dbAll(sql, params);
        if (!rows || rows.length === 0) {
            return res.status(404).send('No replenishment history to export for the selected criteria.');
        }

        const header = '補充日時,工場名,品番,部品品名,補充数,担当者\n';
        const csvRows = rows.map(row => {
            const values = [ row.replenished_at, row.shop_name, row.part_number, row.part_name, row.quantity_added, row.user_name ];
            return values.map(v => `"${String(v || '').replace(/"/g, '""')}"`).join(',');
        });

        const csvString = header + csvRows.join('\n');
        const bom = '\uFEFF';
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="replenishment-history.csv"');
        res.status(200).send(Buffer.from(bom + csvString, 'utf8'));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/stocktake-analysis', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { part_id, shop_id } = req.body;
    if (!part_id || !shop_id) {
        return res.status(400).json({ error: 'Part ID and Shop ID are required' });
    }

    if (req.session.user.role === 'supplier') {
        const part = await dbGet("SELECT id FROM parts WHERE id = ? AND (supplier_user_id = ? OR supplier_user_id IS NULL)", [part_id, req.session.user.id]);
        if (!part) {
            return res.status(403).json({ error: 'Forbidden: You can only analyze stock for your own parts.' });
        }
    }

    try {
        // 1. Find the last stocktake as the base point
        let base_time = '1970-01-01 00:00:00';
        let base_quantity = 0;

        const lastStocktake = await dbGet(`
            SELECT stocktake_time, quantity_after 
            FROM stocktake_history
            WHERE part_id = ? AND shop_id = ?
            ORDER BY stocktake_time DESC
            LIMIT 1
        `, [part_id, shop_id]);

        if (lastStocktake) {
            base_time = lastStocktake.stocktake_time;
            base_quantity = lastStocktake.quantity_after;
        } else {
            // If no stocktake, find the first replenishment as a fallback base
            const firstReplenishment = await dbGet(`
                SELECT replenished_at, quantity_added
                FROM replenishment_history
                WHERE part_id = ? AND shop_id = ?
                ORDER BY replenished_at ASC
                LIMIT 1
            `, [part_id, shop_id]);
            if(firstReplenishment) {
                 base_time = firstReplenishment.replenished_at;
                 base_quantity = firstReplenishment.quantity_added;
            }
        }

        // 2. Get all detailed records since the base time
        const replenishments = await dbAll(
            `SELECT rh.replenished_at, rh.quantity_added, u.username 
             FROM replenishment_history rh JOIN users u ON rh.user_id = u.id 
             WHERE rh.part_id = ? AND rh.shop_id = ? AND rh.replenished_at > ? ORDER BY rh.replenished_at DESC`,
            [part_id, shop_id, base_time]
        );

        const usages = await dbAll(
            `SELECT h.usage_time, h.status, e.name as employee_name 
             FROM usage_history h JOIN employees e ON h.employee_id = e.id
             WHERE h.part_id = ? AND h.shop_id = ? AND h.usage_time > ? ORDER BY h.usage_time DESC`,
            [part_id, shop_id, base_time]
        );

        // 3. Calculate summary
        const total_replenished = replenishments.reduce((sum, r) => sum + r.quantity_added, 0);
        const total_used = usages.filter(u => u.status === 'active').length;
        const total_cancelled = usages.filter(u => u.status === 'cancelled').length;
        
        const calculated_stock = base_quantity + total_replenished - total_used + total_cancelled;

        res.json({
            summary: {
                base_time,
                base_quantity,
                total_replenished,
                total_used,
                total_cancelled,
                calculated_stock
            },
            details: {
                replenishments,
                usages
            }
        });

    } catch (err) {
        console.error("Stocktake analysis failed:", err);
        res.status(500).json({ error: '理論在庫データの分析中にエラーが発生しました。', details: err.message });
    }
});

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