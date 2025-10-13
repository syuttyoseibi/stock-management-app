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