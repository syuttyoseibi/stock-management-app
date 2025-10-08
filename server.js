
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');

const dbPath = process.env.NODE_ENV === 'test' ? ':memory:' : (process.env.DATABASE_PATH || './data/stock.db');

// Ensure the directory for the database exists before opening the database
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

const dbRun = (sql, params = []) => new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
        if (err) reject(err);
        else resolve(this);
    });
});

const dbGet = (sql, params = []) => new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
        if (err) reject(err);
        else resolve(row);
    });
});

const dbAll = (sql, params = []) => new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
    });
});

const initializeDatabase = async () => {
    await dbRun(`CREATE TABLE IF NOT EXISTS shops (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE)`);
    await dbRun(`CREATE TABLE IF NOT EXISTS categories (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE)`);
    await dbRun(`CREATE TABLE IF NOT EXISTS parts (id INTEGER PRIMARY KEY AUTOINCREMENT, part_number TEXT NOT NULL UNIQUE, part_name TEXT NOT NULL, category_id INTEGER, FOREIGN KEY (category_id) REFERENCES categories(id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS inventories (id INTEGER PRIMARY KEY AUTOINCREMENT, part_id INTEGER NOT NULL, shop_id INTEGER NOT NULL, quantity INTEGER NOT NULL, min_reorder_level INTEGER NOT NULL, location_info TEXT, FOREIGN KEY (part_id) REFERENCES parts(id), FOREIGN KEY (shop_id) REFERENCES shops(id), UNIQUE(part_id, shop_id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS usage_history (id INTEGER PRIMARY KEY AUTOINCREMENT, part_id INTEGER NOT NULL, shop_id INTEGER NOT NULL, usage_time TEXT NOT NULL, mechanic_name TEXT, status TEXT NOT NULL DEFAULT 'active', FOREIGN KEY (part_id) REFERENCES parts(id), FOREIGN KEY (shop_id) REFERENCES shops(id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, shop_id INTEGER, role TEXT NOT NULL, FOREIGN KEY (shop_id) REFERENCES shops(id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS cancellation_history (id INTEGER PRIMARY KEY AUTOINCREMENT, usage_history_id INTEGER NOT NULL, cancelled_by_user_id INTEGER NOT NULL, cancelled_at TEXT NOT NULL, reason TEXT, FOREIGN KEY (usage_history_id) REFERENCES usage_history(id), FOREIGN KEY (cancelled_by_user_id) REFERENCES users(id))`);
    await dbRun(`CREATE TABLE IF NOT EXISTS stocktake_history (id INTEGER PRIMARY KEY AUTOINCREMENT, part_id INTEGER NOT NULL, shop_id INTEGER NOT NULL, user_id INTEGER NOT NULL, stocktake_time TEXT NOT NULL, quantity_before INTEGER NOT NULL, quantity_after INTEGER NOT NULL, notes TEXT, FOREIGN KEY (part_id) REFERENCES parts(id), FOREIGN KEY (shop_id) REFERENCES shops(id), FOREIGN KEY (user_id) REFERENCES users(id))`);

    const users = await dbGet("SELECT COUNT(*) AS count FROM users");
    if (users.count === 0) {
        console.log("Seeding initial user data...");
        const hash = await bcrypt.hash('password', saltRounds);
        await dbRun("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", ['admin', hash, 'admin']);
    }
};

// --- Auth APIs ---
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    try {
        const user = await dbGet("SELECT * FROM users WHERE username = ?", [username]);
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const match = await bcrypt.compare(password, user.password_hash);
        if (match) {
            req.session.user = { id: user.id, username: user.username, role: user.role, shop_id: user.shop_id };
            res.json({ message: 'Login successful', user: req.session.user });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/logout', (req, res) => { req.session.destroy(err => { if (err) { return res.status(500).json({ error: 'Could not log out' }); } res.clearCookie('connect.sid'); res.json({ message: 'Logout successful' }); }); });
app.get('/api/auth/status', (req, res) => { if (req.session.user) { res.json({ loggedIn: true, user: req.session.user }); } else { res.json({ loggedIn: false }); } });

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
 const sql = `SELECT p.id, p.part_number, p.part_name, i.quantity, i.location_info FROM parts p JOIN inventories i ON p.id = i.part_id WHERE i.shop_id = ? ORDER BY p.part_name;`;
 try {
 const rows = await dbAll(sql, [shopId]);
 res.json(rows);
 } catch (err) {
 res.status(500).json({ error: err.message });
 }
});
app.post('/api/use-part', isAuthenticated, async (req, res) => { const { part_id, shop_id, mechanic_name } = req.body;
 if (!part_id || !shop_id || !mechanic_name) {
 return res.status(400).json({ error: "部品ID、工場ID、整備士名は必須です" });
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
 await dbRun("INSERT INTO usage_history (part_id, shop_id, usage_time, mechanic_name) VALUES (?, ?, datetime('now', 'localtime'), ?)", [part_id, shop_id, mechanic_name]);
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
 const sql = `SELECT h.id, p.part_number, p.part_name, h.usage_time, h.mechanic_name, h.status FROM usage_history h JOIN parts p ON h.part_id = p.id WHERE h.shop_id = ? AND STRFTIME('%Y-%m', h.usage_time) = ? ORDER BY h.usage_time DESC`;
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

app.get('/api/admin/parts/csv', isAuthenticated, isAdmin, async (req, res) => { const sql = `SELECT p.id, p.part_number, p.part_name, c.name as category_name FROM parts p LEFT JOIN categories c ON p.category_id = c.id ORDER BY p.id`; try { const rows = await dbAll(sql); if (!rows || rows.length === 0) { return res.status(404).send('No parts to export.'); } const header = 'ID,Part Number,Part Name,Category Name\n'; const csvRows = rows.map(row => `"${row.id}","${row.part_number}","${row.part_name}","${row.category_name || ''}"`); const csvString = header + csvRows.join('\n'); res.setHeader('Content-Type', 'text/csv; charset=utf-8'); res.setHeader('Content-Disposition', 'attachment; filename="parts-master.csv"'); res.status(200).send(Buffer.from(csvString, 'utf8')); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/admin/parts/csv', isAuthenticated, isAdmin, async (req, res) => { const { csvData } = req.body;
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
 const [part_number, part_name, category_name] = row.split(',').map(field => field.trim().replace(/^"|"$/g, ''));
 if (!part_number || !part_name) {
 errors.push(`Row ${index + 1}: Invalid data - ${row}`);
 errorCount++;
 continue;
 }
 const category = await dbGet("SELECT id FROM categories WHERE name = ?", [category_name]);
 let categoryId = category ? category.id : null;
 if (!category && category_name) {
 const result = await dbRun("INSERT INTO categories (name) VALUES (?)", [category_name]);
 categoryId = result.lastID;
 }
 const sql = `INSERT INTO parts (part_number, part_name, category_id) VALUES (?, ?, ?) ON CONFLICT(part_number) DO UPDATE SET part_name = excluded.part_name, category_id = excluded.category_id;`;
 await dbRun(sql, [part_number, part_name, categoryId]);
 successCount++;
 }
 if (errorCount > 0) {
 await dbRun("ROLLBACK;");
 return res.status(400).json({ error: "CSV import failed due to errors.", details: errors });
 }
 await dbRun("COMMIT;");
 res.json({ message: "CSV import successful.", summary: `Success: ${successCount}, Failed: ${errorCount}` });
 } catch (err) {
 await dbRun("ROLLBACK;");
 res.status(500).json({ error: 'An unexpected error occurred.', details: err.message });
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

app.get('/api/admin/all-usage-history', isAuthenticated, isAdmin, async (req, res) => { const { startDate, endDate, shopId, partId } = req.query;
 let sql = `SELECT s.name AS shop_name, p.part_number, p.part_name, h.usage_time, h.mechanic_name FROM usage_history h JOIN shops s ON h.shop_id = s.id JOIN parts p ON h.part_id = p.id`;
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
app.get('/api/admin/reorder-list/csv', isAuthenticated, isAdmin, async (req, res) => { const sql = `SELECT s.name AS shop_name, p.part_number, p.part_name, i.quantity, i.min_reorder_level, (i.min_reorder_level - i.quantity) AS shortage FROM inventories i JOIN shops s ON i.shop_id = s.id JOIN parts p ON i.part_id = p.id WHERE i.quantity < i.min_reorder_level ORDER BY s.name, shortage DESC, p.part_name`; try { const rows = await dbAll(sql); if (!rows || rows.length === 0) { return res.status(404).send('No items to export.'); } const header = '工場名,品番,部品名,現在庫数,最低発注レベル,不足数\n'; const csvRows = rows.map(row => `"${row.shop_name}","${row.part_number}","${row.part_name}",${row.quantity},${row.min_reorder_level},${row.shortage}`); const csvString = header + csvRows.join('\n'); res.setHeader('Content-Type', 'text/csv; charset=utf-8'); res.setHeader('Content-Disposition', 'attachment; filename="reorder-list.csv"'); res.status(200).send(Buffer.from(csvString, 'utf8')); } catch (err) { res.status(500).json({ error: err.message }); } });

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
