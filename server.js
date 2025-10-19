const express = require('express');
require('dotenv').config(); // Load environment variables from .env file
const { Pool } = require('pg');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const multer = require('multer');

// --- Multer Setup for CSV upload ---
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// --- PostgreSQL (Supabase) Connection ---
let pool;

// Do not initialize DB connection in test environment
if (process.env.NODE_ENV !== 'test') {
    // For debugging Render environment variables
    console.log('--- DATABASE CONNECTION DEBUG ---');
    if (process.env.DATABASE_URL) {
        console.log('DATABASE_URL environment variable FOUND.');
        // Mask password for security before logging
        try {
            const maskedUrl = new URL(process.env.DATABASE_URL);
            maskedUrl.password = '*****';
            console.log('Connecting with URL:', maskedUrl.toString());
        } catch (e) {
            console.error('Could not parse DATABASE_URL');
        }
    } else {
        console.error('FATAL: DATABASE_URL environment variable NOT FOUND!');
    }
    console.log('-----------------------------');


    pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: {
            rejectUnauthorized: false
        }
    });

    console.log('Connecting to Supabase...');
    pool.query('SELECT NOW()', (err, res) => {
        if (err) {
            console.error('Error connecting to Supabase', err);
        } else {
            console.log('Successfully connected to Supabase at', res.rows[0].now);
        }
    });
} else {
    // In test environment, use a placeholder object for pool
    // to avoid errors on import. The tests should mock db functions.
    pool = {
        query: () => Promise.resolve({ rows: [] }),
        connect: () => Promise.resolve({
            query: () => Promise.resolve({ rows: [] }),
            release: () => {}
        })
    };
    console.log('Running in TEST environment. Database connection skipped.');
}

const app = express();
const PORT = 3000;
const saltRounds = 10;

app.use(express.json());
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.use(express.static('public'));
app.use(cookieParser());
if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1);
}

app.use(session({
    secret: 'a-very-secret-key-that-should-be-in-env',
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax'
    }
}));

// --- New DB Helper Functions for PostgreSQL ---
const dbQuery = (text, params) => pool.query(text, params);

const dbGet = async (text, params) => {
    const result = await pool.query(text, params);
    return result.rows[0];
};

const dbAll = async (text, params) => {
    const result = await pool.query(text, params);
    return result.rows;
};

const initializeDatabase = async () => {
    try {
        const dropQuery = `
            DROP TABLE IF EXISTS
                cancellation_history,
                stocktake_history,
                replenishment_history,
                usage_history,
                inventories,
                parts,
                categories,
                employees,
                supplier_employees,
                shops,
                users,
                suppliers
            CASCADE;
        `;
        console.log('Dropping existing tables...');
        await dbQuery(dropQuery);
        console.log('Tables dropped successfully.');

        const createSchemaQuery = `
            CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role = 'admin'));
            CREATE TABLE IF NOT EXISTS suppliers (id SERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS shops (id SERIAL PRIMARY KEY, name TEXT NOT NULL, supplier_id INTEGER REFERENCES suppliers(id), username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, UNIQUE(name, supplier_id));
            CREATE TABLE IF NOT EXISTS supplier_employees (id SERIAL PRIMARY KEY, name TEXT NOT NULL, supplier_id INTEGER NOT NULL REFERENCES suppliers(id), is_active BOOLEAN DEFAULT TRUE);
            CREATE TABLE IF NOT EXISTS employees (id SERIAL PRIMARY KEY, name TEXT NOT NULL, shop_id INTEGER NOT NULL REFERENCES shops(id), is_active BOOLEAN DEFAULT TRUE);
            CREATE TABLE IF NOT EXISTS categories (id SERIAL PRIMARY KEY, name TEXT NOT NULL, supplier_id INTEGER REFERENCES suppliers(id), UNIQUE(name, supplier_id));
            CREATE TABLE IF NOT EXISTS parts (id SERIAL PRIMARY KEY, part_number TEXT NOT NULL, part_name TEXT NOT NULL, category_id INTEGER REFERENCES categories(id), supplier_id INTEGER REFERENCES suppliers(id), UNIQUE(part_number, supplier_id));
            CREATE TABLE IF NOT EXISTS inventories (id SERIAL PRIMARY KEY, part_id INTEGER NOT NULL REFERENCES parts(id), shop_id INTEGER NOT NULL REFERENCES shops(id), quantity INTEGER NOT NULL, min_reorder_level INTEGER NOT NULL, location_info TEXT, UNIQUE(part_id, shop_id));
            CREATE TABLE IF NOT EXISTS usage_history (id SERIAL PRIMARY KEY, part_id INTEGER NOT NULL REFERENCES parts(id), shop_id INTEGER NOT NULL REFERENCES shops(id), employee_id INTEGER NOT NULL REFERENCES employees(id), usage_time TIMESTAMPTZ NOT NULL DEFAULT NOW(), status TEXT NOT NULL DEFAULT 'active');
            CREATE TABLE IF NOT EXISTS cancellation_history (id SERIAL PRIMARY KEY, usage_history_id INTEGER NOT NULL REFERENCES usage_history(id), cancelled_by_notes TEXT, cancelled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), reason TEXT);
            CREATE TABLE IF NOT EXISTS stocktake_history (id SERIAL PRIMARY KEY, part_id INTEGER NOT NULL REFERENCES parts(id), shop_id INTEGER NOT NULL REFERENCES shops(id), performed_by_employee_id INTEGER REFERENCES employees(id), stocktake_time TIMESTAMPTZ NOT NULL DEFAULT NOW(), quantity_before INTEGER NOT NULL, quantity_after INTEGER NOT NULL, notes TEXT);
            CREATE TABLE IF NOT EXISTS replenishment_history (id SERIAL PRIMARY KEY, part_id INTEGER NOT NULL REFERENCES parts(id), shop_id INTEGER NOT NULL REFERENCES shops(id), performed_by_supplier_employee_id INTEGER REFERENCES supplier_employees(id), replenished_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), quantity_added INTEGER NOT NULL);
        `;
        console.log('Creating new tables...');
        await dbQuery(createSchemaQuery);
        console.log('Tables created successfully.');

        const adminCountResult = await dbGet("SELECT COUNT(*) AS count FROM users WHERE username = $1", ['admin']);
        const adminCount = parseInt(adminCountResult.count, 10);

        if (adminCount === 0) {
            console.log("Seeding database for PostgreSQL...");

            // 1. Seed Admin
            const adminHash = await bcrypt.hash('password', saltRounds);
            await dbQuery("INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)", ['admin', adminHash, 'admin']);

            // 2. Seed a Supplier
            const supplierHash = await bcrypt.hash('supplier', saltRounds);
            const supplierResult = await dbQuery("INSERT INTO suppliers (name, username, password_hash) VALUES ($1, $2, $3) RETURNING id", ['Default部品商', 'supplier', supplierHash]);
            const supplierId = supplierResult.rows[0].id;

            // 3. Seed a Shop for that Supplier
            const shopHash = await bcrypt.hash('shop', saltRounds);
            const shopResult = await dbQuery("INSERT INTO shops (name, supplier_id, username, password_hash) VALUES ($1, $2, $3, $4) RETURNING id", ['A整備工場', supplierId, 'shop', shopHash]);
            const shopId = shopResult.rows[0].id;

            // 4. Seed employees for the Shop
            await dbQuery("INSERT INTO employees (name, shop_id) VALUES ($1, $2)", ['鈴木 一郎', shopId]);
            await dbQuery("INSERT INTO employees (name, shop_id) VALUES ($1, $2)", ['田中 太郎', shopId]);

            // 5. Seed employees/staff for the Supplier
            await dbQuery("INSERT INTO supplier_employees (name, supplier_id) VALUES ($1, $2)", ['山田 花子', supplierId]);

            // 6. Seed master data (categories and parts) for the Supplier
            const categoryResult = await dbQuery("INSERT INTO categories (name, supplier_id) VALUES ($1, $2) RETURNING id", ['エンジン消耗品', supplierId]);
            const catId = categoryResult.rows[0].id;
            const partResult1 = await dbQuery("INSERT INTO parts (part_number, part_name, category_id, supplier_id) VALUES ($1, $2, $3, $4) RETURNING id", ['EO-001', 'エンジンオイル 5W-30 SN 4L', catId, supplierId]);
            const partResult2 = await dbQuery("INSERT INTO parts (part_number, part_name, category_id, supplier_id) VALUES ($1, $2, $3, $4) RETURNING id", ['OF-001', 'オイルフィルター トヨタ/ダイハツ用', catId, supplierId]);
            
            // 7. Seed inventory linking parts to the shop
            await dbQuery("INSERT INTO inventories (part_id, shop_id, quantity, min_reorder_level, location_info) VALUES ($1, $2, $3, $4, $5)", [partResult1.rows[0].id, shopId, 20, 5, "棚A-1"]);
            await dbQuery("INSERT INTO inventories (part_id, shop_id, quantity, min_reorder_level, location_info) VALUES ($1, $2, $3, $4, $5)", [partResult2.rows[0].id, shopId, 15, 5, "棚A-2"]);

            console.log("PostgreSQL database seeded successfully.");
        }
    } catch (err) {
        console.error("Error during database initialization:", err);
        throw err; // Re-throw the error to be caught by the caller
    }
};

// --- Auth APIs ---
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        // 1. Check for Admin
        const admin = await dbGet("SELECT * FROM users WHERE username = $1", [username]);
        if (admin) {
            const match = await bcrypt.compare(password, admin.password_hash);
            if (match) {
                req.session.auth = { type: 'admin', id: admin.id, username: admin.username, name: admin.username, role: 'admin' };
                return res.json({ message: 'Login successful', user: req.session.auth });
            }
        }

        // 2. Check for Supplier
        const supplier = await dbGet("SELECT * FROM suppliers WHERE username = $1", [username]);
        if (supplier) {
            const match = await bcrypt.compare(password, supplier.password_hash);
            if (match) {
                req.session.auth = { type: 'supplier', id: supplier.id, username: supplier.username, name: supplier.name, role: 'supplier' };
                return res.json({ message: 'Login successful', user: req.session.auth });
            }
        }

        // 3. Check for Shop
        const shop = await dbGet("SELECT * FROM shops WHERE username = $1", [username]);
        if (shop) {
            const match = await bcrypt.compare(password, shop.password_hash);
            if (match) {
                req.session.auth = { type: 'shop', id: shop.id, username: shop.username, name: shop.name, role: 'shop_user', shop_id: shop.id };
                return res.json({ message: 'Login successful', user: req.session.auth });
            }
        }

        // 4. If no user found in any table, return invalid credentials
        return res.status(401).json({ error: 'Invalid credentials' });

    } catch (err) {
        console.error('Server error during login:', err);
        res.status(500).json({ error: 'Server error during login' });
    }
});

app.post('/api/logout', (req, res) => { 
    req.session.destroy(err => { 
        if (err) { 
            return res.status(500).json({ error: 'Could not log out' }); 
        } 
        res.clearCookie('connect.sid'); 
        res.json({ message: 'Logout successful' }); 
    }); 
});

app.get('/api/auth/status', (req, res) => { 
    if (req.session.auth) { 
        res.json({ loggedIn: true, user: req.session.auth }); 
    } else { 
        res.json({ loggedIn: false }); 
    } 
});

app.get('/api/employees', isAuthenticated, isShop, async (req, res) => {
    try {
        const employees = await dbAll(
            "SELECT id, name, is_active FROM employees WHERE shop_id = $1 ORDER BY name",
            [req.session.auth.id]
        );
        res.json(employees);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/employees', isAuthenticated, isShop, async (req, res) => {
    const { name } = req.body;
    const shop_id = req.session.auth.id;
    if (!name) {
        return res.status(400).json({ error: 'Employee name is required' });
    }
    try {
        const result = await dbQuery("INSERT INTO employees (name, shop_id) VALUES ($1, $2) RETURNING id", [name, shop_id]);
        const newEmployee = result.rows[0];
        res.status(201).json({ id: newEmployee.id, name, shop_id });
    } catch (err) {
        console.error(err);
        // Add a more specific error for unique constraint violation
        if (err.code === '23505') { // 23505 is the PostgreSQL error code for unique_violation
            return res.status(409).json({ error: 'An employee with this name may already exist.' });
        }
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/employees/:id', isAuthenticated, isShop, async (req, res) => {
    const { id } = req.params;
    const { name, is_active } = req.body;
    const shop_id = req.session.auth.id;

    if (!name || is_active === undefined) {
        return res.status(400).json({ error: 'Name and is_active are required' });
    }

    try {
        // Ensure the employee belongs to the user's shop before updating
        const employee = await dbGet("SELECT id FROM employees WHERE id = $1 AND shop_id = $2", [id, shop_id]);
        if (!employee) {
            return res.status(404).json({ error: 'Employee not found in your shop' });
        }

        const result = await dbQuery("UPDATE employees SET name = $1, is_active = $2 WHERE id = $3", [name, is_active, id]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Employee not found' });
        }
        res.json({ message: 'Employee updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// --- Middleware ---
function isAuthenticated(req, res, next) {
    if (req.session.auth) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
}

function isAdmin(req, res, next) {
    if (req.session.auth && req.session.auth.type === 'admin') {
        next();
    } else {
        res.status(403).json({ error: 'Forbidden: Admin access required' });
    }
}

function isSupplier(req, res, next) {
    if (req.session.auth && req.session.auth.type === 'supplier') {
        next();
    } else {
        res.status(403).json({ error: 'Forbidden: Supplier access required' });
    }
}

function isShop(req, res, next) {
    if (req.session.auth && req.session.auth.type === 'shop') {
        next();
    } else {
        res.status(403).json({ error: 'Forbidden: Shop access required' });
    }
}

function isAdminOrSupplier(req, res, next) {
    if (req.session.auth && (req.session.auth.type === 'admin' || req.session.auth.type === 'supplier')) {
        next();
    } else {
        res.status(403).json({ error: 'Forbidden: Admin or Supplier access required' });
    }
}

// --- General User APIs ---
app.get('/api/shops', isAuthenticated, async (req, res) => {
    const { type, id } = req.session.auth;
    try {
        if (type === 'admin') {
            const rows = await dbAll("SELECT id, name FROM shops ORDER BY name");
            return res.json(rows);
        }
        if (type === 'supplier') {
            // A supplier can see the shops they manage
            const rows = await dbAll("SELECT id, name FROM shops WHERE supplier_id = $1 ORDER BY name", [id]);
            return res.json(rows);
        }
        if (type === 'shop') {
            // A shop can only see itself
            const row = await dbGet("SELECT id, name FROM shops WHERE id = $1", [id]);
            return res.json(row ? [row] : []);
        }
        return res.status(403).json({ error: 'Forbidden: Invalid role' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/shops/:shopId/inventory', isAuthenticated, async (req, res) => { 
    const { shopId } = req.params;
    const { type, id: authId } = req.session.auth;

    try {
        // --- Authorization ---
        if (type === 'shop' && parseInt(shopId) !== authId) {
            return res.status(403).json({ error: "Forbidden: You can only view your own shop's inventory" });
        }
        if (type === 'supplier') {
            const isManagedShop = await dbGet("SELECT id FROM shops WHERE id = $1 AND supplier_id = $2", [shopId, authId]);
            if (!isManagedShop) {
                return res.status(403).json({ error: "Forbidden: You can only view inventory for shops you manage." });
            }
        }

        // --- Query Building ---
        let sql = `
            SELECT 
                p.id, p.part_number, p.part_name, 
                c.id as category_id, c.name as category_name, 
                i.quantity, i.min_reorder_level, i.location_info 
            FROM inventories i
            JOIN parts p ON i.part_id = p.id
            LEFT JOIN categories c ON p.category_id = c.id 
            WHERE i.shop_id = $1`;
        const params = [shopId];

        if (type === 'supplier') {
            // Suppliers see inventory only for parts they supply (or global parts)
            sql += ` AND (p.supplier_id = $2 OR p.supplier_id IS NULL)`;
            params.push(authId);
        }

        sql += ` ORDER BY c.name, p.part_name;`;

        const rows = await dbAll(sql, params);
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});
app.post('/api/use-part', isAuthenticated, isShop, async (req, res) => { 
    const { part_id, employee_id } = req.body;
    const shop_id = req.session.auth.id;

    if (!part_id || !employee_id) {
        return res.status(400).json({ error: "部品IDと従業員IDは必須です" });
    }

    const client = await pool.connect();

    try {
        // Verify the employee belongs to the shop
        const employeeResult = await client.query("SELECT id FROM employees WHERE id = $1 AND shop_id = $2", [employee_id, shop_id]);
        if (employeeResult.rows.length === 0) {
            return res.status(403).json({ error: "Forbidden: This employee does not belong to your shop." });
        }

        await client.query("BEGIN");

        const updateResult = await client.query("UPDATE inventories SET quantity = quantity - 1 WHERE part_id = $1 AND shop_id = $2 AND quantity > 0", [part_id, shop_id]);

        if (updateResult.rowCount === 0) {
            await client.query("ROLLBACK");
            return res.status(400).json({ error: "在庫がないか、在庫更新に失敗しました。" });
        }

        await client.query("INSERT INTO usage_history (part_id, shop_id, usage_time, employee_id, status) VALUES ($1, $2, NOW(), $3, 'active')", [part_id, shop_id, employee_id]);
        
        const inventoryResult = await client.query(`SELECT i.quantity, i.min_reorder_level, p.part_name FROM inventories i JOIN parts p ON i.part_id = p.id WHERE i.part_id = $1 AND i.shop_id = $2`, [part_id, shop_id]);
        const row = inventoryResult.rows[0];

        if (row && row.quantity < row.min_reorder_level) {
            console.log(`!!! 再発注アラート: [工場ID: ${shop_id}] ${row.part_name} が最低発注レベル (${row.min_reorder_level})を下回りました。現在の在庫: ${row.quantity}`);
        }

        await client.query("COMMIT");
        res.json({ message: "使用記録が完了しました。", stock_left: row ? row.quantity : 0 });

    } catch (err) {
        await client.query("ROLLBACK");
        console.error("Transaction error in /api/use-part: ", err);
        res.status(500).json({ error: "トランザクションエラー: " + err.message });
    } finally {
        client.release();
    }
});

app.get('/api/usage-history', isAuthenticated, isShop, async (req, res) => {
    const shop_id = req.session.auth.id;
    let { month, startDate, endDate } = req.query;

    let sql = `SELECT h.id, p.part_number, p.part_name, h.usage_time, e.name as employee_name, h.status FROM usage_history h JOIN parts p ON h.part_id = p.id JOIN employees e ON h.employee_id = e.id`;
    const whereClauses = [];
    const params = [];
    let paramIndex = 1;

    whereClauses.push(`h.shop_id = $${paramIndex++}`);
    params.push(shop_id);

    if (month) {
        whereClauses.push(`TO_CHAR(h.usage_time, 'YYYY-MM') = $${paramIndex++}`);
        params.push(month);
    } else if (startDate && endDate) {
        whereClauses.push(`h.usage_time BETWEEN $${paramIndex++} AND $${paramIndex++}`);
        params.push(startDate, endDate + ' 23:59:59');
    } else {
        // Default to current month if no range is provided
        const now = new Date();
        month = `${now.getFullYear()}-${(now.getMonth() + 1).toString().padStart(2, '0')}`;
        whereClauses.push(`TO_CHAR(h.usage_time, 'YYYY-MM') = $${paramIndex++}`);
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

app.get('/api/usage-history/csv', isAuthenticated, isShop, async (req, res) => {
    const shop_id = req.session.auth.id;
    let { month, startDate, endDate } = req.query;

    let sql = `SELECT h.id, p.part_number, p.part_name, h.usage_time, e.name as employee_name, h.status, ch.reason as cancellation_reason 
             FROM usage_history h 
             JOIN parts p ON h.part_id = p.id 
             JOIN employees e ON h.employee_id = e.id
             LEFT JOIN cancellation_history ch ON h.id = ch.usage_history_id`;
    const whereClauses = [];
    const params = [];
    let paramIndex = 1;

    whereClauses.push(`h.shop_id = $${paramIndex++}`);
    params.push(shop_id);

    if (month) {
        whereClauses.push(`TO_CHAR(h.usage_time, 'YYYY-MM') = $${paramIndex++}`);
        params.push(month);
    } else if (startDate && endDate) {
        whereClauses.push(`h.usage_time BETWEEN $${paramIndex++} AND $${paramIndex++}`);
        params.push(startDate, endDate + ' 23:59:59');
    } else {
        // Default to current month if no range is provided
        const now = new Date();
        month = `${now.getFullYear()}-${(now.getMonth() + 1).toString().padStart(2, '0')}`;
        whereClauses.push(`TO_CHAR(h.usage_time, 'YYYY-MM') = $${paramIndex++}`);
        params.push(month);
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
    const { type, id } = req.session.auth;
    try {
        let sql = "SELECT id, name, username, supplier_id FROM shops";
        const params = [];
        if (type === 'supplier') {
            sql += " WHERE supplier_id = $1";
            params.push(id);
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
    const { name, username, password, supplier_id } = req.body; // New fields
    const { type, id: authId } = req.session.auth;

    if (!name || !username || !password) {
        return res.status(400).json({ error: '工場名、ログインID、パスワードは必須です' });
    }

    let final_supplier_id = null;
    if (type === 'supplier') {
        final_supplier_id = authId;
    } else if (type === 'admin') {
        final_supplier_id = supplier_id || null;
    }

    try {
        // Cross-table username validation
        const userExists = await dbGet("SELECT id FROM users WHERE username = $1", [username]);
        const supplierExists = await dbGet("SELECT id FROM suppliers WHERE username = $1", [username]);
        if (userExists || supplierExists) {
            return res.status(409).json({ error: `ログインID「${username}」は他の役割で既に使用されています。` });
        }

        const hash = await bcrypt.hash(password, saltRounds);
        const result = await dbQuery(
            "INSERT INTO shops (name, username, password_hash, supplier_id) VALUES ($1, $2, $3, $4) RETURNING id",
            [name, username, hash, final_supplier_id]
        );
        res.json({ id: result.rows[0].id, name, username, supplier_id: final_supplier_id });
    } catch (err) {
        if (err.code === '23505') { // unique_violation
            return res.status(409).json({ error: 'その工場名またはログインIDは既に使用されています。' });
        }
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/admin/shops/:id', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { id: shopId } = req.params;
    const { name, username, password } = req.body;
    const { type, id: authId } = req.session.auth;

    if (!name || !username) {
        return res.status(400).json({ error: '工場名とログインIDは必須です' });
    }

    try {
        // Authorization check
        if (type === 'supplier') {
            const shop = await dbGet("SELECT id FROM shops WHERE id = $1 AND supplier_id = $2", [shopId, authId]);
            if (!shop) {
                return res.status(403).json({ error: 'Forbidden: You can only edit shops you manage.' });
            }
        }

        // Cross-table username validation
        const userExists = await dbGet("SELECT id FROM users WHERE username = $1", [username]);
        const supplierExists = await dbGet("SELECT id FROM suppliers WHERE username = $1", [username]);
        const shopConflict = await dbGet("SELECT id FROM shops WHERE username = $1 AND id != $2", [username, shopId]);
        if (userExists || supplierExists || shopConflict) {
            return res.status(409).json({ error: `ログインID「${username}」は既に使用されています。` });
        }

        if (password) {
            const hash = await bcrypt.hash(password, saltRounds);
            await dbQuery("UPDATE shops SET name = $1, username = $2, password_hash = $3 WHERE id = $4", [name, username, hash, shopId]);
        } else {
            await dbQuery("UPDATE shops SET name = $1, username = $2 WHERE id = $3", [name, username, shopId]);
        }
        res.json({ message: 'Shop updated successfully' });
    } catch (err) {
        if (err.code === '23505') { // unique_violation
            return res.status(409).json({ error: 'その工場名は、同じ部品商の管理下で既に使用されています。' });
        }
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/shops/:id', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { id: shopId } = req.params;
    const { type, id: authId } = req.session.auth;

    try {
        // Authorization
        const shop = await dbGet("SELECT id, supplier_id FROM shops WHERE id = $1", [shopId]);
        if (!shop) {
            return res.status(404).json({ error: 'Shop not found.' });
        }
        if (type === 'supplier' && shop.supplier_id !== authId) {
            return res.status(403).json({ error: 'Forbidden: You can only delete shops you manage.' });
        }

        // Pre-deletion checks
        const employeeCountResult = await dbGet("SELECT COUNT(*) AS count FROM employees WHERE shop_id = $1", [shopId]);
        if (parseInt(employeeCountResult.count, 10) > 0) {
            return res.status(400).json({ error: 'Cannot delete shop: Employees are still assigned to it.' });
        }
        const invCountResult = await dbGet("SELECT COUNT(*) AS count FROM inventories WHERE shop_id = $1", [shopId]);
        if (parseInt(invCountResult.count, 10) > 0) {
            return res.status(400).json({ error: 'Cannot delete shop: Inventory is still assigned to it.' });
        }

        // Deletion
        const result = await dbQuery("DELETE FROM shops WHERE id = $1", [shopId]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Shop not found or could not be deleted.' });
        }
        res.json({ message: 'Shop deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/categories', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { type, id } = req.session.auth;
    try {
        let sql = "SELECT id, name FROM categories";
        const params = [];
        if (type === 'supplier') {
            sql += " WHERE supplier_id = $1 OR supplier_id IS NULL";
            params.push(id);
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
        return res.status(400).json({ error: 'カテゴリー名は必須です' });
    }
    const { type, id } = req.session.auth;
    const supplier_id = type === 'supplier' ? id : null;

    try {
        const result = await dbQuery("INSERT INTO categories (name, supplier_id) VALUES ($1, $2) RETURNING id", [name, supplier_id]);
        res.json({ id: result.rows[0].id, name, supplier_id });
    } catch (err) {
        if (err.code === '23505') { // unique_violation
            return res.status(409).json({ error: `カテゴリー名「${name}」は既に使用されています。` });
        }
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/admin/categories/:id', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { id: categoryId } = req.params;
    const { name } = req.body;
    if (!name) {
        return res.status(400).json({ error: 'Category name is required' });
    }
    const { type, id: authId } = req.session.auth;

    try {
        if (type === 'supplier') {
            const category = await dbGet("SELECT id FROM categories WHERE id = $1 AND supplier_id = $2", [categoryId, authId]);
            if (!category) {
                return res.status(403).json({ error: 'Forbidden: You can only edit categories you own.' });
            }
        }
        const result = await dbQuery("UPDATE categories SET name = $1 WHERE id = $2", [name, categoryId]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Category not found.' });
        }
        res.json({ message: 'Category updated successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/categories/:id', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { id: categoryId } = req.params;
    const { type, id: authId } = req.session.auth;

    try {
        // Authorization
        if (type === 'supplier') {
            const category = await dbGet("SELECT id FROM categories WHERE id = $1 AND supplier_id = $2", [categoryId, authId]);
            if (!category) {
                return res.status(403).json({ error: 'Forbidden: You can only delete categories you own.' });
            }
        }

        // Pre-deletion check
        const partCountResult = await dbGet("SELECT COUNT(*) AS count FROM parts WHERE category_id = $1", [categoryId]);
        if (parseInt(partCountResult.count, 10) > 0) {
            return res.status(400).json({ error: 'Cannot delete category: Parts are still assigned to it.' });
        }

        // Deletion
        const result = await dbQuery("DELETE FROM categories WHERE id = $1", [categoryId]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Category not found.' });
        }
        res.json({ message: 'Category deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/parts', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { type, id } = req.session.auth;
    let sql = `SELECT p.id, p.part_number, p.part_name, p.category_id, c.name as category_name FROM parts p LEFT JOIN categories c ON p.category_id = c.id`;
    const params = [];
    if (type === 'supplier') {
        sql += " WHERE p.supplier_id = $1 OR p.supplier_id IS NULL";
        params.push(id);
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
    const { type, id: authId } = req.session.auth;
    try {
        let uncategorizedCategory;
        if (type === 'supplier') {
            uncategorizedCategory = await dbGet("SELECT id FROM categories WHERE name = $1 AND (supplier_id = $2 OR supplier_id IS NULL)", ['未分類', authId]);
        } else { // admin
            uncategorizedCategory = await dbGet("SELECT id FROM categories WHERE name = $1 AND supplier_id IS NULL", ['未分類']);
        }
        const uncategorizedId = uncategorizedCategory ? uncategorizedCategory.id : -1;

        let sql = `SELECT id, part_number, part_name FROM parts WHERE category_id IS NULL OR category_id = $1`;
        const params = [uncategorizedId];

        if (type === 'supplier') {
            sql += " AND (supplier_id = $2 OR supplier_id IS NULL)";
            params.push(authId);
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
        return res.status(400).json({ error: '品番と部品名は必須です' });
    }
    const { type, id } = req.session.auth;
    const supplier_id = type === 'supplier' ? id : null;
    try {
        const result = await dbQuery("INSERT INTO parts (part_number, part_name, category_id, supplier_id) VALUES ($1, $2, $3, $4) RETURNING id", [part_number, part_name, category_id, supplier_id]);
        res.json({ id: result.rows[0].id, part_number, part_name, category_id, supplier_id });
    } catch (err) {
        if (err.code === '23505') { // unique_violation
            return res.status(409).json({ error: `品番「${part_number}」は既に使用されています。` });
        }
        res.status(500).json({ error: err.message });
    }
});
app.put('/api/admin/parts/:id', isAuthenticated, isAdminOrSupplier, async (req, res) => { 
    const { id: partId } = req.params;
    const { part_number, part_name, category_id } = req.body;
    if (!part_number || !part_name) {
        return res.status(400).json({ error: 'Part number and name are required' });
    }
    const { type, id: authId } = req.session.auth;

    try {
        if (type === 'supplier') {
            const part = await dbGet("SELECT id FROM parts WHERE id = $1 AND supplier_id = $2", [partId, authId]);
            if (!part) {
                return res.status(403).json({ error: 'Forbidden: You can only edit parts you own.' });
            }
        }
        
        const result = await dbQuery("UPDATE parts SET part_number = $1, part_name = $2, category_id = $3 WHERE id = $4", [part_number, part_name, category_id, partId]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Part not found.' });
        }
        res.json({ message: 'Part updated successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/admin/parts/:id/category', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { id: partId } = req.params;
    const { categoryId } = req.body;
    const { type, id: authId } = req.session.auth;

    try {
        if (type === 'supplier') {
            const part = await dbGet("SELECT id FROM parts WHERE id = $1 AND supplier_id = $2", [partId, authId]);
            if (!part) {
                return res.status(403).json({ error: 'Forbidden: You can only assign categories for parts you own.' });
            }
        }
        const result = await dbQuery("UPDATE parts SET category_id = $1 WHERE id = $2", [categoryId, partId]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Part not found.' });
        }
        res.json({ message: 'Category updated successfully.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.delete('/api/admin/parts/:id', isAuthenticated, isAdminOrSupplier, async (req, res) => { 
    const { id: partId } = req.params;
    const { type, id: authId } = req.session.auth;

    try {
        if (type === 'supplier') {
            const part = await dbGet("SELECT id FROM parts WHERE id = $1 AND supplier_id = $2", [partId, authId]);
            if (!part) {
                return res.status(403).json({ error: 'Forbidden: You can only delete parts you own.' });
            }
        }

        const invCountResult = await dbGet("SELECT COUNT(*) AS count FROM inventories WHERE part_id = $1", [partId]);
        if (parseInt(invCountResult.count, 10) > 0) {
            return res.status(400).json({ error: 'Cannot delete part: It still exists in some inventories.' });
        }

        const result = await dbQuery("DELETE FROM parts WHERE id = $1", [partId]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Part not found.' });
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
    const { type, id: authId } = req.session.auth;

    try {
        const invPlaceholders = partIds.map((_, i) => `$${i + 1}`).join(',');
        const invCountSql = `SELECT COUNT(*) AS count FROM inventories WHERE part_id IN (${invPlaceholders})`;
        const invCountResult = await dbGet(invCountSql, partIds);
        if (parseInt(invCountResult.count, 10) > 0) {
            return res.status(400).json({ error: '削除できません: 選択された部品のいくつかが、いずれかの工場の在庫として登録されています。' });
        }

        const deleteParams = [...partIds];
        const deletePlaceholders = partIds.map((_, i) => `$${i + 1}`).join(',');
        let deleteSql = `DELETE FROM parts WHERE id IN (${deletePlaceholders})`;

        if (type === 'supplier') {
            deleteSql += ` AND supplier_id = $${partIds.length + 1}`;
            deleteParams.push(authId);
        }

        const result = await dbQuery(deleteSql, deleteParams);

        if (result.rowCount === 0) {
            return res.status(404).json({ error: '削除対象の部品が見つからないか、権限がありません。' });
        }
        res.json({ message: `${result.rowCount}件の部品を削除しました。` });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/parts/csv', isAuthenticated, isAdminOrSupplier, async (req, res) => { 
    let sql = `SELECT p.id, p.part_number, p.part_name, c.name as category_name FROM parts p LEFT JOIN categories c ON p.category_id = c.id`;
    const params = [];
    if (req.session.auth.type === 'supplier') {
        sql += " WHERE p.supplier_id = $1 OR p.supplier_id IS NULL";
        params.push(req.session.auth.id);
    }
    sql += " ORDER BY p.id";

    try { 
        const rows = await dbAll(sql, params); 
        if (!rows || rows.length === 0) { 
            return res.status(404).send('No parts to export.'); 
        } 
        const header = 'ID,Part Number,Part Name,Category Name\n'; 
        const csvRows = rows.map(row => `"${row.id}","${row.part_number}","${row.part_name}","${row.category_name || ''}"`);
        const csvString = header + csvRows.join('\n');
        const bom = '\uFEFF';
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="parts-master.csv"');
        res.status(200).send(Buffer.from(bom + csvString, 'utf8')); 
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    } 
});
app.post('/api/admin/parts/csv', isAuthenticated, isAdminOrSupplier, upload.single('csvFile'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'CSVファイルがアップロードされていません。' });
    }

    const { type, id: authId } = req.session.auth;
    const supplierId = type === 'supplier' ? authId : null;

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

    const client = await pool.connect();
    try {
        await client.query("BEGIN");

        const getOrCreateCategory = async (name, supplierId) => {
            const categoryResult = await client.query("SELECT id FROM categories WHERE name = $1 AND supplier_id IS NOT DISTINCT FROM $2", [name, supplierId]);
            if (categoryResult.rows.length > 0) {
                return categoryResult.rows[0].id;
            } else {
                const newCategoryResult = await client.query("INSERT INTO categories (name, supplier_id) VALUES ($1, $2) RETURNING id", [name, supplierId]);
                return newCategoryResult.rows[0].id;
            }
        };

        const uncategorizedId = await getOrCreateCategory('未分類', supplierId);

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
                categoryId = await getOrCreateCategory(category_name, supplierId);
            }

            const existingPartResult = await client.query("SELECT id FROM parts WHERE part_number = $1 AND supplier_id IS NOT DISTINCT FROM $2", [part_number, supplierId]);
            if (existingPartResult.rows.length > 0) {
                await client.query("UPDATE parts SET part_name = $1, category_id = $2 WHERE id = $3", [part_name, categoryId, existingPartResult.rows[0].id]);
            } else {
                await client.query("INSERT INTO parts (part_number, part_name, category_id, supplier_id) VALUES ($1, $2, $3, $4)", [part_number, part_name, categoryId, supplierId]);
            }
            successCount++;
        }

        if (errorCount > 0) {
            await client.query("ROLLBACK");
            return res.status(400).json({ error: "CSVインポートがエラーのため中断されました。", details: errors });
        }

        await client.query("COMMIT");
        res.json({ message: "CSVインポートが正常に完了しました。", summary: `成功件数: ${successCount}件。` });
    } catch (err) {
        await client.query("ROLLBACK");
        res.status(500).json({ error: '予期せぬサーバーエラーが発生しました。', details: err.message });
    } finally {
        client.release();
    }
});

// --- Admin: Supplier Management ---
app.get('/api/admin/suppliers', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const suppliers = await dbAll("SELECT id, name, username FROM suppliers ORDER BY id");
        res.json(suppliers);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/suppliers', isAuthenticated, isAdmin, async (req, res) => {
    const { name, username, password } = req.body;
    if (!name || !username || !password) {
        return res.status(400).json({ error: '部品商名、ログインID、パスワードは必須です' });
    }
    try {
        // Cross-table username validation
        const userExists = await dbGet("SELECT id FROM users WHERE username = $1", [username]);
        const shopExists = await dbGet("SELECT id FROM shops WHERE username = $1", [username]);
        if (userExists || shopExists) {
            return res.status(409).json({ error: `ログインID「${username}」は他の役割で既に使用されています。` });
        }

        const hash = await bcrypt.hash(password, saltRounds);
        const result = await dbQuery("INSERT INTO suppliers (name, username, password_hash) VALUES ($1, $2, $3) RETURNING id", [name, username, hash]);
        res.status(201).json({ id: result.rows[0].id, name, username });
    } catch (err) {
        if (err.code === '23505') { // unique_violation
            return res.status(409).json({ error: 'その部品商名またはログインIDは既に使用されています。' });
        }
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/admin/suppliers/:id', isAuthenticated, isAdmin, async (req, res) => {
    const { id: supplierId } = req.params;
    const { name, username, password } = req.body;
    if (!name || !username) {
        return res.status(400).json({ error: '部品商名とログインIDは必須です' });
    }
    try {
        // Cross-table username validation
        const userExists = await dbGet("SELECT id FROM users WHERE username = $1", [username]);
        const shopExists = await dbGet("SELECT id FROM shops WHERE username = $1", [username]);
        const supplierConflict = await dbGet("SELECT id FROM suppliers WHERE username = $1 AND id != $2", [username, supplierId]);
        if (userExists || shopExists || supplierConflict) {
            return res.status(409).json({ error: `ログインID「${username}」は既に使用されています。` });
        }

        if (password) {
            const hash = await bcrypt.hash(password, saltRounds);
            await dbQuery("UPDATE suppliers SET name = $1, username = $2, password_hash = $3 WHERE id = $4", [name, username, hash, supplierId]);
        } else {
            await dbQuery("UPDATE suppliers SET name = $1, username = $2 WHERE id = $3", [name, username, supplierId]);
        }
        res.json({ message: 'Supplier updated successfully' });
    } catch (err) {
        if (err.code === '23505') { // unique_violation
            return res.status(409).json({ error: 'その部品商名は既に使用されています。' });
        }
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/suppliers/:id', isAuthenticated, isAdmin, async (req, res) => {
    const { id: supplierId } = req.params;
    try {
        const shopCountResult = await dbGet("SELECT COUNT(*) AS count FROM shops WHERE supplier_id = $1", [supplierId]);
        if (parseInt(shopCountResult.count, 10) > 0) {
            return res.status(400).json({ error: 'Cannot delete supplier: Shops are still assigned to them.' });
        }
        const partCountResult = await dbGet("SELECT COUNT(*) AS count FROM parts WHERE supplier_id = $1", [supplierId]);
        if (parseInt(partCountResult.count, 10) > 0) {
            return res.status(400).json({ error: 'Cannot delete supplier: Parts are still assigned to them.' });
        }

        const result = await dbQuery("DELETE FROM suppliers WHERE id = $1", [supplierId]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Supplier not found.' });
        }
        res.json({ message: 'Supplier deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- Supplier: Employee Management ---
app.get('/api/supplier/employees', isAuthenticated, isSupplier, async (req, res) => {
    const { id: supplierId } = req.session.auth;
    try {
        const employees = await dbAll("SELECT id, name, is_active FROM supplier_employees WHERE supplier_id = $1 ORDER BY name", [supplierId]);
        res.json(employees);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/supplier/employees', isAuthenticated, isSupplier, async (req, res) => {
    const { name } = req.body;
    const { id: supplierId } = req.session.auth;
    if (!name) {
        return res.status(400).json({ error: 'Employee name is required' });
    }
    try {
        const result = await dbQuery("INSERT INTO supplier_employees (name, supplier_id) VALUES ($1, $2) RETURNING id", [name, supplierId]);
        res.status(201).json({ id: result.rows[0].id, name, supplier_id: supplierId });
    } catch (err) {
        if (err.code === '23505') { // unique_violation
            return res.status(409).json({ error: 'An employee with this name may already exist for this supplier.' });
        }
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/supplier/employees/:id', isAuthenticated, isSupplier, async (req, res) => {
    const { id: employeeId } = req.params;
    const { name, is_active } = req.body;
    const { id: supplierId } = req.session.auth;

    if (!name || is_active === undefined) {
        return res.status(400).json({ error: 'Name and is_active status are required' });
    }
    try {
        const result = await dbQuery("UPDATE supplier_employees SET name = $1, is_active = $2 WHERE id = $3 AND supplier_id = $4", [name, is_active, employeeId, supplierId]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Employee not found or you do not have permission to edit it.' });
        }
        res.json({ message: 'Supplier employee updated successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/supplier/employees/:id', isAuthenticated, isSupplier, async (req, res) => {
    const { id: employeeId } = req.params;
    const { id: supplierId } = req.session.auth;
    try {
        const result = await dbQuery("DELETE FROM supplier_employees WHERE id = $1 AND supplier_id = $2", [employeeId, supplierId]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Employee not found or you do not have permission to delete it.' });
        }
        res.json({ message: 'Supplier employee deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- Admin Employee Management ---



app.get('/api/admin/inventory/locations', isAuthenticated, isAdminOrSupplier, async (req, res) => { try { const rows = await dbAll("SELECT DISTINCT location_info FROM inventories WHERE location_info IS NOT NULL AND location_info != '' ORDER BY location_info"); res.json(rows.map(r => r.location_info)); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/admin/all-inventory', isAuthenticated, isAdminOrSupplier, async (req, res) => { 
    let sql = `SELECT i.part_id, i.shop_id, s.name AS shop_name, p.part_number, p.part_name, i.quantity, i.min_reorder_level, i.location_info FROM inventories i JOIN shops s ON i.shop_id = s.id JOIN parts p ON i.part_id = p.id`;
    const params = [];
    if (req.session.auth.type === 'supplier') {
        sql += " WHERE p.supplier_id = $1 OR p.supplier_id IS NULL";
        params.push(req.session.auth.id);
    }
    sql += " ORDER BY s.name, p.part_name";
    try { 
        const rows = await dbAll(sql, params); 
        res.json(rows); 
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    } 
});
app.post('/api/admin/inventory', isAuthenticated, isAdminOrSupplier, async (req, res) => { 
    const { shop_id, part_id, quantity, min_reorder_level, location_info } = req.body;
    if (!shop_id || !part_id || quantity === undefined || min_reorder_level === undefined) {
        return res.status(400).json({ error: 'Shop, part, quantity, and min_reorder_level are required' });
    }

    if (req.session.auth.type === 'supplier') {
        const part = await dbGet("SELECT id FROM parts WHERE id = $1 AND (supplier_id = $2 OR supplier_id IS NULL)", [part_id, req.session.auth.id]);
        if (!part) {
            return res.status(403).json({ error: 'Forbidden: You can only manage inventory for parts you supply.' });
        }
    }

    const sql = `INSERT INTO inventories (shop_id, part_id, quantity, min_reorder_level, location_info) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (part_id, shop_id) DO UPDATE SET quantity = excluded.quantity, min_reorder_level = excluded.min_reorder_level, location_info = excluded.location_info`;
    try {
        await dbQuery(sql, [shop_id, part_id, quantity, min_reorder_level, location_info || '']);
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

    if (req.session.auth.type === 'supplier') {
        const part = await dbGet("SELECT id FROM parts WHERE id = $1 AND supplier_id = $2", [part_id, req.session.auth.id]);
        if (!part) {
            return res.status(403).json({ error: 'Forbidden: You can only delete inventory for parts you own.' });
        }
    }

    try {
        const result = await dbQuery("DELETE FROM inventories WHERE shop_id = $1 AND part_id = $2", [shop_id, part_id]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Inventory entry not found' });
        }
        res.json({ message: 'Inventory entry deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/inventory/stocktake', isAuthenticated, isAdminOrSupplier, async (req, res) => { 
    const { shop_id, stocktakeData, performed_by_employee_id } = req.body;
    if (!shop_id || !Array.isArray(stocktakeData)) {
        return res.status(400).json({ error: 'Shop ID and stocktake data are required.' });
    }
    const client = await pool.connect();
    try {
        await client.query("BEGIN");
        let updatedCount = 0;
        for (const item of stocktakeData) {
            if (item.part_id == null || item.actual_quantity == null) continue;

            if (req.session.auth.type === 'supplier') {
                const partResult = await client.query("SELECT id FROM parts WHERE id = $1 AND (supplier_id = $2 OR supplier_id IS NULL)", [item.part_id, req.session.auth.id]);
                if (partResult.rows.length === 0) {
                    console.log(`Skipping stocktake for part ID ${item.part_id} as it is not accessible by supplier ${req.session.auth.id}`);
                    continue;
                }
            }

            const invResult = await client.query("SELECT quantity FROM inventories WHERE part_id = $1 AND shop_id = $2", [item.part_id, shop_id]);
            const row = invResult.rows[0];

            if (row && row.quantity !== item.actual_quantity) {
                await client.query("UPDATE inventories SET quantity = $1 WHERE part_id = $2 AND shop_id = $3", [item.actual_quantity, item.part_id, shop_id]);
                const historySql = `INSERT INTO stocktake_history (part_id, shop_id, performed_by_employee_id, stocktake_time, quantity_before, quantity_after, notes) VALUES ($1, $2, $3, NOW(), $4, $5, $6)`;
                await client.query(historySql, [item.part_id, shop_id, performed_by_employee_id, row.quantity, item.actual_quantity, '棚卸しによる調整']);
                updatedCount++;
            }
        }
        await client.query("COMMIT");
        res.json({ message: `Stocktake completed successfully. ${updatedCount} items updated.` });
    } catch (err) {
        console.error('Stocktake transaction failed:', err);
        await client.query("ROLLBACK");
        res.status(500).json({ error: 'Stocktake failed and was rolled back.', details: err.message });
    } finally {
        client.release();
    }
});

app.post('/api/admin/inventory/replenish', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { shop_id, part_id, quantity_added, performed_by_supplier_employee_id } = req.body;

    if (!shop_id || !part_id || !quantity_added) {
        return res.status(400).json({ error: '工場、部品、および補充数量は必須です。' });
    }
    if (req.session.auth.type === 'supplier' && !performed_by_supplier_employee_id) {
        return res.status(400).json({ error: '補充担当者を選択してください。' });
    }

    if (req.session.auth.type === 'supplier') {
        const part = await dbGet("SELECT id FROM parts WHERE id = $1 AND (supplier_id = $2 OR supplier_id IS NULL)", [part_id, req.session.auth.id]);
        if (!part) {
            return res.status(403).json({ error: 'Forbidden: You can only replenish parts you supply.' });
        }
    }

    const quantity = parseInt(quantity_added, 10);
    if (isNaN(quantity) || quantity <= 0) {
        return res.status(400).json({ error: '補充数量は正の整数である必要があります。' });
    }

    const client = await pool.connect();
    try {
        await client.query("BEGIN");

        const invResult = await client.query("SELECT id FROM inventories WHERE part_id = $1 AND shop_id = $2", [part_id, shop_id]);
        const inventory = invResult.rows[0];
        
        if (inventory) {
            await client.query("UPDATE inventories SET quantity = quantity + $1 WHERE id = $2", [quantity, inventory.id]);
        } else {
            await client.query("INSERT INTO inventories (part_id, shop_id, quantity, min_reorder_level, location_info) VALUES ($1, $2, $3, 0, '')", [part_id, shop_id, quantity]);
        }

        const performed_by = req.session.auth.type === 'supplier' ? performed_by_supplier_employee_id : null;
        await client.query(
            `INSERT INTO replenishment_history (part_id, shop_id, performed_by_supplier_employee_id, replenished_at, quantity_added) VALUES ($1, $2, $3, NOW(), $4)`,
            [part_id, shop_id, performed_by, quantity]
        );

        await client.query("COMMIT");
        
        const newQuantityResult = await dbGet("SELECT quantity FROM inventories WHERE part_id = $1 AND shop_id = $2", [part_id, shop_id]);

        res.json({ message: '在庫の補充が正常に完了しました。', new_quantity: newQuantityResult.quantity });
    } catch (err) {
        await client.query("ROLLBACK");
        res.status(500).json({ error: '補充処理中にエラーが発生しました。', details: err.message });
    } finally {
        client.release();
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
    let paramIndex = 1;

    if (req.session.auth.type === 'supplier') {
        whereClauses.push(`(p.supplier_id = $${paramIndex++} OR p.supplier_id IS NULL)`);
        params.push(req.session.auth.id);
    }
    if (startDate) { whereClauses.push(`h.usage_time >= $${paramIndex++}`); params.push(startDate); }
    if (endDate) { whereClauses.push(`h.usage_time <= $${paramIndex++}`); params.push(endDate + ' 23:59:59'); }
    if (shopId) { whereClauses.push(`h.shop_id = $${paramIndex++}`); params.push(shopId); }
    if (partId) { whereClauses.push(`h.part_id = $${paramIndex++}`); params.push(partId); }
    
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
    let paramIndex = 1;

    if (req.session.auth.type === 'supplier') {
        whereClauses.push(`(p.supplier_id = $${paramIndex++} OR p.supplier_id IS NULL)`);
        params.push(req.session.auth.id);
    }
    if (startDate) { whereClauses.push(`h.usage_time >= $${paramIndex++}`); params.push(startDate); }
    if (endDate) { whereClauses.push(`h.usage_time <= $${paramIndex++}`); params.push(endDate + ' 23:59:59'); }
    if (shopId) { whereClauses.push(`h.shop_id = $${paramIndex++}`); params.push(shopId); }
    if (partId) { whereClauses.push(`h.part_id = $${paramIndex++}`); params.push(partId); }
    
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
    if (req.session.auth.type === 'supplier') {
        sql += " AND (p.supplier_id = $1 OR p.supplier_id IS NULL)";
        params.push(req.session.auth.id);
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
    if (req.session.auth.type === 'supplier') {
        sql += " AND (p.supplier_id = $1 OR p.supplier_id IS NULL)";
        params.push(req.session.auth.id);
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
const getReplenishmentHistoryQuery = (queryParams, auth) => {
    const { startDate, endDate, shopId, partId } = queryParams;
    let sql = `SELECT rh.id, s.name AS shop_name, p.part_number, p.part_name, se.name AS user_name, rh.replenished_at, rh.quantity_added
               FROM replenishment_history rh
               LEFT JOIN shops s ON rh.shop_id = s.id 
               LEFT JOIN parts p ON rh.part_id = p.id 
               LEFT JOIN supplier_employees se ON rh.performed_by_supplier_employee_id = se.id`;
    const whereClauses = [];
    const params = [];
    let paramIndex = 1;

    if (auth.type === 'supplier') {
        whereClauses.push(`(p.supplier_id = $${paramIndex++} OR p.supplier_id IS NULL)`);
        params.push(auth.id);
    } else if (auth.type === 'shop') {
        whereClauses.push(`rh.shop_id = $${paramIndex++}`);
        params.push(auth.id);
    }

    if (startDate) { whereClauses.push(`rh.replenished_at >= $${paramIndex++}`); params.push(startDate); }
    if (endDate) { whereClauses.push(`rh.replenished_at <= $${paramIndex++}`); params.push(endDate + ' 23:59:59'); }
    if (shopId && auth.type !== 'shop') { // Shops can't filter by other shops
        whereClauses.push(`rh.shop_id = $${paramIndex++}`); 
        params.push(shopId); 
    }
    if (partId) { whereClauses.push(`rh.part_id = $${paramIndex++}`); params.push(partId); }
    if (whereClauses.length > 0) { sql += " WHERE " + whereClauses.join(" AND "); }
    sql += " ORDER BY rh.replenished_at DESC";
    return { sql, params };
};

app.get('/api/admin/replenishment-history', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    try {
        const { sql, params } = getReplenishmentHistoryQuery(req.query, req.session.auth);
        const rows = await dbAll(sql, params);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/replenishment-history/csv', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    try {
        const { sql, params } = getReplenishmentHistoryQuery(req.query, req.session.auth);
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

// Shop-specific endpoint for replenishment history
app.get('/api/replenishment-history', isAuthenticated, isShop, async (req, res) => {
    try {
        const { sql, params } = getReplenishmentHistoryQuery(req.query, req.session.auth);
        const rows = await dbAll(sql, params);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/replenishment-history/csv', isAuthenticated, isShop, async (req, res) => {
    try {
        const { sql, params } = getReplenishmentHistoryQuery(req.query, req.session.auth);
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

app.post('/api/cancel-usage', isAuthenticated, isShop, async (req, res) => {
    const { usage_id, reason } = req.body;
    const { id: shop_id, username } = req.session.auth;

    if (!usage_id) {
        return res.status(400).json({ error: 'Usage ID is required.' });
    }

    const client = await pool.connect();
    try {
        await client.query("BEGIN");

        const usageResult = await client.query("SELECT * FROM usage_history WHERE id = $1 AND shop_id = $2", [usage_id, shop_id]);
        const usage = usageResult.rows[0];

        if (!usage) {
            await client.query("ROLLBACK");
            return res.status(404).json({ error: 'Usage history not found or you do not have permission to cancel it.' });
        }

        if (usage.status === 'cancelled') {
            await client.query("ROLLBACK");
            return res.status(400).json({ error: 'This usage record has already been cancelled.' });
        }

        // 1. Update usage_history status
        await client.query("UPDATE usage_history SET status = 'cancelled' WHERE id = $1", [usage_id]);

        // 2. Log the cancellation
        const notes = `Cancelled by shop user: ${username}`;
        await client.query("INSERT INTO cancellation_history (usage_history_id, cancelled_by_notes, cancelled_at, reason) VALUES ($1, $2, NOW(), $3)", [usage_id, notes, reason]);

        // 3. Revert inventory quantity
        await client.query("UPDATE inventories SET quantity = quantity + 1 WHERE part_id = $1 AND shop_id = $2", [usage.part_id, usage.shop_id]);

        await client.query("COMMIT");
        res.json({ message: 'Usage record cancelled successfully.' });

    } catch (err) {
        await client.query("ROLLBACK");
        console.error('Cancellation transaction failed:', err);
        res.status(500).json({ error: 'Failed to cancel usage record.', details: err.message });
    } finally {
        client.release();
    }
});

app.post('/api/admin/stocktake-analysis', isAuthenticated, isAdminOrSupplier, async (req, res) => {
    const { part_id, shop_id } = req.body;
    if (!part_id || !shop_id) {
        return res.status(400).json({ error: 'Part ID and Shop ID are required' });
    }

    if (req.session.auth.type === 'supplier') {
        const part = await dbGet("SELECT id FROM parts WHERE id = $1 AND (supplier_id = $2 OR supplier_id IS NULL)", [part_id, req.session.auth.id]);
        if (!part) {
            return res.status(403).json({ error: 'Forbidden: You can only analyze stock for parts you supply.' });
        }
    }

    try {
        // 1. Find the last stocktake as the base point
        let base_time = '1970-01-01 00:00:00';
        let base_quantity = 0;

        const lastStocktake = await dbGet(`
            SELECT stocktake_time, quantity_after 
            FROM stocktake_history
            WHERE part_id = $1 AND shop_id = $2
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
                WHERE part_id = $1 AND shop_id = $2
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
            `SELECT rh.replenished_at, rh.quantity_added, se.name as username 
             FROM replenishment_history rh JOIN supplier_employees se ON rh.performed_by_supplier_employee_id = se.id 
             WHERE rh.part_id = $1 AND rh.shop_id = $2 AND rh.replenished_at > $3 ORDER BY rh.replenished_at DESC`,
            [part_id, shop_id, base_time]
        );

        const usages = await dbAll(
            `SELECT h.usage_time, h.status, e.name as employee_name 
             FROM usage_history h JOIN employees e ON h.employee_id = e.id
             WHERE h.part_id = $1 AND h.shop_id = $2 AND h.usage_time > $3 ORDER BY h.usage_time DESC`,
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
    app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
};

// Only run the server automatically if this file is executed directly
if (require.main === module && process.env.NODE_ENV !== 'test') {
    startServer();
}

module.exports = { app, initializeDatabase };