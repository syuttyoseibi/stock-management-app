
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./stock.db');
const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static('public'));

// --- データベースと初期データの準備 (複数工場対応) ---
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

    // 3. 在庫テーブル (工場と部品を紐付け)
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

    // --- 初期データの投入 (初回起動時のみ) ---
    db.get("SELECT COUNT(*) AS count FROM shops", (err, row) => {
        if (row && row.count === 0) {
            console.log("Seeding initial data...");
            const shops = ["A整備工場", "B整備工場"];
            const parts = [
                { number: "OF-001", name: "オイルフィルター X10" },
                { number: "BP-002", name: "ブレーキパッド R20" },
                { number: "BT-003", name: "バッテリー V60" }
            ];

            // 工場を追加
            const shopStmt = db.prepare("INSERT INTO shops (name) VALUES (?)");
            shops.forEach(shop => shopStmt.run(shop));
            shopStmt.finalize();

            // 部品を追加
            const partStmt = db.prepare("INSERT INTO parts (part_number, part_name) VALUES (?, ?)");
            parts.forEach(p => partStmt.run(p.number, p.name));
            partStmt.finalize();

            // 在庫を追加 (A工場とB工場に初期在庫を設定)
            const invStmt = db.prepare("INSERT INTO inventories (part_id, shop_id, quantity, min_reorder_level, location_info) VALUES (?, ?, ?, ?, ?)");
            // A工場
            invStmt.run(1, 1, 15, 5, "棚A-1"); // オイルフィルター
            invStmt.run(2, 1, 8, 3, "棚A-2");  // ブレーキパッド
            // B工場
            invStmt.run(1, 2, 20, 5, "ラック1"); // オイルフィルター
            invStmt.run(3, 2, 5, 2, "ラック2");  // バッテリー
            invStmt.finalize();

            console.log("Initial data seeded successfully.");
        } else {
            console.log("Database already contains data. Skipping seed.");
        }
    });
});


/*
// -------------------------------------------------
// TODO: APIはステップ2で新しいDB構造に合わせて修正します
// -------------------------------------------------

// API 1: 部品リストの取得
app.get('/api/parts', (req, res) => {
    db.all("SELECT id, part_name, current_stock FROM parts ORDER BY part_name", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// API 2: 部品の使用記録
app.post('/api/use-part', (req, res) => {
    const { part_id, mechanic_name } = req.body;
    if (!part_id) return res.status(400).json({ error: "部品IDが必要です" });

    db.serialize(() => {
        db.run("BEGIN TRANSACTION;");

        db.run("UPDATE parts SET current_stock = current_stock - 1 WHERE id = ? AND current_stock > 0", [part_id], function(err) {
            if (err || this.changes === 0) {
                db.run("ROLLBACK;");
                return res.status(400).json({ error: "在庫がないか、在庫更新に失敗しました。" });
            }

            db.run("INSERT INTO usage_history (part_id, usage_time, mechanic_name) VALUES (?, datetime('now', 'localtime'), ?)", [part_id, mechanic_name || '不明'], function(err) {
                if (err) {
                    db.run("ROLLBACK;");
                    return res.status(500).json({ error: "履歴記録エラー: " + err.message });
                }

                db.get("SELECT part_name, current_stock, min_reorder_level FROM parts WHERE id = ?", [part_id], (err, row) => {
                    if (row && row.current_stock < row.min_reorder_level) {
                        console.log(`!!! 再発注アラート: ${row.part_name} が最低発注レベル (${row.min_reorder_level})を下回りました。現在の在庫: ${row.current_stock}`);
                    }
                    db.run("COMMIT;");
                    res.json({ message: "使用記録が完了しました。", stock_left: row.current_stock });
                });
            });
        });
    });
});
*/

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
