
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

// -------------------------------------------------
// API (ステップ2: 新DB構造対応)
// -------------------------------------------------

// API 1: 全ての工場リストを取得
app.get('/api/shops', (req, res) => {
    db.all("SELECT id, name FROM shops ORDER BY name", [], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// API 2: 指定された工場の在庫部品リストを取得
app.get('/api/shops/:shopId/inventory', (req, res) => {
    const { shopId } = req.params;
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

// API 3: 部品の使用を記録
app.post('/api/use-part', (req, res) => {
    const { part_id, shop_id, mechanic_name } = req.body;

    if (!part_id || !shop_id) {
        return res.status(400).json({ error: "部品IDと工場IDは必須です" });
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
                        // This is tricky, the main transaction is already done. We'll just log the error.
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


app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
