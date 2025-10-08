
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./stock.db');
const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static('public')); 

// --- データベースと初期データの準備 ---
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS parts (\n        id INTEGER PRIMARY KEY AUTOINCREMENT,\n        part_name TEXT NOT NULL,\n        stock_location TEXT NOT NULL,\n        current_stock INTEGER NOT NULL,\n        min_reorder_level INTEGER NOT NULL\n    )`);

    db.run(`CREATE TABLE IF NOT EXISTS usage_history (\n        id INTEGER PRIMARY KEY AUTOINCREMENT,\n        part_id INTEGER NOT NULL,\n        usage_time TEXT NOT NULL,\n        mechanic_name TEXT,\n        FOREIGN KEY (part_id) REFERENCES parts(id)\n    )`);
    
    db.get("SELECT COUNT(*) AS count FROM parts", (err, row) => {
        if (row && row.count === 0) {
            const stmt = db.prepare("INSERT INTO parts (part_name, stock_location, current_stock, min_reorder_level) VALUES (?, ?, ?, ?)");
            stmt.run("オイルフィルター X10", "田辺工場_棚A", 15, 5);
            stmt.run("ブレーキパッド R20", "田辺工場_棚B", 8, 3);
            stmt.run("バッテリー V60", "田辺工場_棚C", 4, 2);
            stmt.finalize();
            console.log("Initial test data inserted.");
        }
    });
});


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

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
