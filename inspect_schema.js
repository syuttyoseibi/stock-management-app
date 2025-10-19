
const sqlite3 = require('sqlite3').verbose();
const dbPath = './data/stock.db';

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Could not connect to database', err);
        return;
    }
    console.log('Connected to database at', dbPath);
});

db.serialize(() => {
    db.all("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'", [], (err, tables) => {
        if (err) {
            console.error('Error fetching tables', err);
            return;
        }
        tables.forEach((table) => {
            console.log(`-- Schema for table: ${table.name}`);
            console.log(table.sql + ';\n');
        });
    });
});

db.close((err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Closed the database connection.');
});

