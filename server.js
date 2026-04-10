const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// Папки
const dataDir = path.join(__dirname, 'data');
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

// SQLite база данных
const db = new sqlite3.Database(path.join(dataDir, 'test_constructor.db'));

// Инициализация таблиц
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS tests (
        id TEXT PRIMARY KEY,
        data TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS users_data (
        id TEXT PRIMARY KEY,
        data TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS tasks_base (
        id TEXT PRIMARY KEY,
        data TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        data TEXT
    )`);
    
    // Начальные данные, если пусто
    db.get("SELECT * FROM tests WHERE id = 'all_tests'", (err, row) => {
        if (!row) {
            db.run("INSERT INTO tests (id, data) VALUES (?, ?)", ['all_tests', JSON.stringify([])]);
        }
    });
    db.get("SELECT * FROM users_data WHERE id = 'all_users'", (err, row) => {
        if (!row) {
            db.run("INSERT INTO users_data (id, data) VALUES (?, ?)", ['all_users', JSON.stringify({ groups: [], users: [] })]);
        }
    });
    db.get("SELECT * FROM tasks_base WHERE id = 'all_tasks'", (err, row) => {
        if (!row) {
            db.run("INSERT INTO tasks_base (id, data) VALUES (?, ?)", ['all_tasks', JSON.stringify([])]);
        }
    });
    db.get("SELECT * FROM sessions WHERE id = 'all_sessions'", (err, row) => {
        if (!row) {
            db.run("INSERT INTO sessions (id, data) VALUES (?, ?)", ['all_sessions', JSON.stringify([])]);
        }
    });
});

// CRUD для тестов
app.get('/api/tests', (req, res) => {
    db.get("SELECT data FROM tests WHERE id = 'all_tests'", (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(row ? JSON.parse(row.data) : []);
    });
});
app.post('/api/tests', (req, res) => {
    const tests = req.body;
    db.run("INSERT OR REPLACE INTO tests (id, data) VALUES (?, ?)", ['all_tests', JSON.stringify(tests)], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// CRUD для пользователей (ученики и группы)
app.get('/api/users-data', (req, res) => {
    db.get("SELECT data FROM users_data WHERE id = 'all_users'", (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(row ? JSON.parse(row.data) : { groups: [], users: [] });
    });
});
app.post('/api/users-data', (req, res) => {
    const data = req.body;
    db.run("INSERT OR REPLACE INTO users_data (id, data) VALUES (?, ?)", ['all_users', JSON.stringify(data)], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// CRUD для базы заданий
app.get('/api/tasks-base', (req, res) => {
    db.get("SELECT data FROM tasks_base WHERE id = 'all_tasks'", (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(row ? JSON.parse(row.data) : []);
    });
});
app.post('/api/tasks-base', (req, res) => {
    const tasks = req.body;
    db.run("INSERT OR REPLACE INTO tasks_base (id, data) VALUES (?, ?)", ['all_tasks', JSON.stringify(tasks)], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// Сессии учеников
app.get('/api/sessions', (req, res) => {
    db.get("SELECT data FROM sessions WHERE id = 'all_sessions'", (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(row ? JSON.parse(row.data) : []);
    });
});
app.post('/api/sessions', (req, res) => {
    const sessions = req.body;
    db.run("INSERT OR REPLACE INTO sessions (id, data) VALUES (?, ?)", ['all_sessions', JSON.stringify(sessions)], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// Загрузка файлов
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => {
        const unique = uuidv4() + path.extname(file.originalname);
        cb(null, unique);
    }
});
const upload = multer({ storage });
app.post('/api/upload-file', upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Файл не загружен' });
    res.json({ fileName: req.file.filename, originalName: req.file.originalname });
});
app.get('/api/uploads/:filename', (req, res) => {
    const filePath = path.join(uploadsDir, req.params.filename);
    if (fs.existsSync(filePath)) res.sendFile(filePath);
    else res.status(404).json({ error: 'Файл не найден' });
});

// Экспорт/импорт всей БД
app.get('/api/export-db', (req, res) => {
    const filePath = path.join(dataDir, 'test_constructor.db');
    res.download(filePath, 'test_constructor.db');
});
const multerDb = multer({ storage: multer.memoryStorage() });
app.post('/api/import-db', multerDb.single('db'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Файл не загружен' });
    const newDbPath = path.join(dataDir, 'test_constructor.db');
    fs.writeFileSync(newDbPath, req.file.buffer);
    res.json({ success: true });
});

// Старт сервера
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Сервер запущен на http://localhost:${PORT}`);
});
