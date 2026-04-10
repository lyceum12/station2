const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// Настройка CORS для работы с credentials
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
    secret: 'test_constructor_secret_key_2025',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 1000 * 60 * 60 * 24 }
}));

// Папки
const dataDir = path.join(__dirname, 'data');
const uploadsDir = path.join(__dirname, 'uploads');
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir);

// SQLite база данных
const db = new sqlite3.Database(path.join(dataDir, 'test_constructor.db'));

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        role TEXT DEFAULT 'admin',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS tests (id TEXT PRIMARY KEY, data TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS users_data (id TEXT PRIMARY KEY, data TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS tasks_base (id TEXT PRIMARY KEY, data TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, data TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT,
        ip TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    db.get("SELECT * FROM users WHERE username = 'admin'", async (err, row) => {
        if (!row) {
            const hash = await bcrypt.hash('admin', 10);
            db.run("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", ['admin', hash, 'super_admin']);
            console.log('Создан главный администратор: admin / admin');
        }
    });
});

function logAction(username, action, req) {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    db.run("INSERT INTO logs (username, action, ip) VALUES (?, ?, ?)", [username, action, ip]);
}

function isAuthenticated(req, res, next) {
    if (req.session.user) return next();
    res.status(401).json({ error: 'Не авторизован' });
}

function isSuperAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'super_admin') return next();
    res.status(403).json({ error: 'Доступ запрещён' });
}

// API

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err || !user) return res.status(401).json({ error: 'Неверные учётные данные' });
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(401).json({ error: 'Неверные учётные данные' });
        req.session.user = { id: user.id, username: user.username, role: user.role };
        logAction(user.username, 'Вход в систему', req);
        res.json({ success: true, role: user.role });
    });
});

app.post('/api/logout', (req, res) => {
    if (req.session.user) logAction(req.session.user.username, 'Выход из системы', req);
    req.session.destroy();
    res.json({ success: true });
});

app.post('/api/change-password', isAuthenticated, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    db.get("SELECT * FROM users WHERE id = ?", [req.session.user.id], async (err, user) => {
        if (err || !user) return res.status(401).json({ error: 'Пользователь не найден' });
        const match = await bcrypt.compare(oldPassword, user.password_hash);
        if (!match) return res.status(401).json({ error: 'Неверный текущий пароль' });
        const hash = await bcrypt.hash(newPassword, 10);
        db.run("UPDATE users SET password_hash = ? WHERE id = ?", [hash, req.session.user.id]);
        logAction(req.session.user.username, 'Смена пароля', req);
        res.json({ success: true });
    });
});

app.get('/api/users-list', isAuthenticated, isSuperAdmin, (req, res) => {
    db.all("SELECT id, username, role, created_at FROM users", (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/create-admin', isAuthenticated, isSuperAdmin, async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Заполните все поля' });
    const hash = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", [username, hash, role || 'admin'], function(err) {
        if (err) return res.status(400).json({ error: 'Пользователь уже существует' });
        logAction(req.session.user.username, `Создан администратор ${username}`, req);
        res.json({ success: true });
    });
});

app.post('/api/delete-admin', isAuthenticated, isSuperAdmin, (req, res) => {
    const { id } = req.body;
    if (id == req.session.user.id) return res.status(400).json({ error: 'Нельзя удалить самого себя' });
    db.run("DELETE FROM users WHERE id = ?", [id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        logAction(req.session.user.username, `Удалён администратор id=${id}`, req);
        res.json({ success: true });
    });
});

app.get('/api/logs', isAuthenticated, isSuperAdmin, (req, res) => {
    db.all("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 1000", (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.get('/api/tests', isAuthenticated, (req, res) => {
    db.get("SELECT data FROM tests WHERE id = 'all_tests'", (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(row ? JSON.parse(row.data) : []);
    });
});

app.post('/api/tests', isAuthenticated, (req, res) => {
    const tests = req.body;
    db.run("INSERT OR REPLACE INTO tests (id, data) VALUES (?, ?)", ['all_tests', JSON.stringify(tests)], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        logAction(req.session.user.username, 'Сохранение тестов', req);
        res.json({ success: true });
    });
});

app.get('/api/users-data', isAuthenticated, (req, res) => {
    db.get("SELECT data FROM users_data WHERE id = 'all_users'", (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(row ? JSON.parse(row.data) : { groups: [], users: [] });
    });
});

app.post('/api/users-data', isAuthenticated, (req, res) => {
    const data = req.body;
    db.run("INSERT OR REPLACE INTO users_data (id, data) VALUES (?, ?)", ['all_users', JSON.stringify(data)], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        logAction(req.session.user.username, 'Сохранение пользователей', req);
        res.json({ success: true });
    });
});

app.get('/api/tasks-base', isAuthenticated, (req, res) => {
    db.get("SELECT data FROM tasks_base WHERE id = 'all_tasks'", (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(row ? JSON.parse(row.data) : []);
    });
});

app.post('/api/tasks-base', isAuthenticated, (req, res) => {
    const tasks = req.body;
    db.run("INSERT OR REPLACE INTO tasks_base (id, data) VALUES (?, ?)", ['all_tasks', JSON.stringify(tasks)], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        logAction(req.session.user.username, 'Сохранение базы заданий', req);
        res.json({ success: true });
    });
});

app.get('/api/sessions', isAuthenticated, (req, res) => {
    db.get("SELECT data FROM sessions WHERE id = 'all_sessions'", (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(row ? JSON.parse(row.data) : []);
    });
});

app.post('/api/sessions', isAuthenticated, (req, res) => {
    const sessions = req.body;
    db.run("INSERT OR REPLACE INTO sessions (id, data) VALUES (?, ?)", ['all_sessions', JSON.stringify(sessions)], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

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

app.get('/api/export-db', isAuthenticated, (req, res) => {
    const filePath = path.join(dataDir, 'test_constructor.db');
    res.download(filePath, 'test_constructor.db');
});
const multerDb = multer({ storage: multer.memoryStorage() });
app.post('/api/import-db', isAuthenticated, multerDb.single('db'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Файл не загружен' });
    const newDbPath = path.join(dataDir, 'test_constructor.db');
    fs.writeFileSync(newDbPath, req.file.buffer);
    logAction(req.session.user.username, 'Импорт базы данных', req);
    res.json({ success: true });
});

app.get('/api/check-session', (req, res) => {
    if (req.session.user) res.json({ authenticated: true, role: req.session.user.role });
    else res.json({ authenticated: false });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Сервер запущен на http://localhost:${PORT}`);
    console.log(`Главный админ: admin / admin`);
});
