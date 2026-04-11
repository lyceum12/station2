const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));
app.use(session({
    secret: 'test_constructor_secret_2025',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 1000 * 60 * 60 * 24 }
}));

// Папки
const dataDir = path.join(__dirname, 'data');
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

// SQLite база данных
const dbPath = path.join(dataDir, 'test_constructor.db');
const db = new sqlite3.Database(dbPath);

// Инициализация таблиц
db.serialize(() => {
    // Администраторы
    db.run(`CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        role TEXT DEFAULT 'admin',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    // Логи
    db.run(`CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT,
        ip TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    // Тесты (хранятся как JSON)
    db.run(`CREATE TABLE IF NOT EXISTS tests (
        id TEXT PRIMARY KEY,
        data TEXT
    )`);
    // Пользователи (ученики)
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        fullName TEXT,
        registrationNumber TEXT UNIQUE,
        groupName TEXT
    )`);
    // Группы
    db.run(`CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE
    )`);
    // База заданий
    db.run(`CREATE TABLE IF NOT EXISTS tasks_base (
        id TEXT PRIMARY KEY,
        data TEXT
    )`);
    // Активные сессии учеников
    db.run(`CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        data TEXT
    )`);
    
    // Создание главного админа
    db.get("SELECT * FROM admins WHERE username = 'admin'", async (err, row) => {
        if (!row) {
            const hash = await bcrypt.hash('admin', 10);
            db.run("INSERT INTO admins (username, password_hash, role) VALUES (?, ?, ?)", ['admin', hash, 'super_admin']);
            console.log('Создан главный администратор: admin / admin');
        }
    });
});

// Вспомогательные функции
function runQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function(err) { if (err) reject(err); else resolve(this); });
    });
}
function getQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => { if (err) reject(err); else resolve(row); });
    });
}
function allQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => { if (err) reject(err); else resolve(rows); });
    });
}

function addLog(username, action, req) {
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

// ========== API авторизации ==========
app.get('/api/check-session', (req, res) => {
    if (req.session.user) res.json({ authenticated: true, role: req.session.user.role });
    else res.json({ authenticated: false });
});
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await getQuery("SELECT * FROM admins WHERE username = ?", [username]);
    if (!user) return res.status(401).json({ error: 'Неверный логин или пароль' });
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Неверный логин или пароль' });
    req.session.user = { id: user.id, username: user.username, role: user.role };
    addLog(user.username, 'Вход в систему', req);
    res.json({ success: true, role: user.role });
});
app.post('/api/logout', (req, res) => {
    if (req.session.user) addLog(req.session.user.username, 'Выход из системы', req);
    req.session.destroy();
    res.json({ success: true });
});
app.post('/api/change-password', isAuthenticated, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const user = await getQuery("SELECT * FROM admins WHERE id = ?", [req.session.user.id]);
    if (!user) return res.status(401).json({ error: 'Пользователь не найден' });
    const match = await bcrypt.compare(oldPassword, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Неверный текущий пароль' });
    const hash = await bcrypt.hash(newPassword, 10);
    await runQuery("UPDATE admins SET password_hash = ? WHERE id = ?", [hash, req.session.user.id]);
    addLog(req.session.user.username, 'Смена пароля', req);
    res.json({ success: true });
});

// ========== Управление администраторами ==========
app.get('/api/admins', isAuthenticated, isSuperAdmin, async (req, res) => {
    const rows = await allQuery("SELECT id, username, role, created_at FROM admins");
    res.json(rows);
});
app.post('/api/admins', isAuthenticated, isSuperAdmin, async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Заполните все поля' });
    const existing = await getQuery("SELECT * FROM admins WHERE username = ?", [username]);
    if (existing) return res.status(400).json({ error: 'Пользователь уже существует' });
    const hash = await bcrypt.hash(password, 10);
    await runQuery("INSERT INTO admins (username, password_hash, role) VALUES (?, ?, ?)", [username, hash, role || 'admin']);
    addLog(req.session.user.username, `Создан администратор ${username}`, req);
    res.json({ success: true });
});
app.delete('/api/admins/:id', isAuthenticated, isSuperAdmin, async (req, res) => {
    const id = parseInt(req.params.id);
    if (id === req.session.user.id) return res.status(400).json({ error: 'Нельзя удалить себя' });
    await runQuery("DELETE FROM admins WHERE id = ?", [id]);
    addLog(req.session.user.username, `Удалён администратор id=${id}`, req);
    res.json({ success: true });
});
app.get('/api/logs', isAuthenticated, isSuperAdmin, async (req, res) => {
    const logs = await allQuery("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 500");
    res.json(logs);
});

// ========== Группы ==========
app.get('/api/groups', isAuthenticated, async (req, res) => {
    const groups = await allQuery("SELECT id, name FROM groups");
    res.json(groups);
});
app.post('/api/groups', isAuthenticated, async (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Введите название' });
    await runQuery("INSERT INTO groups (name) VALUES (?)", [name]);
    res.json({ success: true });
});
app.put('/api/groups/:id', isAuthenticated, async (req, res) => {
    const { name } = req.body;
    await runQuery("UPDATE groups SET name = ? WHERE id = ?", [name, req.params.id]);
    res.json({ success: true });
});
app.delete('/api/groups/:id', isAuthenticated, async (req, res) => {
    await runQuery("DELETE FROM groups WHERE id = ?", [req.params.id]);
    res.json({ success: true });
});

// ========== Пользователи (ученики) ==========
app.get('/api/users', isAuthenticated, async (req, res) => {
    const users = await allQuery("SELECT id, fullName, registrationNumber, groupName FROM users");
    res.json(users);
});
app.post('/api/users', isAuthenticated, async (req, res) => {
    const { fullName, registrationNumber, groupName } = req.body;
    if (!fullName) return res.status(400).json({ error: 'Введите ФИО' });
    let code = registrationNumber;
    if (!code) {
        // Генерация уникального 6-значного кода
        let exists = true;
        while (exists) {
            code = Math.floor(100000 + Math.random() * 900000).toString();
            const existing = await getQuery("SELECT * FROM users WHERE registrationNumber = ?", [code]);
            exists = !!existing;
        }
    } else {
        const existing = await getQuery("SELECT * FROM users WHERE registrationNumber = ?", [code]);
        if (existing) return res.status(400).json({ error: 'Код уже существует' });
    }
    const id = uuidv4();
    await runQuery("INSERT INTO users (id, fullName, registrationNumber, groupName) VALUES (?, ?, ?, ?)", [id, fullName, code, groupName || null]);
    res.json({ success: true, user: { id, fullName, registrationNumber: code, groupName } });
});
app.put('/api/users/:id', isAuthenticated, async (req, res) => {
    const { fullName, registrationNumber, groupName } = req.body;
    const existing = await getQuery("SELECT * FROM users WHERE registrationNumber = ? AND id != ?", [registrationNumber, req.params.id]);
    if (existing) return res.status(400).json({ error: 'Код уже используется другим пользователем' });
    await runQuery("UPDATE users SET fullName = ?, registrationNumber = ?, groupName = ? WHERE id = ?", [fullName, registrationNumber, groupName || null, req.params.id]);
    res.json({ success: true });
});
app.delete('/api/users/:id', isAuthenticated, async (req, res) => {
    await runQuery("DELETE FROM users WHERE id = ?", [req.params.id]);
    res.json({ success: true });
});

// ========== Тесты ==========
app.get('/api/tests', isAuthenticated, async (req, res) => {
    const row = await getQuery("SELECT data FROM tests WHERE id = 'all_tests'");
    res.json(row ? JSON.parse(row.data) : []);
});
app.post('/api/tests', isAuthenticated, async (req, res) => {
    await runQuery("INSERT OR REPLACE INTO tests (id, data) VALUES (?, ?)", ['all_tests', JSON.stringify(req.body)]);
    addLog(req.session.user.username, 'Сохранение тестов', req);
    res.json({ success: true });
});

// ========== База заданий ==========
app.get('/api/tasks-base', isAuthenticated, async (req, res) => {
    const row = await getQuery("SELECT data FROM tasks_base WHERE id = 'all_tasks'");
    res.json(row ? JSON.parse(row.data) : []);
});
app.post('/api/tasks-base', isAuthenticated, async (req, res) => {
    await runQuery("INSERT OR REPLACE INTO tasks_base (id, data) VALUES (?, ?)", ['all_tasks', JSON.stringify(req.body)]);
    res.json({ success: true });
});

// ========== Сессии учеников ==========
app.get('/api/sessions', isAuthenticated, async (req, res) => {
    const row = await getQuery("SELECT data FROM sessions WHERE id = 'all_sessions'");
    res.json(row ? JSON.parse(row.data) : []);
});
app.post('/api/sessions', isAuthenticated, async (req, res) => {
    await runQuery("INSERT OR REPLACE INTO sessions (id, data) VALUES (?, ?)", ['all_sessions', JSON.stringify(req.body)]);
    res.json({ success: true });
});

// Старт сессии (без авторизации)
app.post('/api/start-session', async (req, res) => {
    const { testId, testLogin, studentCode } = req.body;
    // Получаем тест
    const testRow = await getQuery("SELECT data FROM tests WHERE id = 'all_tests'");
    const tests = testRow ? JSON.parse(testRow.data) : [];
    const test = tests.find(t => t.id === testId);
    if (!test) return res.status(404).json({ error: 'Тест не найден' });
    // Проверяем логин теста
    if (test.testLogin !== testLogin) return res.status(403).json({ error: 'Неверный логин теста' });
    // Проверяем ученика по коду
    const student = await getQuery("SELECT * FROM users WHERE registrationNumber = ?", [studentCode]);
    if (!student) return res.status(403).json({ error: 'Неверный код участника' });
    // Проверяем, добавлен ли ученик в этот тест
    const testStudents = test.students || [];
    if (!testStudents.some(s => s.registrationNumber === studentCode)) {
        return res.status(403).json({ error: 'Вы не добавлены в этот тест' });
    }
    // Лимит попыток
    const attemptsLimit = test.attemptsLimit || 0;
    if (attemptsLimit > 0) {
        const results = test.results || [];
        const attemptsCount = results.filter(r => r.studentRegNumber === studentCode).length;
        if (attemptsCount >= attemptsLimit) {
            return res.status(403).json({ error: `Превышен лимит попыток (${attemptsLimit})` });
        }
    }
    // Формируем порядок вопросов
    let questionsOrder = [...(test.questions || [])].sort(() => Math.random() - 0.5).map(q => q.id);
    if (test.instruction && test.instruction.blocks && test.instruction.blocks.length) {
        questionsOrder.unshift('__INSTRUCTION__');
    }
    const endTime = Date.now() + (test.timeLimitMinutes || 60) * 60 * 1000;
    const sessionId = uuidv4();
    const sessions = await getQuery("SELECT data FROM sessions WHERE id = 'all_sessions'") || { data: '[]' };
    let sessionsList = JSON.parse(sessions.data);
    sessionsList.push({
        id: sessionId, testId, studentRegNumber: studentCode, studentName: student.fullName,
        startTime: Date.now(), endTimestamp: endTime, questionsOrder, currentIndex: 0, answers: {}
    });
    await runQuery("INSERT OR REPLACE INTO sessions (id, data) VALUES (?, ?)", ['all_sessions', JSON.stringify(sessionsList)]);
    res.json({ sessionId, endTimestamp: endTime, questionsOrder });
});

app.get('/api/session/:sessionId', async (req, res) => {
    const sessionsRow = await getQuery("SELECT data FROM sessions WHERE id = 'all_sessions'");
    const sessions = sessionsRow ? JSON.parse(sessionsRow.data) : [];
    const session = sessions.find(s => s.id === req.params.sessionId);
    if (!session) return res.status(404).json({ error: 'Сессия не найдена' });
    res.json(session);
});

app.post('/api/session/:sessionId', async (req, res) => {
    const { answers, currentIndex } = req.body;
    const sessionsRow = await getQuery("SELECT data FROM sessions WHERE id = 'all_sessions'");
    let sessions = sessionsRow ? JSON.parse(sessionsRow.data) : [];
    const idx = sessions.findIndex(s => s.id === req.params.sessionId);
    if (idx === -1) return res.status(404).json({ error: 'Сессия не найдена' });
    if (answers) sessions[idx].answers = { ...sessions[idx].answers, ...answers };
    if (currentIndex !== undefined) sessions[idx].currentIndex = currentIndex;
    await runQuery("INSERT OR REPLACE INTO sessions (id, data) VALUES (?, ?)", ['all_sessions', JSON.stringify(sessions)]);
    res.json({ success: true });
});

app.post('/api/finish-session/:sessionId', async (req, res) => {
    const sessionsRow = await getQuery("SELECT data FROM sessions WHERE id = 'all_sessions'");
    let sessions = sessionsRow ? JSON.parse(sessionsRow.data) : [];
    const idx = sessions.findIndex(s => s.id === req.params.sessionId);
    if (idx === -1) return res.status(404).json({ error: 'Сессия не найдена' });
    const session = sessions[idx];
    // Сохраняем результат в тест
    const testsRow = await getQuery("SELECT data FROM tests WHERE id = 'all_tests'");
    let tests = testsRow ? JSON.parse(testsRow.data) : [];
    const testIdx = tests.findIndex(t => t.id === session.testId);
    if (testIdx !== -1) {
        if (!tests[testIdx].results) tests[testIdx].results = [];
        tests[testIdx].results.push({
            studentRegNumber: session.studentRegNumber,
            studentName: session.studentName,
            finishedAt: Date.now(),
            answers: Object.entries(session.answers).map(([qid, ans]) => ({ questionId: qid, answerText: ans.text, files: ans.files || [] }))
        });
        await runQuery("INSERT OR REPLACE INTO tests (id, data) VALUES (?, ?)", ['all_tests', JSON.stringify(tests)]);
    }
    sessions.splice(idx, 1);
    await runQuery("INSERT OR REPLACE INTO sessions (id, data) VALUES (?, ?)", ['all_sessions', JSON.stringify(sessions)]);
    res.json({ success: true });
});

// Загрузка файлов
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
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

// Экспорт / импорт всей БД
app.get('/api/export-db', isAuthenticated, (req, res) => {
    res.download(dbPath, 'test_constructor.db');
});
const uploadDb = multer({ storage: multer.memoryStorage() });
app.post('/api/import-db', isAuthenticated, uploadDb.single('db'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Файл не загружен' });
    fs.writeFileSync(dbPath, req.file.buffer);
    addLog(req.session.user.username, 'Импорт базы данных', req);
    res.json({ success: true });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Сервер запущен на http://localhost:${PORT}`);
    console.log(`Логин: admin, пароль: admin`);
});
