const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
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

// Файлы данных
const usersFile = path.join(dataDir, 'users.json');
const logsFile = path.join(dataDir, 'logs.json');
const testsFile = path.join(dataDir, 'tests.json');
const tasksBaseFile = path.join(dataDir, 'tasks_base.json');
const sessionsFile = path.join(dataDir, 'sessions.json');

// Инициализация файлов
if (!fs.existsSync(usersFile)) {
    const defaultUsers = [
        { id: 1, username: 'admin', password_hash: bcrypt.hashSync('admin', 10), role: 'super_admin', created_at: new Date().toISOString() }
    ];
    fs.writeFileSync(usersFile, JSON.stringify(defaultUsers, null, 2));
}
if (!fs.existsSync(logsFile)) fs.writeFileSync(logsFile, JSON.stringify([]));
if (!fs.existsSync(testsFile)) fs.writeFileSync(testsFile, JSON.stringify([]));
if (!fs.existsSync(tasksBaseFile)) fs.writeFileSync(tasksBaseFile, JSON.stringify([]));
if (!fs.existsSync(sessionsFile)) fs.writeFileSync(sessionsFile, JSON.stringify([]));

// Вспомогательные функции
function readJSON(file) {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
}
function writeJSON(file, data) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// Логирование
function addLog(username, action, req) {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const logs = readJSON(logsFile);
    logs.unshift({ timestamp: new Date().toISOString(), username, action, ip });
    if (logs.length > 1000) logs.pop();
    writeJSON(logsFile, logs);
}

// Middleware проверки авторизации
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
    if (req.session.user) {
        res.json({ authenticated: true, role: req.session.user.role });
    } else {
        res.json({ authenticated: false });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const users = readJSON(usersFile);
    const user = users.find(u => u.username === username);
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
    const users = readJSON(usersFile);
    const user = users.find(u => u.id === req.session.user.id);
    if (!user) return res.status(401).json({ error: 'Пользователь не найден' });
    const match = await bcrypt.compare(oldPassword, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Неверный текущий пароль' });
    user.password_hash = await bcrypt.hash(newPassword, 10);
    writeJSON(usersFile, users);
    addLog(req.session.user.username, 'Смена пароля', req);
    res.json({ success: true });
});

// ========== Управление администраторами (только super_admin) ==========
app.get('/api/users-list', isAuthenticated, isSuperAdmin, (req, res) => {
    const users = readJSON(usersFile);
    const safeUsers = users.map(({ id, username, role, created_at }) => ({ id, username, role, created_at }));
    res.json(safeUsers);
});

app.post('/api/create-admin', isAuthenticated, isSuperAdmin, async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Заполните все поля' });
    const users = readJSON(usersFile);
    if (users.find(u => u.username === username)) return res.status(400).json({ error: 'Пользователь уже существует' });
    const newId = users.length ? Math.max(...users.map(u => u.id)) + 1 : 2;
    const newUser = {
        id: newId,
        username,
        password_hash: await bcrypt.hash(password, 10),
        role: role || 'admin',
        created_at: new Date().toISOString()
    };
    users.push(newUser);
    writeJSON(usersFile, users);
    addLog(req.session.user.username, `Создан администратор ${username} (${newUser.role})`, req);
    res.json({ success: true });
});

app.post('/api/delete-admin', isAuthenticated, isSuperAdmin, (req, res) => {
    const { id } = req.body;
    if (id === req.session.user.id) return res.status(400).json({ error: 'Нельзя удалить самого себя' });
    let users = readJSON(usersFile);
    const userToDelete = users.find(u => u.id === id);
    if (!userToDelete) return res.status(404).json({ error: 'Пользователь не найден' });
    users = users.filter(u => u.id !== id);
    writeJSON(usersFile, users);
    addLog(req.session.user.username, `Удалён администратор ${userToDelete.username}`, req);
    res.json({ success: true });
});

app.get('/api/logs', isAuthenticated, isSuperAdmin, (req, res) => {
    const logs = readJSON(logsFile);
    res.json(logs);
});

// ========== Основные данные ==========
app.get('/api/tests', isAuthenticated, (req, res) => res.json(readJSON(testsFile)));
app.post('/api/tests', isAuthenticated, (req, res) => { writeJSON(testsFile, req.body); res.json({ success: true }); });
app.get('/api/users', isAuthenticated, (req, res) => {
    // users.json здесь – это пользователи-ученики, а не администраторы (отдельный файл)
    const file = path.join(dataDir, 'users_data.json');
    if (!fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify({ groups: [], users: [] }));
    res.json(JSON.parse(fs.readFileSync(file)));
});
app.post('/api/users', isAuthenticated, (req, res) => {
    const file = path.join(dataDir, 'users_data.json');
    fs.writeFileSync(file, JSON.stringify(req.body));
    res.json({ success: true });
});
app.get('/api/tasks-base', isAuthenticated, (req, res) => res.json(readJSON(tasksBaseFile)));
app.post('/api/tasks-base', isAuthenticated, (req, res) => { writeJSON(tasksBaseFile, req.body); res.json({ success: true }); });
app.get('/api/sessions', isAuthenticated, (req, res) => res.json(readJSON(sessionsFile)));
app.post('/api/sessions', isAuthenticated, (req, res) => { writeJSON(sessionsFile, req.body); res.json({ success: true }); });

// Экспорт/импорт всех данных
app.get('/api/export-data', isAuthenticated, (req, res) => {
    const allData = {
        tests: readJSON(testsFile),
        users_data: JSON.parse(fs.readFileSync(path.join(dataDir, 'users_data.json'), 'utf8')),
        tasks_base: readJSON(tasksBaseFile),
        sessions: readJSON(sessionsFile)
    };
    res.setHeader('Content-Disposition', 'attachment; filename="test_constructor_backup.json"');
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(allData, null, 2));
});

app.post('/api/import-data', isAuthenticated, (req, res) => {
    const { tests, users_data, tasks_base, sessions } = req.body;
    if (tests !== undefined) writeJSON(testsFile, tests);
    if (users_data !== undefined) fs.writeFileSync(path.join(dataDir, 'users_data.json'), JSON.stringify(users_data, null, 2));
    if (tasks_base !== undefined) writeJSON(tasksBaseFile, tasks_base);
    if (sessions !== undefined) writeJSON(sessionsFile, sessions);
    addLog(req.session.user.username, 'Импорт данных', req);
    res.json({ success: true });
});

// ========== Сессии учеников (без авторизации) ==========
app.post('/api/start-session', (req, res) => {
    const { testId, studentRegNumber, studentName } = req.body;
    const tests = readJSON(testsFile);
    const test = tests.find(t => t.id === testId);
    if (!test) return res.status(404).json({ error: 'Тест не найден' });
    const student = (test.students || []).find(s => s.registrationNumber === studentRegNumber);
    if (!student) return res.status(403).json({ error: 'Код участника не найден' });
    const shuffledIds = [...(test.questions || [])].sort(() => Math.random() - 0.5).map(q => q.id);
    const endTime = Date.now() + (test.timeLimitMinutes || 60) * 60 * 1000;
    const sessionId = uuidv4();
    const sessions = readJSON(sessionsFile);
    sessions.push({
        id: sessionId,
        testId,
        studentRegNumber,
        studentName: student.fullName,
        startTime: Date.now(),
        endTimestamp: endTime,
        questionsOrder: shuffledIds,
        currentIndex: 0,
        answers: {}
    });
    writeJSON(sessionsFile, sessions);
    res.json({ sessionId, endTimestamp: endTime, questionsOrder: shuffledIds });
});

app.get('/api/session/:sessionId', (req, res) => {
    const sessions = readJSON(sessionsFile);
    const session = sessions.find(s => s.id === req.params.sessionId);
    if (!session) return res.status(404).json({ error: 'Сессия не найдена' });
    res.json(session);
});

app.post('/api/session/:sessionId', (req, res) => {
    const { answers, currentIndex } = req.body;
    const sessions = readJSON(sessionsFile);
    const index = sessions.findIndex(s => s.id === req.params.sessionId);
    if (index === -1) return res.status(404).json({ error: 'Сессия не найдена' });
    if (answers) sessions[index].answers = { ...sessions[index].answers, ...answers };
    if (currentIndex !== undefined) sessions[index].currentIndex = currentIndex;
    writeJSON(sessionsFile, sessions);
    res.json({ success: true });
});

app.post('/api/finish-session/:sessionId', (req, res) => {
    const sessions = readJSON(sessionsFile);
    const index = sessions.findIndex(s => s.id === req.params.sessionId);
    if (index === -1) return res.status(404).json({ error: 'Сессия не найдена' });
    const session = sessions[index];
    const tests = readJSON(testsFile);
    const testIndex = tests.findIndex(t => t.id === session.testId);
    if (testIndex !== -1) {
        if (!tests[testIndex].results) tests[testIndex].results = [];
        tests[testIndex].results.push({
            studentRegNumber: session.studentRegNumber,
            studentName: session.studentName,
            finishedAt: Date.now(),
            answers: Object.entries(session.answers).map(([qid, ans]) => ({
                questionId: qid,
                answerText: ans.text,
                files: ans.files || []
            }))
        });
        writeJSON(testsFile, tests);
    }
    sessions.splice(index, 1);
    writeJSON(sessionsFile, sessions);
    res.json({ success: true });
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

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Сервер запущен на http://localhost:${PORT}`);
    console.log(`Логин: admin, пароль: admin`);
});
