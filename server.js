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

// Файл с данными администратора
const adminFile = path.join(dataDir, 'admin.json');

// Инициализация администратора по умолчанию
async function initAdmin() {
    if (!fs.existsSync(adminFile)) {
        const hash = await bcrypt.hash('admin', 10);
        fs.writeFileSync(adminFile, JSON.stringify({ username: 'admin', password_hash: hash }));
        console.log('Создан администратор: admin / admin');
    }
}
initAdmin();

// Вспомогательные функции для работы с JSON-файлами
function readJSON(file) {
    const filePath = path.join(dataDir, file);
    if (!fs.existsSync(filePath)) return [];
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function writeJSON(file, data) {
    fs.writeFileSync(path.join(dataDir, file), JSON.stringify(data, null, 2));
}

// ========== API авторизации ==========

// Проверка сессии
app.get('/api/check-session', (req, res) => {
    if (req.session.user) {
        res.json({ authenticated: true });
    } else {
        res.json({ authenticated: false });
    }
});

// Вход
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const admin = JSON.parse(fs.readFileSync(adminFile, 'utf8'));
    if (username !== admin.username) {
        return res.status(401).json({ error: 'Неверный логин или пароль' });
    }
    const match = await bcrypt.compare(password, admin.password_hash);
    if (!match) {
        return res.status(401).json({ error: 'Неверный логин или пароль' });
    }
    req.session.user = { username: admin.username };
    res.json({ success: true });
});

// Выход
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Смена пароля
app.post('/api/change-password', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Не авторизован' });
    const { oldPassword, newPassword } = req.body;
    const admin = JSON.parse(fs.readFileSync(adminFile, 'utf8'));
    const match = await bcrypt.compare(oldPassword, admin.password_hash);
    if (!match) {
        return res.status(401).json({ error: 'Неверный текущий пароль' });
    }
    const newHash = await bcrypt.hash(newPassword, 10);
    fs.writeFileSync(adminFile, JSON.stringify({ username: admin.username, password_hash: newHash }));
    res.json({ success: true });
});

// Middleware для проверки авторизации в API
function isAuthenticated(req, res, next) {
    if (req.session.user) return next();
    res.status(401).json({ error: 'Не авторизован' });
}

// ========== Защищённые API ==========
app.get('/api/tests', isAuthenticated, (req, res) => {
    const tests = readJSON('tests.json');
    res.json(tests);
});

app.post('/api/tests', isAuthenticated, (req, res) => {
    writeJSON('tests.json', req.body);
    res.json({ success: true });
});

app.get('/api/users', isAuthenticated, (req, res) => {
    const users = readJSON('users.json');
    res.json(users);
});

app.post('/api/users', isAuthenticated, (req, res) => {
    writeJSON('users.json', req.body);
    res.json({ success: true });
});

app.get('/api/tasks-base', isAuthenticated, (req, res) => {
    const tasks = readJSON('tasks_base.json');
    res.json(tasks);
});

app.post('/api/tasks-base', isAuthenticated, (req, res) => {
    writeJSON('tasks_base.json', req.body);
    res.json({ success: true });
});

app.get('/api/sessions', isAuthenticated, (req, res) => {
    const sessions = readJSON('sessions.json');
    res.json(sessions);
});

app.post('/api/sessions', isAuthenticated, (req, res) => {
    writeJSON('sessions.json', req.body);
    res.json({ success: true });
});

// ========== Публичные API (для учеников) ==========
app.post('/api/start-session', (req, res) => {
    const { testId, studentRegNumber, studentName } = req.body;
    const tests = readJSON('tests.json');
    const test = tests.find(t => t.id === testId);
    if (!test) return res.status(404).json({ error: 'Тест не найден' });
    const student = (test.students || []).find(s => s.registrationNumber === studentRegNumber);
    if (!student) return res.status(403).json({ error: 'Код участника не найден' });
    const questions = test.questions || [];
    const shuffledIds = [...questions].sort(() => Math.random() - 0.5).map(q => q.id);
    const endTime = Date.now() + (test.timeLimitMinutes || 60) * 60 * 1000;
    const sessionId = uuidv4();
    const sessions = readJSON('sessions.json');
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
    writeJSON('sessions.json', sessions);
    res.json({ sessionId, endTimestamp: endTime, questionsOrder: shuffledIds });
});

app.get('/api/session/:sessionId', (req, res) => {
    const sessions = readJSON('sessions.json');
    const session = sessions.find(s => s.id === req.params.sessionId);
    if (!session) return res.status(404).json({ error: 'Сессия не найдена' });
    res.json(session);
});

app.post('/api/session/:sessionId', (req, res) => {
    const { answers, currentIndex } = req.body;
    const sessions = readJSON('sessions.json');
    const index = sessions.findIndex(s => s.id === req.params.sessionId);
    if (index === -1) return res.status(404).json({ error: 'Сессия не найдена' });
    if (answers) sessions[index].answers = { ...sessions[index].answers, ...answers };
    if (currentIndex !== undefined) sessions[index].currentIndex = currentIndex;
    writeJSON('sessions.json', sessions);
    res.json({ success: true });
});

app.post('/api/finish-session/:sessionId', (req, res) => {
    const sessions = readJSON('sessions.json');
    const index = sessions.findIndex(s => s.id === req.params.sessionId);
    if (index === -1) return res.status(404).json({ error: 'Сессия не найдена' });
    const session = sessions[index];
    const tests = readJSON('tests.json');
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
        writeJSON('tests.json', tests);
    }
    sessions.splice(index, 1);
    writeJSON('sessions.json', sessions);
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
