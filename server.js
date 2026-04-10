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

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));
app.use(session({
    secret: 'test_constructor_secret_2025',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 1000 * 60 * 60 * 24 }
}));

const dataDir = path.join(__dirname, 'data');
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

// Файлы: администраторы и остальные данные
const adminsFile = path.join(dataDir, 'admins.json');
const adminFile = path.join(dataDir, 'admin.json'); // устаревший, будет удалён, но для совместимости оставим

// Инициализация суперадминистратора (admin)
async function initSuperAdmin() {
    let admins = [];
    if (fs.existsSync(adminsFile)) {
        admins = JSON.parse(fs.readFileSync(adminsFile, 'utf8'));
    }
    const existing = admins.find(a => a.username === 'admin');
    if (!existing) {
        const hash = await bcrypt.hash('admin', 10);
        admins.push({ id: 'admin', username: 'admin', password_hash: hash, role: 'super_admin' });
        fs.writeFileSync(adminsFile, JSON.stringify(admins, null, 2));
        console.log('Создан суперадминистратор: admin / admin');
    }
    // Для совместимости со старым файлом admin.json (если есть)
    if (fs.existsSync(adminFile)) {
        fs.unlinkSync(adminFile);
    }
}
initSuperAdmin();

// Вспомогательные функции для работы с JSON-файлами данных (тесты, пользователи и т.д.)
function readJSON(file) {
    const filePath = path.join(dataDir, file);
    if (!fs.existsSync(filePath)) return [];
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}
function writeJSON(file, data) {
    fs.writeFileSync(path.join(dataDir, file), JSON.stringify(data, null, 2));
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
    if (!fs.existsSync(adminsFile)) return res.status(401).json({ error: 'Системная ошибка' });
    const admins = JSON.parse(fs.readFileSync(adminsFile, 'utf8'));
    const admin = admins.find(a => a.username === username);
    if (!admin) return res.status(401).json({ error: 'Неверный логин или пароль' });
    const match = await bcrypt.compare(password, admin.password_hash);
    if (!match) return res.status(401).json({ error: 'Неверный логин или пароль' });
    req.session.user = { id: admin.id, username: admin.username, role: admin.role };
    res.json({ success: true, role: admin.role });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.post('/api/change-password', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Не авторизован' });
    const { oldPassword, newPassword } = req.body;
    const admins = JSON.parse(fs.readFileSync(adminsFile, 'utf8'));
    const admin = admins.find(a => a.id === req.session.user.id);
    if (!admin) return res.status(401).json({ error: 'Пользователь не найден' });
    const match = await bcrypt.compare(oldPassword, admin.password_hash);
    if (!match) return res.status(401).json({ error: 'Неверный текущий пароль' });
    const newHash = await bcrypt.hash(newPassword, 10);
    admin.password_hash = newHash;
    fs.writeFileSync(adminsFile, JSON.stringify(admins, null, 2));
    res.json({ success: true });
});

// Middleware проверки авторизации
function isAuthenticated(req, res, next) {
    if (req.session.user) return next();
    res.status(401).json({ error: 'Не авторизован' });
}
function isSuperAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'super_admin') return next();
    res.status(403).json({ error: 'Доступ запрещён' });
}

// ========== API управления администраторами (только для super_admin) ==========
app.get('/api/admins', isAuthenticated, isSuperAdmin, (req, res) => {
    const admins = JSON.parse(fs.readFileSync(adminsFile, 'utf8'));
    // Отправляем без паролей
    const safe = admins.map(({ id, username, role }) => ({ id, username, role }));
    res.json(safe);
});

app.post('/api/admins', isAuthenticated, isSuperAdmin, async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Заполните логин и пароль' });
    const admins = JSON.parse(fs.readFileSync(adminsFile, 'utf8'));
    if (admins.find(a => a.username === username)) {
        return res.status(400).json({ error: 'Логин уже существует' });
    }
    const hash = await bcrypt.hash(password, 10);
    const newId = Date.now().toString() + '_' + Math.random().toString(36).substr(2, 6);
    const newAdmin = { id: newId, username, password_hash: hash, role: role || 'admin' };
    admins.push(newAdmin);
    fs.writeFileSync(adminsFile, JSON.stringify(admins, null, 2));
    res.json({ success: true });
});

app.delete('/api/admins/:id', isAuthenticated, isSuperAdmin, (req, res) => {
    const id = req.params.id;
    if (id === 'admin') return res.status(400).json({ error: 'Нельзя удалить главного администратора' });
    let admins = JSON.parse(fs.readFileSync(adminsFile, 'utf8'));
    const newAdmins = admins.filter(a => a.id !== id);
    if (newAdmins.length === admins.length) return res.status(404).json({ error: 'Администратор не найден' });
    fs.writeFileSync(adminsFile, JSON.stringify(newAdmins, null, 2));
    res.json({ success: true });
});

app.post('/api/admins/:id/change-password', isAuthenticated, isSuperAdmin, async (req, res) => {
    const { id } = req.params;
    const { newPassword } = req.body;
    if (!newPassword) return res.status(400).json({ error: 'Новый пароль не указан' });
    let admins = JSON.parse(fs.readFileSync(adminsFile, 'utf8'));
    const admin = admins.find(a => a.id === id);
    if (!admin) return res.status(404).json({ error: 'Администратор не найден' });
    const hash = await bcrypt.hash(newPassword, 10);
    admin.password_hash = hash;
    fs.writeFileSync(adminsFile, JSON.stringify(admins, null, 2));
    res.json({ success: true });
});

// ========== Остальные API (тесты, пользователи, задания, сессии) – без изменений ==========
app.get('/api/tests', isAuthenticated, (req, res) => res.json(readJSON('tests.json')));
app.post('/api/tests', isAuthenticated, (req, res) => { writeJSON('tests.json', req.body); res.json({ success: true }); });
app.get('/api/users', isAuthenticated, (req, res) => res.json(readJSON('users.json')));
app.post('/api/users', isAuthenticated, (req, res) => { writeJSON('users.json', req.body); res.json({ success: true }); });
app.get('/api/tasks-base', isAuthenticated, (req, res) => res.json(readJSON('tasks_base.json')));
app.post('/api/tasks-base', isAuthenticated, (req, res) => { writeJSON('tasks_base.json', req.body); res.json({ success: true }); });
app.get('/api/sessions', isAuthenticated, (req, res) => res.json(readJSON('sessions.json')));
app.post('/api/sessions', isAuthenticated, (req, res) => { writeJSON('sessions.json', req.body); res.json({ success: true }); });

// Экспорт/импорт данных
app.get('/api/export-data', isAuthenticated, (req, res) => {
    const allData = {
        tests: readJSON('tests.json'),
        users: readJSON('users.json'),
        tasks_base: readJSON('tasks_base.json'),
        sessions: readJSON('sessions.json')
    };
    res.setHeader('Content-Disposition', 'attachment; filename="test_constructor_backup.json"');
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(allData, null, 2));
});

app.post('/api/import-data', isAuthenticated, (req, res) => {
    const { tests, users, tasks_base, sessions } = req.body;
    if (tests !== undefined) writeJSON('tests.json', tests);
    if (users !== undefined) writeJSON('users.json', users);
    if (tasks_base !== undefined) writeJSON('tasks_base.json', tasks_base);
    if (sessions !== undefined) writeJSON('sessions.json', sessions);
    res.json({ success: true });
});

// Сессии учеников (без авторизации)
app.post('/api/start-session', (req, res) => {
    const { testId, studentRegNumber, studentName } = req.body;
    const tests = readJSON('tests.json');
    const test = tests.find(t => t.id === testId);
    if (!test) return res.status(404).json({ error: 'Тест не найден' });
    const student = (test.students || []).find(s => s.registrationNumber === studentRegNumber);
    if (!student) return res.status(403).json({ error: 'Код участника не найден' });
    const shuffledIds = [...(test.questions || [])].sort(() => Math.random() - 0.5).map(q => q.id);
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
    console.log(`Суперадминистратор: admin / admin`);
});
