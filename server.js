const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: 'test_constructor_secret_key_change_me',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 } // 24 часа
}));

// Создание папок
const dataDir = path.join(__dirname, 'data');
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

// Настройка multer для загрузки файлов
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => {
        const unique = uuidv4() + path.extname(file.originalname);
        cb(null, unique);
    }
});
const upload = multer({ storage });

// Вспомогательные функции для работы с JSON файлами
function readJSON(file) {
    const filePath = path.join(dataDir, file);
    if (!fs.existsSync(filePath)) return [];
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}
function writeJSON(file, data) {
    fs.writeFileSync(path.join(dataDir, file), JSON.stringify(data, null, 2));
}

// Инициализация данных по умолчанию
function initData() {
    // Админы
    let admins = readJSON('admins.json');
    if (!admins.length) {
        const hashedPassword = bcrypt.hashSync('admin', 10);
        admins.push({ id: 'super1', login: 'admin', password: hashedPassword, role: 'superadmin' });
        writeJSON('admins.json', admins);
    }
    // Остальные файлы
    if (!fs.existsSync(path.join(dataDir, 'tests.json'))) writeJSON('tests.json', []);
    if (!fs.existsSync(path.join(dataDir, 'users.json'))) writeJSON('users.json', { groups: [], users: [] });
    if (!fs.existsSync(path.join(dataDir, 'tasks_base.json'))) writeJSON('tasks_base.json', []);
    if (!fs.existsSync(path.join(dataDir, 'sessions.json'))) writeJSON('sessions.json', []);
    if (!fs.existsSync(path.join(dataDir, 'logs.json'))) writeJSON('logs.json', []);
}
initData();

// Функция логирования
function logAction(req, action, details = '') {
    const logs = readJSON('logs.json');
    logs.push({
        timestamp: new Date().toISOString(),
        ip: req.ip || req.connection.remoteAddress,
        user: req.session.user ? req.session.user.login : 'anonymous',
        action,
        details
    });
    writeJSON('logs.json', logs);
}

// Middleware проверки авторизации
function requireAuth(req, res, next) {
    if (!req.session.user) return res.status(401).json({ error: 'Не авторизован' });
    next();
}
function requireSuperAdmin(req, res, next) {
    if (!req.session.user || req.session.user.role !== 'superadmin') return res.status(403).json({ error: 'Доступ запрещён' });
    next();
}

// ==================== API ====================

// Авторизация
app.post('/api/login', (req, res) => {
    const { login, password } = req.body;
    const admins = readJSON('admins.json');
    const user = admins.find(a => a.login === login);
    if (!user || !bcrypt.compareSync(password, user.password)) {
        logAction(req, 'LOGIN_FAILED', `Логин: ${login}`);
        return res.status(401).json({ error: 'Неверный логин или пароль' });
    }
    req.session.user = { id: user.id, login: user.login, role: user.role };
    logAction(req, 'LOGIN_SUCCESS', `Логин: ${login}`);
    res.json({ success: true, role: user.role });
});

// Выход
app.post('/api/logout', (req, res) => {
    logAction(req, 'LOGOUT');
    req.session.destroy();
    res.json({ success: true });
});

// Смена пароля (для текущего пользователя)
app.post('/api/change-password', requireAuth, (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const admins = readJSON('admins.json');
    const user = admins.find(a => a.id === req.session.user.id);
    if (!bcrypt.compareSync(oldPassword, user.password)) {
        return res.status(401).json({ error: 'Неверный старый пароль' });
    }
    user.password = bcrypt.hashSync(newPassword, 10);
    writeJSON('admins.json', admins);
    logAction(req, 'PASSWORD_CHANGED');
    res.json({ success: true });
});

// Получение списка админов (только superadmin)
app.get('/api/admins', requireSuperAdmin, (req, res) => {
    const admins = readJSON('admins.json').map(a => ({ id: a.id, login: a.login, role: a.role }));
    res.json(admins);
});

// Добавление админа (только superadmin)
app.post('/api/admins', requireSuperAdmin, (req, res) => {
    const { login, password, role } = req.body;
    const admins = readJSON('admins.json');
    if (admins.find(a => a.login === login)) {
        return res.status(400).json({ error: 'Логин уже существует' });
    }
    const newId = 'admin_' + Date.now();
    admins.push({
        id: newId,
        login,
        password: bcrypt.hashSync(password, 10),
        role: role || 'admin'
    });
    writeJSON('admins.json', admins);
    logAction(req, 'ADMIN_CREATED', `Логин: ${login}, роль: ${role || 'admin'}`);
    res.json({ success: true });
});

// Удаление админа (только superadmin, нельзя удалить себя)
app.delete('/api/admins/:id', requireSuperAdmin, (req, res) => {
    const { id } = req.params;
    if (id === req.session.user.id) {
        return res.status(400).json({ error: 'Нельзя удалить самого себя' });
    }
    let admins = readJSON('admins.json');
    admins = admins.filter(a => a.id !== id);
    writeJSON('admins.json', admins);
    logAction(req, 'ADMIN_DELETED', `ID: ${id}`);
    res.json({ success: true });
});

// Получение логов (только superadmin)
app.get('/api/logs', requireSuperAdmin, (req, res) => {
    const logs = readJSON('logs.json');
    res.json(logs);
});

// === Остальные API для работы с тестами, пользователями и т.д. (без изменений) ===
// Тесты
app.get('/api/tests', requireAuth, (req, res) => {
    const tests = readJSON('tests.json');
    res.json(tests);
});
app.post('/api/tests', requireAuth, (req, res) => {
    const tests = req.body;
    writeJSON('tests.json', tests);
    logAction(req, 'TESTS_UPDATED');
    res.json({ success: true });
});
// Пользователи
app.get('/api/users', requireAuth, (req, res) => {
    const users = readJSON('users.json');
    res.json(users);
});
app.post('/api/users', requireAuth, (req, res) => {
    const users = req.body;
    writeJSON('users.json', users);
    logAction(req, 'USERS_UPDATED');
    res.json({ success: true });
});
// База заданий
app.get('/api/tasks-base', requireAuth, (req, res) => {
    const tasks = readJSON('tasks_base.json');
    res.json(tasks);
});
app.post('/api/tasks-base', requireAuth, (req, res) => {
    const tasks = req.body;
    writeJSON('tasks_base.json', tasks);
    logAction(req, 'TASKS_BASE_UPDATED');
    res.json({ success: true });
});
// Сессии
app.get('/api/sessions', requireAuth, (req, res) => {
    const sessions = readJSON('sessions.json');
    res.json(sessions);
});
app.post('/api/sessions', requireAuth, (req, res) => {
    const sessions = req.body;
    writeJSON('sessions.json', sessions);
    res.json({ success: true });
});
// Загрузка файлов (для учеников, доступ без авторизации, но с сессией ученика)
app.post('/api/upload-file', upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Файл не загружен' });
    res.json({ fileName: req.file.filename, originalName: req.file.originalname });
});
app.get('/api/uploads/:filename', (req, res) => {
    const filePath = path.join(uploadsDir, req.params.filename);
    if (fs.existsSync(filePath)) res.sendFile(filePath);
    else res.status(404).json({ error: 'Файл не найден' });
});

// Начало сессии ученика (публичный API)
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
    const session = {
        id: sessionId,
        testId,
        studentRegNumber,
        studentName,
        startTime: Date.now(),
        endTimestamp: endTime,
        questionsOrder: shuffledIds,
        currentIndex: 0,
        answers: {}
    };
    const sessions = readJSON('sessions.json');
    sessions.push(session);
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

// Запуск сервера
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Сервер запущен на http://localhost:${PORT}`);
    console.log(`Для доступа с других устройств используйте IP-адрес этого компьютера и порт ${PORT}`);
});
