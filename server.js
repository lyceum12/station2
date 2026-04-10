const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// Папки
const dataDir = path.join(__dirname, 'data');
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

// Файлы данных
const testsFile = path.join(dataDir, 'tests.json');
const usersFile = path.join(dataDir, 'users.json');
const tasksFile = path.join(dataDir, 'tasks_base.json');
const sessionsFile = path.join(dataDir, 'sessions.json');

// Инициализация файлов
function initFile(file, defaultData) {
    if (!fs.existsSync(file)) {
        fs.writeFileSync(file, JSON.stringify(defaultData, null, 2));
    }
}
initFile(testsFile, []);
initFile(usersFile, { groups: [], users: [] });
initFile(tasksFile, []);
initFile(sessionsFile, []);

// Вспомогательные функции
function readJSON(file) {
    const data = fs.readFileSync(file, 'utf8');
    return JSON.parse(data);
}
function writeJSON(file, data) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ========== API ==========

// Тесты
app.get('/api/tests', (req, res) => {
    const tests = readJSON(testsFile);
    res.json(tests);
});
app.post('/api/tests', (req, res) => {
    const tests = req.body;
    writeJSON(testsFile, tests);
    res.json({ success: true });
});

// Пользователи (ученики и группы)
app.get('/api/users-data', (req, res) => {
    const data = readJSON(usersFile);
    res.json(data);
});
app.post('/api/users-data', (req, res) => {
    const data = req.body;
    writeJSON(usersFile, data);
    res.json({ success: true });
});

// База заданий
app.get('/api/tasks-base', (req, res) => {
    const tasks = readJSON(tasksFile);
    res.json(tasks);
});
app.post('/api/tasks-base', (req, res) => {
    const tasks = req.body;
    writeJSON(tasksFile, tasks);
    res.json({ success: true });
});

// Сессии учеников
app.get('/api/sessions', (req, res) => {
    const sessions = readJSON(sessionsFile);
    res.json(sessions);
});
app.post('/api/sessions', (req, res) => {
    const sessions = req.body;
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

// Экспорт/импорт всех данных (для переноса)
app.get('/api/export-all', (req, res) => {
    const data = {
        tests: readJSON(testsFile),
        users: readJSON(usersFile),
        tasks: readJSON(tasksFile),
        sessions: readJSON(sessionsFile)
    };
    res.json(data);
});
app.post('/api/import-all', (req, res) => {
    const { tests, users, tasks, sessions } = req.body;
    if (tests) writeJSON(testsFile, tests);
    if (users) writeJSON(usersFile, users);
    if (tasks) writeJSON(tasksFile, tasks);
    if (sessions) writeJSON(sessionsFile, sessions);
    res.json({ success: true });
});

// Старт сервера
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Сервер запущен на http://localhost:${PORT}`);
});
