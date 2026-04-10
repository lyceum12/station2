const express = require('express');
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

// Папки
const dataDir = path.join(__dirname, 'data');
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

// Вспомогательные функции для работы с JSON-файлами
function readJSON(file) {
    const filePath = path.join(dataDir, file);
    if (!fs.existsSync(filePath)) return [];
    const data = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(data);
}

function writeJSON(file, data) {
    const filePath = path.join(dataDir, file);
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

// ==================== API ====================

// Получить все тесты
app.get('/api/tests', (req, res) => {
    const tests = readJSON('tests.json');
    res.json(tests);
});

// Сохранить все тесты
app.post('/api/tests', (req, res) => {
    const tests = req.body;
    writeJSON('tests.json', tests);
    res.json({ success: true });
});

// Получить пользователей (ученики + группы)
app.get('/api/users', (req, res) => {
    const users = readJSON('users.json');
    res.json(users);
});

// Сохранить пользователей
app.post('/api/users', (req, res) => {
    const users = req.body;
    writeJSON('users.json', users);
    res.json({ success: true });
});

// Получить базу заданий
app.get('/api/tasks-base', (req, res) => {
    const tasks = readJSON('tasks_base.json');
    res.json(tasks);
});

// Сохранить базу заданий
app.post('/api/tasks-base', (req, res) => {
    const tasks = req.body;
    writeJSON('tasks_base.json', tasks);
    res.json({ success: true });
});

// ========== Сессии учеников ==========
// Получить все сессии
app.get('/api/sessions', (req, res) => {
    const sessions = readJSON('sessions.json');
    res.json(sessions);
});

// Сохранить сессии
app.post('/api/sessions', (req, res) => {
    const sessions = req.body;
    writeJSON('sessions.json', sessions);
    res.json({ success: true });
});

// Начать новую сессию
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
        studentName: student.fullName,
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

// Получить сессию по ID
app.get('/api/session/:sessionId', (req, res) => {
    const sessions = readJSON('sessions.json');
    const session = sessions.find(s => s.id === req.params.sessionId);
    if (!session) return res.status(404).json({ error: 'Сессия не найдена' });
    res.json(session);
});

// Обновить сессию (ответы, текущий вопрос)
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

// Завершить сессию и сохранить результат в тест
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

// ========== Загрузка файлов ==========
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
    if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
    } else {
        res.status(404).json({ error: 'Файл не найден' });
    }
});

// Запуск сервера
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Сервер запущен на http://localhost:${PORT}`);
    console.log(`Для доступа с других устройств используйте IP-адрес этого компьютера`);
});
