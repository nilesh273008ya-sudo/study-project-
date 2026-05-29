require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ========== MODELS ==========
const User = require('./models/User');
const Subject = require('./models/Subject');
const Chapter = require('./models/Chapter');
const Lecture = require('./models/Lecture');
const Dpp = require('./models/Dpp');
const DppResult = require('./models/DppResult');
const LiveSchedule = require('./models/LiveSchedule');
const Progress = require('./models/Progress');
const MotivationSchedule = require('./models/MotivationSchedule');
const StudyLog = require('./models/StudyLog');
const RevisionItem = require('./models/RevisionItem');
const TopicPerformance = require('./models/TopicPerformance');
const PlannerTask = require('./models/PlannerTask');

// ========== NEW ROUTES ==========
const courseRoutes = require('./routes/courses');
const streamRoutes = require('./routes/stream');
const downloadRoutes = require('./routes/download');

// ========== HELPERS ==========
function detectTopic(questionText) {
    const text = questionText.toLowerCase();
    if (text.includes('%') || text.includes('percent') || text.includes('percentage')) return 'Percentage';
    if (text.includes('profit') || text.includes('loss') || text.includes('cp') || text.includes('sp')) return 'Profit & Loss';
    if (text.includes('simplif') || text.includes('bodmas') || /[\+\-\*\/\(\)]/.test(text) && !text.includes('profit')) return 'Simplification';
    if (text.includes('ratio') || text.includes('proportion')) return 'Ratio & Proportion';
    if (text.includes('age')) return 'Problems on Ages';
    if (text.includes('mixture') || text.includes('alligation')) return 'Mixture & Alligation';
    if (text.includes('time') && text.includes('work')) return 'Time & Work';
    if (text.includes('speed') || text.includes('distance') || text.includes('train')) return 'Speed, Time & Distance';
    if (text.includes('interest')) return 'Simple & Compound Interest';
    if (text.includes('average')) return 'Average';
    if (text.includes('number series')) return 'Number Series';
    if (text.includes('equation') || text.includes('quadratic')) return 'Quadratic Equations';
    if (text.includes('inequality')) return 'Inequality';
    if (text.includes('syllogism')) return 'Syllogism';
    if (text.includes('arrangement') || text.includes('puzzle')) return 'Puzzles';
    if (text.includes('coding') || text.includes('decoding')) return 'Coding-Decoding';
    if (text.includes('direction')) return 'Direction & Distance';
    if (text.includes('blood relation')) return 'Blood Relations';
    if (text.includes('sequence') || text.includes('series')) return 'Alphanumeric Series';
    if (text.includes('reading comprehension') || text.includes('passage')) return 'Reading Comprehension';
    if (text.includes('cloze test')) return 'Cloze Test';
    if (text.includes('error spotting')) return 'Error Spotting';
    if (text.includes('banking') || text.includes('rbi') || text.includes('sebi')) return 'Banking Awareness';
    if (text.includes('current affairs') || text.includes('gk')) return 'Current Affairs';
    return 'General';
}

// ========== MIDDLEWARE ==========
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));

// Mount new API routes
app.use('/api/courses', courseRoutes);
app.use('/api/stream', streamRoutes);
app.use('/api/download', downloadRoutes);

// Disable caching for all API routes
app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    next();
});

// ========== AUTH MIDDLEWARE ==========
const authenticate = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ success: false, msg: "Please login" });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = { id: decoded.id, role: decoded.role, name: decoded.name };
        next();
    } catch (err) {
        res.status(401).json({ success: false, msg: "Session expired" });
    }
};

const redirectIfAuthenticated = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return next();
    try {
        jwt.verify(token, process.env.JWT_SECRET);
        return res.redirect('/dashboard.html');
    } catch (err) {
        res.clearCookie('token');
        next();
    }
};

const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ success: false, msg: "Admin access required" });
    next();
};

// ========== PUBLIC ROUTES ==========
const setNoCache = (res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
};

app.get('/', redirectIfAuthenticated, (req, res) => {
    setNoCache(res);
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login.html', redirectIfAuthenticated, (req, res) => {
    setNoCache(res);
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup.html', redirectIfAuthenticated, (req, res) => {
    setNoCache(res);
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/forgot-password.html', redirectIfAuthenticated, (req, res) => {
    setNoCache(res);
    res.sendFile(path.join(__dirname, 'public', 'forgot-password.html'));
});

// ========== AUTH ROUTES (Resend – no OTP) ==========
app.post('/api/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) return res.status(400).json({ success: false, msg: 'Missing fields' });
        const existing = await User.findOne({ email });
        if (existing) return res.status(400).json({ success: false, msg: 'Email already registered' });

        const user = await User.create({ name, email, password });

        const token = crypto.randomBytes(32).toString('hex');
        user.verificationToken = token;
        user.verificationTokenExpires = new Date(Date.now() + 3600000);
        await user.save();

        const { sendVerificationEmail } = require('./utils/emailService');
        await sendVerificationEmail(user.email, token, name);

        res.status(201).json({ success: true, msg: 'Account created. Check your email to verify.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

app.get('/api/verify-email', async (req, res) => {
    const { token } = req.query;
    const user = await User.findOne({
        verificationToken: token,
        verificationTokenExpires: { $gt: new Date() }
    });
    if (!user) return res.status(400).send('Invalid or expired verification link.');
    user.verified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpires = undefined;
    await user.save();
    res.redirect('/login.html?verified=true');
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ success: false, msg: 'Invalid credentials' });
        const valid = await user.comparePassword(password);
        if (!valid) return res.status(400).json({ success: false, msg: 'Invalid credentials' });
        const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 7 * 24 * 60 * 60 * 1000 });
        res.json({ success: true, msg: 'Logged in', user: { id: user._id, name: user.name, email: user.email, role: user.role } });
    } catch (error) {
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ success: true, msg: 'Logged out' });
});

// ========== FORGOT / RESET PASSWORD (Resend) ==========
app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ success: false, msg: 'No account with that email' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000;
    await user.save();

    const resetLink = `${process.env.BASE_URL || 'http://localhost:3000'}/reset-password.html?token=${token}`;
    const { sendResetEmail } = require('./utils/emailService');
    try {
        await sendResetEmail(email, resetLink);
        res.json({ success: true, msg: 'Reset link sent to your email' });
    } catch (error) {
        console.error('Email sending error:', error);
        res.status(500).json({ success: false, msg: 'Failed to send email' });
    }
});

app.post('/api/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    const user = await User.findOne({ resetPasswordToken: token, resetPasswordExpires: { $gt: Date.now() } });
    if (!user) return res.status(400).json({ success: false, msg: 'Invalid or expired token' });
    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();
    res.json({ success: true, msg: 'Password reset successful' });
});

// ========== PROTECTED ROUTES ==========
app.get('/api/me', authenticate, async (req, res) => {
    const user = await User.findById(req.user.id).select('-password');
    res.json({ success: true, user });
});

// ---------- SUBJECTS (filter by course) ----------
app.get('/api/subjects', authenticate, async (req, res) => {
    const filter = {};
    if (req.query.courseId) filter.courseId = req.query.courseId;
    const subjects = await Subject.find(filter).sort('order');
    res.json(subjects);
});

app.post('/api/subjects', authenticate, isAdmin, async (req, res) => {
    const { name, icon, color, courseId } = req.body;
    if (!name) return res.status(400).json({ success: false, msg: 'Name required' });
    const subject = await Subject.create({ name, icon, color, courseId });
    res.json({ success: true, subject });
});

app.delete('/api/subjects/:id', authenticate, isAdmin, async (req, res) => {
    await Subject.findByIdAndDelete(req.params.id);
    await Chapter.deleteMany({ subjectId: req.params.id });
    const lectures = await Lecture.find({ subjectId: req.params.id });
    for (let lec of lectures) {
        await Progress.deleteMany({ lecture: lec._id });
        await Dpp.deleteOne({ lectureId: lec._id.toString() });
        await DppResult.deleteMany({ lectureId: lec._id.toString() });
        await Lecture.findByIdAndDelete(lec._id);
    }
    res.json({ success: true });
});

// ---------- CHAPTERS ----------
app.get('/api/chapters', authenticate, async (req, res) => {
    const { subjectId } = req.query;
    if (!subjectId) return res.status(400).json([]);
    const chapters = await Chapter.find({ subjectId }).sort('order');
    res.json(chapters);
});

app.post('/api/chapters', authenticate, isAdmin, async (req, res) => {
    const { subjectId, title, order } = req.body;
    if (!subjectId || !title) return res.status(400).json({ success: false, msg: 'Missing fields' });
    const chapter = await Chapter.create({ subjectId, title, order: order || Date.now() });
    res.json({ success: true, chapter });
});

app.delete('/api/chapters/:id', authenticate, isAdmin, async (req, res) => {
    const chapter = await Chapter.findById(req.params.id);
    if (!chapter) return res.status(404).json({ success: false });
    await Lecture.deleteMany({ chapterId: chapter._id });
    await Chapter.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});

// ---------- LECTURES (with downloadMode) ----------
app.get('/api/lectures', authenticate, async (req, res) => {
    const { subjectId, chapterId } = req.query;
    let query = {};
    if (subjectId) query.subjectId = subjectId;
    if (chapterId) query.chapterId = chapterId;
    const lectures = await Lecture.find(query).sort('createdAt');

    const lectureIds = lectures.map(l => l._id.toString());
    const dpps = await Dpp.find({ lectureId: { $in: lectureIds } }, 'lectureId');
    const dppSet = new Set(dpps.map(d => d.lectureId));

    const progress = await Progress.find({ user: req.user.id, lecture: { $in: lectures.map(l => l._id) } });
    const completedIds = new Set(progress.map(p => p.lecture.toString()));
    const enriched = lectures.map(l => ({
        ...l.toObject(),
        completed: completedIds.has(l._id.toString()),
        hasDpp: dppSet.has(l._id.toString())
    }));
    res.json(enriched);
});

app.get('/api/lectures/:id', authenticate, async (req, res) => {
    const lecture = await Lecture.findById(req.params.id);
    if (!lecture) return res.status(404).json({ success: false });
    res.json(lecture);
});

app.post('/api/lectures', authenticate, isAdmin, async (req, res) => {
    const { subjectId, chapterId, title, date, duration, youtubeId, imageUrl, pdfLink, dppLink, downloadMode } = req.body;
    if (!subjectId || !chapterId || !title) return res.status(400).json({ success: false, msg: 'Missing required fields' });
    const lecture = await Lecture.create({
        subjectId, chapterId, title, date, duration, youtubeId, imageUrl,
        pdfLink, dppLink,
        printableNotesLink: req.body.printableNotesLink || '',
        remark: req.body.remark || '',
        downloadMode: downloadMode || 'none'
    });
    res.json({ success: true, lecture });
});

app.put('/api/lectures/:id', authenticate, isAdmin, async (req, res) => {
    const { title, youtubeId, imageUrl, pdfLink, dppLink, printableNotesLink, remark, downloadMode } = req.body;
    const updates = {};
    if (title !== undefined) updates.title = title;
    if (youtubeId !== undefined) updates.youtubeId = youtubeId;
    if (imageUrl !== undefined) updates.imageUrl = imageUrl;
    if (pdfLink !== undefined) updates.pdfLink = pdfLink;
    if (dppLink !== undefined) updates.dppLink = dppLink;
    if (printableNotesLink !== undefined) updates.printableNotesLink = printableNotesLink;
    if (remark !== undefined) updates.remark = remark;
    if (downloadMode !== undefined) updates.downloadMode = downloadMode;

    const lecture = await Lecture.findByIdAndUpdate(req.params.id, updates, { new: true });
    res.json({ success: true, lecture });
});

app.delete('/api/lectures/:id', authenticate, isAdmin, async (req, res) => {
    await Lecture.findByIdAndDelete(req.params.id);
    await Progress.deleteMany({ lecture: req.params.id });
    await Dpp.deleteOne({ lectureId: req.params.id });
    await DppResult.deleteMany({ lectureId: req.params.id });
    res.json({ success: true });
});

// Mark lecture complete
app.post('/api/lectures/:id/complete', authenticate, async (req, res) => {
    const lecture = await Lecture.findById(req.params.id);
    if (!lecture) return res.status(404).json({ success: false, msg: 'Lecture not found' });
    await Progress.findOneAndUpdate(
        { user: req.user.id, lecture: req.params.id },
        { completed: true, completedAt: new Date() },
        { upsert: true }
    );
    res.json({ success: true });
});

// Bulk create chapters and lectures from JSON
app.post('/api/lectures/bulk', authenticate, isAdmin, async (req, res) => {
    try {
        const { subjectId, chapters } = req.body;
        if (!subjectId || !Array.isArray(chapters) || chapters.length === 0) {
            return res.status(400).json({ error: 'subjectId and chapters array are required' });
        }

        let createdCount = 0;

        for (const ch of chapters) {
            if (!ch.title || !Array.isArray(ch.lectures)) continue;

            let chapter = await Chapter.findOne({ subjectId, title: ch.title });
            if (!chapter) {
                chapter = await Chapter.create({ subjectId, title: ch.title, order: Date.now() });
            }

            for (const lec of ch.lectures) {
                if (!lec.title) continue;
                await Lecture.create({
                    subjectId,
                    chapterId: chapter._id.toString(),
                    title: lec.title,
                    youtubeId: lec.youtubeId || '',
                    date: lec.date || '',
                    duration: lec.duration || '45m',
                    imageUrl: lec.imageUrl || '',
                    pdfLink: lec.pdfLink || '',
                    dppLink: lec.dppLink || ''
                });
                createdCount++;
            }
        }

        res.json({ success: true, createdLectures: createdCount });
    } catch (error) {
        console.error('Bulk upload error:', error);
        res.status(500).json({ error: 'Server error while adding lectures' });
    }
});

// Add/update study log for a date
app.post('/api/study-log', authenticate, async (req, res) => {
    const { date, activities, totalMinutes } = req.body;
    if (!date) return res.status(400).json({ error: 'Date required' });
    const log = await StudyLog.findOneAndUpdate(
        { userId: req.user.id, date: new Date(date) },
        { activities, totalMinutes, $setOnInsert: { userId: req.user.id, date: new Date(date) } },
        { upsert: true, new: true }
    );
    res.json(log);
});

app.get('/api/study-log', authenticate, async (req, res) => {
    const { start, end } = req.query;
    const endDate = end ? new Date(end) : new Date();
    const startDate = start ? new Date(start) : new Date(endDate.getTime() - 7 * 24 * 60 * 60 * 1000);
    const logs = await StudyLog.find({
        userId: req.user.id,
        date: { $gte: startDate, $lte: endDate }
    }).sort({ date: 1 });
    res.json(logs);
});

// ---------- PLANNER TASKS ----------
app.get('/api/planner/tasks', authenticate, async (req, res) => {
    try {
        const { startDate, endDate, completed } = req.query;
        let query = { userId: req.user.id };

        if (startDate || endDate) {
            query.dueDate = {};
            if (startDate) query.dueDate.$gte = new Date(startDate);
            if (endDate) query.dueDate.$lte = new Date(endDate);
        }
        if (completed !== undefined) {
            query.completed = completed === 'true';
        }

        const tasks = await PlannerTask.find(query).sort({ dueDate: 1, order: 1, createdAt: 1 });
        res.json(tasks);
    } catch (err) {
        console.error('Get planner tasks error:', err);
        res.status(500).json({ error: 'Failed to fetch tasks' });
    }
});

app.post('/api/planner/tasks', authenticate, async (req, res) => {
    try {
        const { title, description, subject, dueDate, priority, order } = req.body;
        if (!title || !dueDate) {
            return res.status(400).json({ error: 'Title and due date are required' });
        }
        const task = await PlannerTask.create({
            userId: req.user.id,
            title,
            description: description || '',
            subject: subject || 'other',
            dueDate: new Date(dueDate),
            priority: priority || 'medium',
            order: order || 0,
            completed: false,
            completedAt: null
        });
        res.status(201).json(task);
    } catch (err) {
        console.error('Create planner task error:', err);
        res.status(500).json({ error: 'Failed to create task' });
    }
});

app.put('/api/planner/tasks/:id', authenticate, async (req, res) => {
    try {
        const taskId = req.params.id;
        const updates = req.body;
        const task = await PlannerTask.findOne({ _id: taskId, userId: req.user.id });
        if (!task) {
            return res.status(404).json({ error: 'Task not found' });
        }

        const allowed = ['title', 'description', 'subject', 'dueDate', 'priority', 'completed', 'order'];
        for (let field of allowed) {
            if (updates[field] !== undefined) {
                if (field === 'dueDate') task[field] = new Date(updates[field]);
                else task[field] = updates[field];
            }
        }
        if (updates.completed === true && !task.completed) {
            task.completedAt = new Date();
        } else if (updates.completed === false) {
            task.completedAt = null;
        }

        await task.save();
        res.json(task);
    } catch (err) {
        console.error('Update planner task error:', err);
        res.status(500).json({ error: 'Failed to update task' });
    }
});

app.delete('/api/planner/tasks/:id', authenticate, async (req, res) => {
    try {
        const taskId = req.params.id;
        const result = await PlannerTask.findOneAndDelete({ _id: taskId, userId: req.user.id });
        if (!result) {
            return res.status(404).json({ error: 'Task not found' });
        }
        res.json({ success: true, message: 'Task deleted' });
    } catch (err) {
        console.error('Delete planner task error:', err);
        res.status(500).json({ error: 'Failed to delete task' });
    }
});

app.get('/api/planner/summary', authenticate, async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const endOfWeek = new Date(today);
        endOfWeek.setDate(today.getDate() + 7);

        const tasks = await PlannerTask.find({
            userId: req.user.id,
            dueDate: { $gte: today, $lt: endOfWeek }
        });

        const total = tasks.length;
        const completed = tasks.filter(t => t.completed).length;
        const pending = total - completed;

        res.json({ total, completed, pending, tasks });
    } catch (err) {
        res.status(500).json({ error: 'Failed to get summary' });
    }
});

// ---------- REVISIONS ----------
app.get('/api/revisions/due', authenticate, async (req, res) => {
    const today = new Date();
    today.setHours(0,0,0,0);
    const due = await RevisionItem.find({
        userId: req.user.id,
        nextReviewDate: { $lte: today }
    }).limit(20);
    res.json(due);
});

app.post('/api/revisions/review', authenticate, async (req, res) => {
    const { revisionId, quality } = req.body;
    const item = await RevisionItem.findOne({ _id: revisionId, userId: req.user.id });
    if (!item) return res.status(404).json({ error: 'Not found' });

    let { easeFactor, interval, repetitions } = item;
    if (quality >= 3) {
        if (repetitions === 0) interval = 1;
        else if (repetitions === 1) interval = 6;
        else interval = Math.round(interval * easeFactor);
        repetitions++;
    } else {
        repetitions = 0;
        interval = 1;
    }
    easeFactor = easeFactor + (0.1 - (5 - quality) * 0.08);
    if (easeFactor < 1.3) easeFactor = 1.3;

    const nextReviewDate = new Date();
    nextReviewDate.setDate(nextReviewDate.getDate() + interval);

    item.easeFactor = easeFactor;
    item.interval = interval;
    item.repetitions = repetitions;
    item.nextReviewDate = nextReviewDate;
    await item.save();

    res.json({ success: true, nextReviewDate });
});

// ---------- LIVE SCHEDULES ----------
app.get('/api/live/today', authenticate, async (req, res) => {
    const today = new Date().toISOString().split('T')[0];
    const schedules = await LiveSchedule.find({ date: today }).sort('time');
    res.json(schedules);
});

app.get('/api/live', authenticate, isAdmin, async (req, res) => {
    const { from, to } = req.query;
    let query = {};
    if (from) query.date = { $gte: from };
    if (to) query.date = { ...query.date, $lte: to };
    const schedules = await LiveSchedule.find(query).sort('date time');
    res.json(schedules);
});

app.post('/api/live', authenticate, isAdmin, async (req, res) => {
    const { title, category, date, time, duration, youtubeId } = req.body;
    if (!title || !category || !date || !time) return res.status(400).json({ success: false, msg: 'Missing fields' });
    const schedule = await LiveSchedule.create({ title, category, date, time, duration, youtubeId });
    res.json({ success: true, schedule });
});

app.delete('/api/live/:id', authenticate, isAdmin, async (req, res) => {
    await LiveSchedule.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});

app.put('/api/live/:id', authenticate, isAdmin, async (req, res) => {
    const { title, category, date, time, duration, youtubeId } = req.body;
    try {
        const schedule = await LiveSchedule.findByIdAndUpdate(
            req.params.id,
            { title, category, date, time, duration, youtubeId },
            { new: true, runValidators: true }
        );
        if (!schedule) return res.status(404).json({ success: false, msg: 'Schedule not found' });
        res.json({ success: true, schedule });
    } catch (error) {
        res.status(500).json({ success: false, msg: error.message });
    }
});

// ---------- DPP ROUTES ----------
app.get('/api/dpp/lectures', authenticate, async (req, res) => {
    const dpps = await Dpp.find({}, 'lectureId lectureName subject');
    res.json(dpps);
});

app.get('/api/dpp/:lectureId', authenticate, async (req, res) => {
    const dpp = await Dpp.findOne({ lectureId: req.params.lectureId });
    if (!dpp) return res.status(404).json({ error: 'DPP not found' });
    res.json(dpp);
});

app.post('/api/dpp/upload', authenticate, isAdmin, async (req, res) => {
    try {
        const dppData = req.body;
        if (!dppData.lectureId || !dppData.questions || !Array.isArray(dppData.questions)) {
            return res.status(400).json({ error: 'lectureId and questions array required' });
        }
        const normalized = dppData.questions.map((q, i) => ({
            id: q.id || `q${i+1}`,
            type: q.type || 'multiple-choice',
            questionText: q.text || q.questionText,
            options: q.options || [],
            correctAnswer: q.ans !== undefined ? q.ans : q.correctAnswer,
            explanation: q.explanation || '',
            difficulty: q.diff || q.difficulty || 'MEDIUM',
            date: q.date || ''
        }));
        normalized.forEach(q => {
            if (!q.topic) q.topic = detectTopic(q.questionText);
        });
        dppData.questions = normalized;
        const dpp = await Dpp.findOneAndUpdate(
            { lectureId: dppData.lectureId },
            dppData,
            { upsert: true, new: true, runValidators: true }
        );
        res.json({ success: true, dpp });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.put('/api/dpp/:lectureId', authenticate, isAdmin, async (req, res) => {
    try {
        const { lectureId } = req.params;
        const { questions } = req.body;

        if (!questions || !Array.isArray(questions)) {
            return res.status(400).json({ error: 'questions array required' });
        }

        const normalizedQuestions = questions.map((q, i) => ({
            id: q.id || `q${i+1}`,
            type: q.type || 'multiple-choice',
            questionText: q.questionText || q.text || '',
            options: q.options || [],
            correctAnswer: q.correctAnswer !== undefined ? q.correctAnswer : q.ans,
            explanation: q.explanation || '',
            difficulty: q.difficulty || q.diff || 'MEDIUM',
            date: q.date || '',
            topic: detectTopic(q.questionText || q.text || '')
        }));

        const dpp = await Dpp.findOne({ lectureId });
        if (!dpp) {
            return res.status(404).json({ error: 'DPP not found' });
        }

        dpp.questions = normalizedQuestions;
        await dpp.save();

        res.json({ success: true, dpp });
    } catch (error) {
        console.error('PUT /api/dpp/:lectureId error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/dpp/submit', authenticate, async (req, res) => {
    try {
        const { lectureId, lectureName, answers } = req.body;

        if (!lectureId || !lectureName || !answers) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const dpp = await Dpp.findOne({ lectureId });
        if (!dpp) return res.status(404).json({ error: 'DPP not found' });

        let correctCount = 0;
        const processed = answers.map(ans => {
            const q = dpp.questions.find(q => q.id === ans.questionId);
            const isCorrect = q && ans.selectedOption === q.correctAnswer;
            if (isCorrect) correctCount++;
            return { ...ans, isCorrect };
        });

        const score = (correctCount / dpp.questions.length) * 100;

        const result = await DppResult.create({
            userId: req.user.id,
            lectureId,
            lectureName,
            totalQuestions: dpp.questions.length,
            correctAnswers: correctCount,
            score,
            answers: processed,
            submittedAt: new Date()
        });

        for (let i = 0; i < dpp.questions.length; i++) {
            const q = dpp.questions[i];
            const ans = answers.find(a => a.questionId === q.id);
            const isCorrect = ans && ans.selectedOption === q.correctAnswer;
            const topic = q.topic || detectTopic(q.questionText);

            if (topic) {
                await TopicPerformance.findOneAndUpdate(
                    { userId: req.user.id, topic: topic, subtopic: '' },
                    { $inc: { totalQuestions: 1, correct: isCorrect ? 1 : 0 }, $set: { lastUpdated: new Date() } },
                    { upsert: true }
                );
            }

            if (!ans || ans.selectedOption !== q.correctAnswer) {
                const existing = await RevisionItem.findOne({ userId: req.user.id, questionId: q.id, lectureId: lectureId });
                if (!existing) {
                    await RevisionItem.create({
                        userId: req.user.id,
                        questionId: q.id,
                        lectureId: lectureId,
                        lectureName: lectureName,
                        questionText: q.questionText,
                        options: q.options,
                        correctAnswer: q.correctAnswer,
                        nextReviewDate: new Date(Date.now() + 24 * 60 * 60 * 1000),
                        easeFactor: 2.5,
                        interval: 1,
                        repetitions: 0
                    });
                }
            }
        }

        res.json({ success: true, result: { id: result._id, score, correctCount, totalQuestions: dpp.questions.length } });
    } catch (error) {
        console.error('DPP Submit Error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/dpp/:lectureId', authenticate, isAdmin, async (req, res) => {
    try {
        const { lectureId } = req.params;
        const dpp = await Dpp.findOneAndDelete({ lectureId });
        if (!dpp) {
            return res.status(404).json({ error: 'DPP not found' });
        }
        await DppResult.deleteMany({ lectureId });
        res.json({ success: true, message: 'DPP and associated results deleted' });
    } catch (error) {
        console.error('DELETE /api/dpp/:lectureId error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/dpp/analytics/:lectureId', authenticate, async (req, res) => {
    const results = await DppResult.find({ userId: req.user.id, lectureId: req.params.lectureId }).sort('submittedAt');
    res.json({ attempts: results });
});

// ---------- ANALYTICS ----------
app.get('/api/analytics/topics', authenticate, async (req, res) => {
    try {
        let performances = await TopicPerformance.find({ userId: req.user.id });
        if (!performances) performances = [];
        performances.sort((a, b) => (a.accuracy || 0) - (b.accuracy || 0));
        res.json(performances);
    } catch (error) {
        console.error('Analytics error:', error);
        res.status(500).json([]);
    }
});

app.get('/api/analytics/weak-topics', authenticate, async (req, res) => {
    const threshold = parseInt(req.query.threshold) || 50;
    let all = await TopicPerformance.find({ userId: req.user.id, totalQuestions: { $gt: 5 } });
    const weak = all.filter(p => p.accuracy < threshold);
    res.json(weak);
});

app.get('/api/practice/custom', authenticate, async (req, res) => {
    let topics = req.query.topics;
    if (!topics) return res.status(400).json({ error: 'topics required' });
    const topicArray = topics.split(',').map(t => t.trim());
    const limit = parseInt(req.query.limit) || 10;

    const dpps = await Dpp.find({});
    let questions = [];

    for (const dpp of dpps) {
        for (const q of dpp.questions) {
            const questionTopic = q.topic || detectTopic(q.questionText);
            if (topicArray.includes(questionTopic)) {
                questions.push({
                    id: q.id,
                    text: q.questionText,
                    options: q.options,
                    correctAnswer: q.correctAnswer,
                    topic: questionTopic,
                    lectureId: dpp.lectureId,
                    lectureName: dpp.lectureName,
                    explanation: q.explanation || ''
                });
            }
        }
    }

    for (let i = questions.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [questions[i], questions[j]] = [questions[j], questions[i]];
    }
    questions = questions.slice(0, limit);

    res.json(questions);
});

// ---------- MOTIVATION SCHEDULE ----------
app.get('/api/motivation/current', authenticate, async (req, res) => {
    try {
        const schedule = await MotivationSchedule.findOne({ isActive: true });
        if (!schedule) return res.json({ success: false, msg: 'No active schedule' });

        const start = new Date(schedule.startDate);
        const now = new Date();
        const diffTime = now - start;
        const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));

        if (diffDays < 0) {
            return res.json({ success: false, msg: 'Plan has not started yet' });
        }

        const weekNumber = Math.floor(diffDays / 7) + 1;
        const dayNumber = (diffDays % 7) + 1;

        const weekData = schedule.weeks.find(w => w.weekNumber === weekNumber);
        if (!weekData) {
            return res.json({ success: false, msg: `Week ${weekNumber} not configured` });
        }

        const dayData = weekData.days.find(d => d.dayNumber === dayNumber);
        if (!dayData) {
            return res.json({ success: false, msg: `Day ${dayNumber} not configured` });
        }

        res.json({
            success: true,
            weekNumber,
            dayNumber,
            message: dayData.message,
            startDate: schedule.startDate
        });
    } catch (error) {
        console.error('Motivation error:', error);
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

app.get('/api/motivation', authenticate, isAdmin, async (req, res) => {
    const schedules = await MotivationSchedule.find().sort('-createdAt');
    res.json(schedules);
});

app.post('/api/motivation', authenticate, isAdmin, async (req, res) => {
    try {
        const { startDate, weeks, isActive } = req.body;
        if (!startDate || !weeks || !Array.isArray(weeks)) {
            return res.status(400).json({ success: false, msg: 'Missing required fields' });
        }

        if (isActive) {
            await MotivationSchedule.updateMany({}, { isActive: false });
        }

        const schedule = await MotivationSchedule.create({ startDate, weeks, isActive });
        res.json({ success: true, schedule });
    } catch (error) {
        console.error('Create motivation error:', error);
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

app.put('/api/motivation/:id', authenticate, isAdmin, async (req, res) => {
    try {
        const updates = req.body;
        if (updates.isActive) {
            await MotivationSchedule.updateMany({ _id: { $ne: req.params.id } }, { isActive: false });
        }
        const schedule = await MotivationSchedule.findByIdAndUpdate(req.params.id, updates, { new: true });
        res.json({ success: true, schedule });
    } catch (error) {
        console.error('Update motivation error:', error);
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

app.delete('/api/motivation/:id', authenticate, isAdmin, async (req, res) => {
    try {
        await MotivationSchedule.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (error) {
        console.error('Delete motivation error:', error);
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

// ========== SEEDING ==========
async function seedAdmin() {
    const existing = await User.findOne({ role: 'admin' });
    if (!existing && process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
        await User.create({ name: 'Admin', email: process.env.ADMIN_EMAIL, password: process.env.ADMIN_PASSWORD, role: 'admin' });
        console.log('✅ Admin seeded');
    }
}
async function seedSubjects() {
    const count = await Subject.countDocuments();
    if (count === 0) {
        await Subject.insertMany([
            { name: 'Quantitative Aptitude', icon: '📊', color: 'blue', order: 1 },
            { name: 'Reasoning Ability', icon: '🧠', color: 'purple', order: 2 },
            { name: 'English Language', icon: '📖', color: 'green', order: 3 },
            { name: 'Banking Awareness', icon: '🏦', color: 'orange', order: 4 },
            { name: 'Current Affairs', icon: '🌍', color: 'red', order: 5 }
        ]);
        console.log('✅ Default subjects seeded');
    }
}

// ========== STATIC FILES ==========
app.use(express.static('public'));

// ========== START SERVER ==========
const startServer = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log('✅ MongoDB connected');
        await seedAdmin();
        await seedSubjects();
        app.listen(PORT, '0.0.0.0', () => {
            console.log(`🚀 Server running on port ${PORT}`);
        });
    } catch (err) {
        console.error('❌ Failed to start server:', err);
        process.exit(1);
    }
};
startServer();
