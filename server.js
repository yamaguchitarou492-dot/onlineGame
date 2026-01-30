const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const validator = require('validator');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);

// Render用: プロキシを信頼
app.set('trust proxy', 1);

// ============== セキュリティ設定 ==============

const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');
const BCRYPT_ROUNDS = 12;
const isProduction = process.env.NODE_ENV === 'production';

// Helmet
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            connectSrc: ["'self'", "ws:", "wss:"],
        },
    },
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// セッション設定
const sessionMiddleware = session({
    secret: SESSION_SECRET,
    name: 'sessionId',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000,
        path: '/',
    },
    genid: () => uuidv4(),
});

app.use(sessionMiddleware);

// レート制限
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: 'ログイン試行回数が多すぎます。15分後に再試行してください。' },
    standardHeaders: true,
    legacyHeaders: false,
});

const generalLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 100,
    message: { error: 'リクエストが多すぎます。' },
});

app.use(generalLimiter);

// ============== データベース設定 ==============

const db = new Database('./game_users.db');

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        score INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_login TEXT,
        login_attempts INTEGER DEFAULT 0,
        locked_until TEXT
    )
`);

// プリペアドステートメント
const stmt = {
    findUserByUsername: db.prepare('SELECT * FROM users WHERE username = ?'),
    findUserByEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
    findUserById: db.prepare('SELECT id, username, email, score, created_at FROM users WHERE id = ?'),
    createUser: db.prepare('INSERT INTO users (id, username, email, password_hash) VALUES (?, ?, ?, ?)'),
    updateLastLogin: db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP, login_attempts = 0 WHERE id = ?'),
    updateScore: db.prepare('UPDATE users SET score = ? WHERE id = ?'),
    incrementLoginAttempts: db.prepare('UPDATE users SET login_attempts = login_attempts + 1 WHERE id = ?'),
    lockAccount: db.prepare('UPDATE users SET locked_until = ? WHERE id = ?'),
    getLeaderboard: db.prepare('SELECT username, score FROM users ORDER BY score DESC LIMIT 10'),
};

// ============== 入力バリデーション ==============

function validateUsername(username) {
    if (!username || typeof username !== 'string') return false;
    if (username.length < 3 || username.length > 20) return false;
    if (!/^[a-zA-Z0-9_]+$/.test(username)) return false;
    return true;
}

function validatePassword(password) {
    if (!password || typeof password !== 'string') return false;
    if (password.length < 8 || password.length > 128) return false;
    let strength = 0;
    if (/[a-z]/.test(password)) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^a-zA-Z0-9]/.test(password)) strength++;
    return strength >= 3;
}

function validateEmail(email) {
    if (!email || typeof email !== 'string') return false;
    return validator.isEmail(email);
}

// ============== CSRF トークン ==============

function generateCSRFToken(session) {
    if (!session.csrfToken) {
        session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    return session.csrfToken;
}

function verifyCSRFToken(req) {
    const token = req.headers['x-csrf-token'] || req.body._csrf;
    return token && token === req.session.csrfToken;
}

// ============== 認証ミドルウェア ==============

function requireAuth(req, res, next) {
    if (req.session && req.session.userId) {
        const user = stmt.findUserById.get(req.session.userId);
        if (user) {
            req.user = user;
            return next();
        }
    }
    res.status(401).json({ error: 'ログインが必要です' });
}

// ============== 静的ファイル ==============

app.use(express.static(path.join(__dirname, 'public')));

// ============== API エンドポイント ==============

app.get('/api/csrf-token', (req, res) => {
    res.json({ csrfToken: generateCSRFToken(req.session) });
});

// 新規登録
app.post('/api/register', authLimiter, async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        if (!validateUsername(username)) {
            return res.status(400).json({ 
                error: 'ユーザー名は3-20文字の英数字とアンダースコアのみ使用できます' 
            });
        }
        
        if (!validateEmail(email)) {
            return res.status(400).json({ error: '有効なメールアドレスを入力してください' });
        }
        
        if (!validatePassword(password)) {
            return res.status(400).json({ 
                error: 'パスワードは8文字以上で、大文字・小文字・数字・特殊文字のうち3種類以上を含めてください' 
            });
        }
        
        if (stmt.findUserByUsername.get(username)) {
            return res.status(400).json({ error: 'このユーザー名は既に使用されています' });
        }
        
        if (stmt.findUserByEmail.get(email)) {
            return res.status(400).json({ error: 'このメールアドレスは既に登録されています' });
        }
        
        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
        const userId = uuidv4();
        stmt.createUser.run(userId, username, email.toLowerCase(), passwordHash);
        
        req.session.userId = userId;
        req.session.username = username;
        
        req.session.save((err) => {
            if (err) {
                console.error('Session save error:', err);
                return res.status(500).json({ error: 'セッションエラー' });
            }
            res.json({ 
                success: true, 
                user: { id: userId, username, score: 0 }
            });
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'サーバーエラーが発生しました' });
    }
});

// ログイン
app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'ユーザー名とパスワードを入力してください' });
        }
        
        const user = stmt.findUserByUsername.get(username);
        
        if (!user) {
            await bcrypt.hash(password, BCRYPT_ROUNDS);
            return res.status(401).json({ error: 'ユーザー名またはパスワードが間違っています' });
        }
        
        if (user.locked_until && new Date(user.locked_until) > new Date()) {
            return res.status(423).json({ 
                error: 'アカウントがロックされています。30分後に再試行してください' 
            });
        }
        
        const isValid = await bcrypt.compare(password, user.password_hash);
        
        if (!isValid) {
            stmt.incrementLoginAttempts.run(user.id);
            
            if (user.login_attempts >= 4) {
                const lockTime = new Date(Date.now() + 30 * 60 * 1000).toISOString();
                stmt.lockAccount.run(lockTime, user.id);
                return res.status(423).json({ 
                    error: 'ログイン試行回数が多すぎます。アカウントを30分間ロックしました' 
                });
            }
            
            return res.status(401).json({ error: 'ユーザー名またはパスワードが間違っています' });
        }
        
        stmt.updateLastLogin.run(user.id);
        
        req.session.userId = user.id;
        req.session.username = user.username;
        
        req.session.save((err) => {
            if (err) {
                console.error('Session save error:', err);
                return res.status(500).json({ error: 'セッションエラー' });
            }
            res.json({ 
                success: true, 
                user: { id: user.id, username: user.username, score: user.score }
            });
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'サーバーエラーが発生しました' });
    }
});

// ログアウト
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        res.clearCookie('sessionId', {
            httpOnly: true,
            secure: isProduction,
            sameSite: 'strict',
            path: '/',
        });
        res.json({ success: true });
    });
});

// 現在のユーザー情報取得
app.get('/api/me', (req, res) => {
    if (req.session && req.session.userId) {
        const user = stmt.findUserById.get(req.session.userId);
        if (user) {
            return res.json({ 
                user: { id: user.id, username: user.username, score: user.score },
                csrfToken: generateCSRFToken(req.session)
            });
        }
    }
    res.json({ user: null, csrfToken: generateCSRFToken(req.session) });
});

// リーダーボード
app.get('/api/leaderboard', (req, res) => {
    const leaderboard = stmt.getLeaderboard.all();
    res.json({ leaderboard });
});

// ============== Socket.io ==============

const io = new Server(server, {
    cors: {
        origin: isProduction ? false : "*",
        credentials: true
    }
});

io.use((socket, next) => {
    sessionMiddleware(socket.request, {}, next);
});

const players = {};
const gameObjects = {};
const COLORS = ['#ff6b6b', '#ffd93d', '#6bcb77', '#4d96ff', '#c56cf0', '#ff9ff3'];

function initGameObjects() {
    for (let i = 0; i < 30; i++) {
        gameObjects[`cube_${i}`] = {
            id: `cube_${i}`,
            x: (Math.random() - 0.5) * 80,
            y: 1 + Math.random() * 3,
            z: (Math.random() - 0.5) * 80,
            color: COLORS[Math.floor(Math.random() * COLORS.length)],
            active: true
        };
    }
}
initGameObjects();

io.on('connection', (socket) => {
    const session = socket.request.session;
    
    if (!session || !session.userId) {
        socket.emit('authError', { error: 'ログインが必要です' });
        socket.disconnect(true);
        return;
    }
    
    const user = stmt.findUserById.get(session.userId);
    if (!user) {
        socket.emit('authError', { error: 'ユーザーが見つかりません' });
        socket.disconnect(true);
        return;
    }
    
    console.log(`プレイヤー接続: ${user.username} (${socket.id})`);
    
    players[socket.id] = {
        id: socket.id,
        odbc: user.id,
        username: user.username,
        x: (Math.random() - 0.5) * 20,
        y: 2,
        z: (Math.random() - 0.5) * 20,
        rotationY: 0,
        score: user.score,
        color: COLORS[Object.keys(players).length % COLORS.length]
    };
    
    socket.emit('init', {
        id: socket.id,
        players: players,
        gameObjects: gameObjects,
        user: { username: user.username, score: user.score }
    });
    
    socket.broadcast.emit('playerJoined', players[socket.id]);
    
    socket.on('move', (data) => {
        if (players[socket.id]) {
            players[socket.id].x = Number(data.x) || 0;
            players[socket.id].y = Number(data.y) || 0;
            players[socket.id].z = Number(data.z) || 0;
            players[socket.id].rotationY = Number(data.rotationY) || 0;
            
            const limit = 50;
            players[socket.id].x = Math.max(-limit, Math.min(limit, players[socket.id].x));
            players[socket.id].z = Math.max(-limit, Math.min(limit, players[socket.id].z));
            
            socket.broadcast.emit('playerMoved', players[socket.id]);
        }
    });
    
    socket.on('collectCube', (cubeId) => {
        if (!cubeId || typeof cubeId !== 'string') return;
        
        if (gameObjects[cubeId] && gameObjects[cubeId].active && players[socket.id]) {
            gameObjects[cubeId].active = false;
            players[socket.id].score += 10;
            
            stmt.updateScore.run(players[socket.id].score, session.userId);
            
            io.emit('cubeCollected', {
                cubeId: cubeId,
                odbc: socket.id,
                playerScore: players[socket.id].score
            });
            
            setTimeout(() => {
                gameObjects[cubeId] = {
                    id: cubeId,
                    x: (Math.random() - 0.5) * 80,
                    y: 1 + Math.random() * 3,
                    z: (Math.random() - 0.5) * 80,
                    color: COLORS[Math.floor(Math.random() * COLORS.length)],
                    active: true
                };
                io.emit('cubeSpawned', gameObjects[cubeId]);
            }, 2000);
        }
    });
    
    socket.on('chat', (message) => {
        if (!message || typeof message !== 'string') return;
        
        const sanitized = validator.escape(message.substring(0, 100));
        
        if (players[socket.id] && sanitized.length > 0) {
            io.emit('chatMessage', {
                name: players[socket.id].username,
                message: sanitized,
                color: players[socket.id].color
            });
        }
    });
    
    socket.on('disconnect', () => {
        console.log(`プレイヤー切断: ${user.username}`);
        delete players[socket.id];
        io.emit('playerLeft', socket.id);
    });
});

setInterval(() => {
    const scoreboard = Object.values(players)
        .map(p => ({ name: p.username, score: p.score, color: p.color }))
        .sort((a, b) => b.score - a.score)
        .slice(0, 10);
    io.emit('scoreboard', scoreboard);
}, 1000);

// ============== サーバー起動 ==============

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🔒 セキュアサーバー起動: http://localhost:${PORT}`);
});
