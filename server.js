'use strict';

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const app = express();
const PORT = process.env.PORT || 3000;

const APP_NAME = 'GO&GO';
const CURRENCY = 'GOC';

/*
 * DATABASE
 * Icyitonderwa: /tmp kuri Render ishobora gutuma
 * amakuru abura service yongeye gutangira.
 * Koresha persistent disk cyangwa database ibika
 * amakuru burundu mbere yo gukoresha urubuga live.
 */
const DB_PATH = '/tmp/gogo.db';

if (
    !process.env.SESSION_SECRET ||
    process.env.SESSION_SECRET.length < 32
) {
    throw new Error(
        'SESSION_SECRET igomba kuba nibura inyuguti 32.'
    );
}

let db;

try {
    db = new DatabaseSync(DB_PATH);
    console.log('GO&GO database opened successfully.');
    console.log('Database location:', DB_PATH);
} catch (error) {
    console.error('GO&GO database could not be opened.');
    console.error('Database location:', DB_PATH);
    console.error('Database error:', error.message);
    process.exit(1);
}

/* DATABASE TABLES */

db.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        balance REAL NOT NULL DEFAULT 0,
        is_admin INTEGER NOT NULL DEFAULT 0,
        referral_code TEXT NOT NULL UNIQUE,
        referred_by INTEGER,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (referred_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS videos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        video_url TEXT NOT NULL,
        likes INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS follows (
        follower_id INTEGER NOT NULL,
        following_id INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (follower_id, following_id),
        CHECK (follower_id != following_id),
        FOREIGN KEY (follower_id) REFERENCES users(id),
        FOREIGN KEY (following_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS likes (
        user_id INTEGER NOT NULL,
        video_id INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, video_id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (video_id) REFERENCES videos(id)
    );

    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        video_id INTEGER NOT NULL,
        comment TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (video_id) REFERENCES videos(id)
    );

    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        amount REAL NOT NULL,
        description TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS referrals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        referrer_id INTEGER NOT NULL,
        referred_id INTEGER NOT NULL UNIQUE,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (referrer_id) REFERENCES users(id),
        FOREIGN KEY (referred_id) REFERENCES users(id)
    );
`);

/* PREPARED STATEMENTS */

const q = {
    userById: db.prepare(
        'SELECT * FROM users WHERE id = ?'
    ),

    userByEmail: db.prepare(
        'SELECT * FROM users WHERE email = ?'
    ),

    userByUsername: db.prepare(
        'SELECT * FROM users WHERE username = ?'
    ),

    userByReferral: db.prepare(
        'SELECT * FROM users WHERE referral_code = ?'
    ),

    createUser: db.prepare(`
        INSERT INTO users
        (username, email, password_hash, referral_code, referred_by)
        VALUES (?, ?, ?, ?, ?)
    `),

    videos: db.prepare(`
        SELECT videos.*, users.username
        FROM videos
        JOIN users ON users.id = videos.user_id
        ORDER BY videos.id DESC
    `),

    videoById: db.prepare(
        'SELECT * FROM videos WHERE id = ?'
    ),

    createVideo: db.prepare(`
        INSERT INTO videos (user_id, title, video_url)
        VALUES (?, ?, ?)
    `),

    hasLiked: db.prepare(`
        SELECT 1 FROM likes
        WHERE user_id = ? AND video_id = ?
    `),

    createLike: db.prepare(`
        INSERT INTO likes (user_id, video_id)
        VALUES (?, ?)
    `),

    deleteLike: db.prepare(`
        DELETE FROM likes
        WHERE user_id = ? AND video_id = ?
    `),

    updateLikes: db.prepare(`
        UPDATE videos
        SET likes = (
            SELECT COUNT(*) FROM likes WHERE video_id = ?
        )
        WHERE id = ?
    `),

    follow: db.prepare(`
        INSERT OR IGNORE INTO follows
        (follower_id, following_id)
        VALUES (?, ?)
    `),

    unfollow: db.prepare(`
        DELETE FROM follows
        WHERE follower_id = ? AND following_id = ?
    `),

    followerCount: db.prepare(`
        SELECT COUNT(*) AS total
        FROM follows WHERE following_id = ?
    `),

    followingCount: db.prepare(`
        SELECT COUNT(*) AS total
        FROM follows WHERE follower_id = ?
    `),

    transactions: db.prepare(`
        SELECT * FROM transactions
        WHERE user_id = ?
        ORDER BY id DESC LIMIT 100
    `)
};

/* HELPER FUNCTIONS */

function escapeHtml(value = '') {
    return String(value).replace(/[&<>"']/g, ch => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[ch]);
}

function validUsername(value) {
    return /^[a-zA-Z0-9_]{3,24}$/.test(value);
}

function newReferralCode() {
    return crypto.randomBytes(6).toString('hex').toUpperCase();
}

function resToken(req) {
    return req.session.formToken || '';
}

/* EXPRESS CONFIGURATION */

app.disable('x-powered-by');

app.set('trust proxy', 1);

app.use(express.urlencoded({
    extended: false,
    limit: '20kb'
}));

app.use(express.json({
    limit: '20kb'
}));

app.use(session({
    name: 'gogo.sid',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
}));
/* FORM TOKEN */

app.use((req, res, next) => {
    if (!req.session.formToken) {
        req.session.formToken = crypto.randomBytes(32).toString('hex');
    }

    res.locals.formToken = req.session.formToken;
    next();
});

function checkToken(req, res, next) {
    const token = req.body._token || req.get('x-form-token');
    const expected = req.session.formToken;

    if (
        typeof token !== 'string' ||
        typeof expected !== 'string' ||
        token.length !== expected.length
    ) {
        return res.status(403).send(
            'Request ntiyemewe. Ongera ugerageze.'
        );
    }

    const tokenBuffer = Buffer.from(token);
    const expectedBuffer = Buffer.from(expected);

    if (
        tokenBuffer.length !== expectedBuffer.length ||
        !crypto.timingSafeEqual(tokenBuffer, expectedBuffer)
    ) {
        return res.status(403).send(
            'Request ntiyemewe. Ongera ugerageze.'
        );
    }

    next();
}

/* REQUIRE LOGIN — IKOSA RYAKOSOWE */

function requireLogin(req, res, next) {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const user = q.userById.get(req.session.userId);

    if (!user) {
        req.session.destroy(() => {});
        return res.redirect('/login');
    }

    req.user = user;
    next();
}

/* REQUIRE ADMIN */

function requireAdmin(req, res, next) {
    if (!req.user || req.user.is_admin !== 1) {
        return res.status(403).send(
            'Ntufite uburenganzira bwa Admin.'
        );
    }

    next();
}

/* HTML PAGE TEMPLATE */

function page(title, content, req) {
    const user = req.session.userId
        ? q.userById.get(req.session.userId)
        : null;

    const token = escapeHtml(resToken(req));

    const nav = user ? `
        <nav>
            <a href="/">Home</a>
            <a href="/search">Search</a>
            <a href="/upload">Upload</a>
            <a href="/wallet">GO CASH</a>
            <a href="/referrals">Invite</a>
            ${user.is_admin ? '<a href="/admin">Admin</a>' : ''}
            <form class="inline" method="post" action="/logout">
                <input type="hidden" name="_token" value="${token}">
                <button class="navbtn">Logout</button>
            </form>
        </nav>
    ` : `
        <nav>
            <a href="/">Home</a>
            <a href="/login">Login</a>
            <a href="/register">Create account</a>
        </nav>
    `;

    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(title)} | GO&GO</title>
    <style>
        :root {
            --green: #087f23;
            --yellow: #ffdf00;
            --white: #ffffff;
            --background: #f5f7f3;
            --text: #202820;
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: var(--background);
            color: var(--text);
        }

        header {
            background: var(--green);
            color: white;
            padding: 16px;
        }

        .brand {
            font-size: 26px;
            font-weight: bold;
        }

        .brand span {
            color: var(--yellow);
        }

        nav {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 12px;
            padding: 12px;
            background: white;
            border-bottom: 2px solid var(--yellow);
        }

        nav a {
            color: var(--green);
            text-decoration: none;
            font-weight: bold;
        }

        main {
            max-width: 900px;
            margin: 20px auto;
            padding: 0 12px;
        }

        .card {
            background: white;
            padding: 18px;
            margin-bottom: 16px;
            border-radius: 12px;
            box-shadow: 0 2px 8px #00000012;
        }

        input, textarea, button {
            font: inherit;
            padding: 10px;
            margin: 5px 0;
            max-width: 100%;
        }

        input, textarea {
            width: 100%;
            border: 1px solid #cccccc;
            border-radius: 6px;
        }

        button, .button {
            background: var(--green);
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            padding: 10px 14px;
            text-decoration: none;
        }

        .inline {
            display: inline;
        }

        .navbtn {
            background: var(--green);
        }

        .yellow {
            background: var(--yellow);
            color: #202820;
        }

        .muted {
            color: #666666;
            font-size: 14px;
        }

        .video-card {
            position: relative;
        }

        .video-card video {
            width: 100%;
            max-height: 520px;
            background: #111111;
            border-radius: 8px;
        }

        .share-button {
            background: var(--yellow);
            color: #202820;
            font-size: 20px;
            border-radius: 50%;
            width: 46px;
            height: 46px;
        }

        .actions {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 8px;
            margin-top: 10px;
        }

        .error {
            color: #b00020;
        }

        @media (max-width: 600px) {
            main {
                margin-top: 12px;
            }

            nav {
                gap: 9px;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="brand">GO<span>&</span>GO</div>
        <div>Share your world.</div>
    </header>

    ${nav}

    <main>
        ${content}
    </main>

    <script>
        async function sharePost(url, title) {
            const fullUrl = new URL(url, window.location.origin).href;

            if (navigator.share) {
                try {
                    await navigator.share({
                        title: title || 'GO&GO',
                        url: fullUrl
                    });
                    return;
                } catch (error) {
                    if (error.name === 'AbortError') return;
                }
            }

            try {
                await navigator.clipboard.writeText(fullUrl);
                alert('Link yakoporowe!');
            } catch (error) {
                window.prompt('Kopiya iyi link:', fullUrl);
            }
        }
    </script>
</body>
</html>
    `;
 /* =========================================
   GO&GO — IGICE CYA 3/5
   REGISTER, LOGIN, HOME, SEARCH, UPLOAD
========================================= */

/* HOME */

app.get('/', (req, res) => {
    const videos = q.videos.all();

    const content = `
        <section class="card">
            <h1>Murakaza neza kuri GO&GO 💚💛</h1>
            <p>Sangira ibitekerezo, amafoto na video n'inshuti zawe.</p>
            ${req.session.userId
                ? '<a class="button" href="/upload">Shyiraho post</a>'
                : '<a class="button" href="/register">Fungura konti</a>'}
        </section>

        <h2>Posts nshya</h2>

        ${videos.length ? videos.map(video => `
            <article class="card video-card">
                <h3>${escapeHtml(video.username)}</h3>
                <p>${escapeHtml(video.title)}</p>

                <video controls preload="metadata"
                    src="${escapeHtml(video.video_url)}"></video>

                <div class="actions">
                    <span>❤️ ${Number(video.likes) || 0}</span>

                    ${req.session.userId ? `
                        <form class="inline" method="post"
                              action="/like/${video.id}">
                            <input type="hidden" name="_token"
                                   value="${escapeHtml(resToken(req))}">
                            <button type="submit">❤️ Like</button>
                        </form>
                    ` : ''}

                    <button class="share-button" type="button"
                        aria-label="Share post"
                        onclick="sharePost('/post/${video.id}',
                        '${escapeHtml(video.title).replace(/'/g, '&#39;')}')">
                        ↗
                    </button>
                </div>

                <p class="muted">
                    ${escapeHtml(video.created_at || '')}
                </p>
            </article>
        `).join('') : `
            <section class="card">
                Nta post irashyirwaho. Ba uwa mbere!
            </section>
        `}
    `;

    res.send(page('Home', content, req));
});

/* REGISTER PAGE */

app.get('/register', (req, res) => {
    const content = `
        <section class="card">
            <h1>Fungura konti ya GO&GO</h1>

            <form method="post" action="/register">
                <input type="hidden" name="_token"
                    value="${escapeHtml(resToken(req))}">

                <label>Username</label>
                <input name="username" required minlength="3"
                    maxlength="24" autocomplete="username"
                    placeholder="Andika username">

                <label>Email</label>
                <input name="email" type="email" required
                    maxlength="254" autocomplete="email"
                    placeholder="Andika email">

                <label>Password</label>
                <input name="password" type="password" required
                    minlength="8" maxlength="128"
                    autocomplete="new-password"
                    placeholder="Nibura inyuguti 8">

                <label>Referral code (si ngombwa)</label>
                <input name="referral" maxlength="40"
                    placeholder="Referral code">

                <button type="submit">Create account</button>
            </form>

            <p>Usanzwe ufite konti?
                <a href="/login">Injira hano</a>
            </p>
        </section>
    `;

    res.send(page('Register', content, req));
});

/* REGISTER ACTION */

app.post('/register', checkToken, async (req, res) => {
    try {
        const username = String(req.body.username || '').trim();
        const email = String(req.body.email || '')
            .trim().toLowerCase();
        const password = String(req.body.password || '');
        const referral = String(req.body.referral || '').trim();

        if (!validUsername(username)) {
            return res.status(400).send(
                page('Error', `
                    <section class="card">
                        <h2 class="error">Username si yo!</h2>
                        <p>Koresha inyuguti, imibare na _ gusa,
                        hagati ya 3 na 24.</p>
                        <a href="/register">Subira inyuma</a>
                    </section>
                `, req)
            );
        }

        if (
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
            email.length > 254
        ) {
            return res.status(400).send(
                page('Error', `
                    <section class="card">
                        <h2 class="error">Email si yo.</h2>
                        <a href="/register">Subira inyuma</a>
                    </section>
                `, req)
            );
        }

        if (password.length < 8 || password.length > 128) {
            return res.status(400).send(
                page('Error', `
                    <section class="card">
                        <h2 class="error">Password ntiyujuje ibisabwa.</h2>
                        <p>Igomba kugira inyuguti nibura 8.</p>
                        <a href="/register">Subira inyuma</a>
                    </section>
                `, req)
            );
        }

        if (
            q.userByEmail.get(email) ||
            q.userByUsername.get(username)
        ) {
            return res.status(409).send(
                page('Error', `
                    <section class="card">
                        <h2 class="error">Konti irahari.</h2>
                        <p>Gerageza indi email cyangwa username.</p>
                        <a href="/register">Subira inyuma</a>
                    </section>
                `, req)
            );
        }

        let referredBy = null;

        if (referral) {
            const referrer = q.userByReferral.get(referral);

            if (referrer) {
                referredBy = referrer.id;
            }
        }

        const passwordHash = await bcrypt.hash(password, 12);
        const referralCode = newReferralCode();

        const result = q.createUser.run(
            username,
            email,
            passwordHash,
            referralCode,
            referredBy
        );

        const newUserId = Number(result.lastInsertRowid);

        if (referredBy) {
            db.prepare(`
                INSERT OR IGNORE INTO referrals
                (referrer_id, referred_id)
                VALUES (?, ?)
            `).run(referredBy, newUserId);
        }

        req.session.regenerate(error => {
            if (error) {
                console.error('Session error:', error.message);
                return res.status(500).send(
                    'Konti yako yarakozwe, ariko kwinjira byanze. Gerageza login.'
                );
            }

            req.session.userId = newUserId;
            req.session.formToken =
                crypto.randomBytes(32).toString('hex');

            req.session.save(saveError => {
                if (saveError) {
                    console.error('Session save error:',
                        saveError.message);
                    return res.redirect('/login');
                }

                res.redirect('/');
            });
        });
    } catch (error) {
        console.error('Registration error:', error.message);

        if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            return res.status(409).send(
                'Email cyangwa username isanzwe ikoreshwa.'
            );
        }

        res.status(500).send(
            'Habaye ikibazo mu gukora konti. Ongera ugerageze.'
        );
    }
});

/* LOGIN PAGE */

app.get('/login', (req, res) => {
    const content = `
        <section class="card">
            <h1>Injira muri GO&GO</h1>

            <form method="post" action="/login">
                <input type="hidden" name="_token"
                    value="${escapeHtml(resToken(req))}">

                <label>Email</label>
                <input name="email" type="email" required
                    autocomplete="email">

                <label>Password</label>
                <input name="password" type="password" required
                    autocomplete="current-password">

                <button type="submit">Login</button>
            </form>

            <p>Nta konti ufite?
                <a href="/register">Iyandikishe</a>
            </p>
        </section>
    `;

    res.send(page('Login', content, req));
});

/* LOGIN ACTION */

app.post('/login', checkToken, async (req, res) => {
    try {
        const email = String(req.body.email || '')
            .trim().toLowerCase();
        const password = String(req.body.password || '');

        const user = q.userByEmail.get(email);

        if (
            !user ||
            !(await bcrypt.compare(password, user.password_hash))
        ) {
            return res.status(401).send(
                page('Login', `
                    <section class="card">
                        <h2 class="error">
                            Email cyangwa password si byo.
                        </h2>
                        <a href="/login">Ongera ugerageze</a>
                    </section>
                `, req)
            );
        }

        req.session.regenerate(error => {
            if (error) {
                console.error('Login session error:',
                    error.message);
                return res.status(500).send('Login yanze.');
            }

            req.session.userId = user.id;
            req.session.formToken =
                crypto.randomBytes(32).toString('hex');

            req.session.save(saveError => {
                if (saveError) {
                    console.error('Login save error:',
                        saveError.message);
                    return res.status(500).send(
                        'Login yanze. Ongera ugerageze.'
                    );
                }

                res.redirect('/');
            });
        });
    } catch (error) {
        console.error('Login error:', error.message);
        res.status(500).send('Habaye ikibazo mu kwinjira.');
    }
});

/* LOGOUT */

app.post('/logout', checkToken, requireLogin, (req, res) => {
    req.session.destroy(error => {
        if (error) {
            console.error('Logout error:', error.message);
            return res.status(500).send('Logout yanze.');
        }

        res.clearCookie('gogo.sid');
        res.redirect('/');
    });
});

/* UPLOAD PAGE */

app.get('/upload', requireLogin, (req, res) => {
    const content = `
        <section class="card">
            <h1>Shyiraho video</h1>

            <p>
                Andika umutwe wa video, hanyuma ushyiremo
                URL ya video iboneka kuri internet.
            </p>

            <form method="post" action="/upload">
                <input type="hidden" name="_token"
                    value="${escapeHtml(resToken(req))}">

                <label>Umutwe wa post</label>
                <input name="title" required maxlength="200">

                <label>Video URL</label>
                <input name="video_url" type="url" required
                    maxlength="2000"
                    placeholder="https://example.com/video.mp4">

                <button type="submit">Publish</button>
            </form>
        </section>
    `;

    res.send(page('Upload', content, req));
});

/* UPLOAD ACTION */

app.post('/upload', requireLogin, checkToken, (req, res) => {
    try {
        const title = String(req.body.title || '').trim();
        const videoUrl = String(req.body.video_url || '').trim();

        if (!title || title.length > 200) {
            return res.status(400).send(
                'Umutwe wa post ugomba kuba hagati y’inyuguti 1 na 200.'
            );
        }

        if (
            !/^https?:\/\/\S+$/i.test(videoUrl) ||
            videoUrl.length > 2000
        ) {
            return res.status(400).send(
                'Video URL si yo.'
            );
        }

        q.createVideo.run(req.user.id, title, videoUrl);

        res.redirect('/');
    } catch (error) {
        console.error('Upload error:', error.message);
        res.status(500).send(
            'Video ntiyabashije gushyirwaho.'
        );
    }
});

/* LIKE / UNLIKE */

app.post('/like/:id', requireLogin, checkToken, (req, res) => {
    const videoId = Number(req.params.id);

    if (!Number.isSafeInteger(videoId) || videoId < 1) {
        return res.status(400).send('Post ntiyabonetse.');
    }

    const video = q.videoById.get(videoId);

    if (!video) {
        return res.status(404).send('Post ntiyabonetse.');
    }

    try {
        const existing = q.hasLiked.get(req.user.id, videoId);

        if (existing) {
            q.deleteLike.run(req.user.id, videoId);
        } else {
            q.createLike.run(req.user.id, videoId);
        }

        q.updateLikes.run(videoId, videoId);

        res.redirect('/');
    } catch (error) {
        console.error('Like error:', error.message);
        res.status(500).send('Like yanze. Ongera ugerageze.');
    }
});

/* SEARCH PAGE */

app.get('/search', requireLogin, (req, res) => {
    const term = String(req.query.q || '').trim().slice(0, 60);

    let users = [];

    if (term) {
        users = db.prepare(`
            SELECT id, username
            FROM users
            WHERE username LIKE ?
            ORDER BY username
            LIMIT 30
        `).all('%' + term.replace(/[%_]/g, '') + '%');
    }

    const content = `
        <section class="card">
            <h1>Shaka abantu</h1>

            <form method="get" action="/search">
                <input name="q" maxlength="60"
                    value="${escapeHtml(term)}"
                    placeholder="Shaka username">
                <button type="submit">Search</button>
            </form>
        </section>

        ${users.map(user => `
            <section class="card">
                <strong>${escapeHtml(user.username)}</strong>
                <a class="button" href="/profile/${user.id}">
                    Reba profile
                </a>
            </section>
        `).join('')}
    `;

    res.send(page('Search', content, req));
});
        }
/* =========================================
   GO&GO — IGICE CYA 5/5
   ADMIN, ERRORS AND SERVER STARTUP
========================================= */

/* ADMIN DASHBOARD */

app.get('/admin', requireLogin, requireAdmin, (req, res) => {
    const totalUsers = db.prepare(`
        SELECT COUNT(*) AS total FROM users
    `).get().total;

    const totalPosts = db.prepare(`
        SELECT COUNT(*) AS total FROM videos
    `).get().total;

    const totalComments = db.prepare(`
        SELECT COUNT(*) AS total FROM comments
    `).get().total;

    const totalFollows = db.prepare(`
        SELECT COUNT(*) AS total FROM follows
    `).get().total;

    const users = db.prepare(`
        SELECT id, username, email, balance, is_admin, created_at
        FROM users
        ORDER BY id DESC
        LIMIT 100
    `).all();

    const content = `
        <section class="card">
            <h1>👑 GO&GO Admin Dashboard</h1>

            <p>Total users: <strong>${Number(totalUsers)}</strong></p>
            <p>Total posts: <strong>${Number(totalPosts)}</strong></p>
            <p>Total comments: <strong>${Number(totalComments)}</strong></p>
            <p>Total follows: <strong>${Number(totalFollows)}</strong></p>
        </section>

        <section class="card">
            <h2>Abakoresha baheruka kwiyandikisha</h2>

            <div style="overflow-x:auto">
                <table border="1" cellpadding="8"
                    cellspacing="0" width="100%">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Balance</th>
                            <th>Admin</th>
                            <th>Created</th>
                        </tr>
                    </thead>

                    <tbody>
                        ${users.map(user => `
                            <tr>
                                <td>${Number(user.id)}</td>
                                <td>${escapeHtml(user.username)}</td>
                                <td>${escapeHtml(user.email)}</td>
                                <td>${Number(user.balance || 0)}</td>
                                <td>${user.is_admin ? 'Yes' : 'No'}</td>
                                <td>${escapeHtml(user.created_at || '')}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </section>
    `;

    res.send(page('Admin', content, req));
});

/* ADMIN: VIEW POSTS */

app.get(
    '/admin/posts',
    requireLogin,
    requireAdmin,
    (req, res) => {
        const videos = q.videos.all();

        const content = `
            <section class="card">
                <h1>Manage Posts</h1>

                ${videos.map(video => `
                    <div class="card">
                        <h3>${escapeHtml(video.title)}</h3>
                        <p>
                            By ${escapeHtml(video.username)}
                        </p>
                        <a href="/post/${video.id}">
                            View post
                        </a>
                    </div>
                `).join('')}
            </section>
        `;

        res.send(page('Manage Posts', content, req));
    }
);

/* 404 PAGE */

app.use((req, res) => {
    res.status(404).send(
        page('Page Not Found', `
            <section class="card">
                <h1>404 — Page ntiyabonetse</h1>
                <p>Iyo paji ntiboneka kuri GO&GO.</p>
                <a class="button" href="/">Subira kuri Home</a>
            </section>
        `, req)
    );
});

/* GLOBAL ERROR HANDLER */

app.use((err, req, res, next) => {
    console.error('GO&GO application error:', err);

    if (res.headersSent) {
        return next(err);
    }

    res.status(500).send(
        page('Server Error', `
            <section class="card">
                <h1>Habaye ikibazo</h1>
                <p>Ongera ugerageze nyuma y'akanya.</p>
                <a class="button" href="/">Subira kuri Home</a>
            </section>
        `, req)
    );
});

/* SERVER STARTUP */

const server = app.listen(PORT, '0.0.0.0', () => {
    console.log('===================================');
    console.log('GO&GO server started successfully');
    console.log('Port:', PORT);
    console.log('Environment:', process.env.NODE_ENV || 'development');
    console.log('===================================');
});

/* GRACEFUL SHUTDOWN */

function shutdown(signal) {
    console.log(`${signal} received. Closing GO&GO...`);

    server.close(() => {
        try {
            db.close();
            console.log('Database closed.');
            process.exit(0);
        } catch (error) {
            console.error('Shutdown error:', error.message);
            process.exit(1);
        }
    });

    setTimeout(() => {
        console.error('Shutdown timed out.');
        process.exit(1);
    }, 10000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
