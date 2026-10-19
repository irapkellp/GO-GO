'use strict';

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { DatabaseSync } = require('node:sqlite');

const app = express();
const PORT = process.env.PORT || 3000;

const APP_NAME = 'GO&GO';
const CURRENCY = 'GOC';

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'gogo.db');

if (!process.env.SESSION_SECRET ||
    process.env.SESSION_SECRET.length < 32) {
    throw new Error(
        'SESSION_SECRET igomba kuba nibura inyuguti 32.'
    );
}

const db = new DatabaseSync(DB_PATH);

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
        SELECT 1 FROM likes WHERE user_id = ? AND video_id = ?
    `),
    createLike: db.prepare(`
        INSERT INTO likes (user_id, video_id)
        VALUES (?, ?)
    `),
    deleteLike: db.prepare(`
        DELETE FROM likes WHERE user_id = ? AND video_id = ?
    `),
    updateLikes: db.prepare(`
        UPDATE videos SET likes = (
            SELECT COUNT(*) FROM likes WHERE video_id = ?
        ) WHERE id = ?
    `),
    follow: db.prepare(`
        INSERT OR IGNORE INTO follows (follower_id, following_id)
        VALUES (?, ?)
    `),
    unfollow: db.prepare(`
        DELETE FROM follows
        WHERE follower_id = ? AND following_id = ?
    `),
    followerCount: db.prepare(`
        SELECT COUNT(*) AS total FROM follows WHERE following_id = ?
    `),
    followingCount: db.prepare(`
        SELECT COUNT(*) AS total FROM follows WHERE follower_id = ?
    `),
    transactions: db.prepare(`
        SELECT * FROM transactions
        WHERE user_id = ?
        ORDER BY id DESC LIMIT 100
    `)
};

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

app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(express.json({ limit: '20kb' }));

app.use(session({
    name: 'gogo.sid',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        maxAge: 7 * 24 * 60 * 60 * 1000
    }
}));

// Basic request token for forms.
app.use((req, res, next) => {
    if (!req.session.formToken) {
        req.session.formToken = crypto.randomBytes(24).toString('hex');
    }
    res.locals.formToken = req.session.formToken;
    next();
});

function checkToken(req, res, next) {
    const token = req.body._token || req.get('x-form-token');

    if (!token ||
        !req.session.formToken ||
        !crypto.timingSafeEqual(
            Buffer.from(String(token)),
            Buffer.from(String(req.session.formToken))
        )) {
        return res.status(403).send('Request ntiyemewe. Ongera ugerageze.');
    }

    next();
}

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

function requireAdmin(req, res, next) {
    if (!req.user || req.user.is_admin !== 1) {
        return res.status(403).send('Ntufite uburenganzira bwa Admin.');
    }

    next();
}

function page(title, content, req, extra = '') {
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

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} | GO&GO</title>
<style>
:root {
    --green: #138b43;
    --darkgreen: #08632c;
    --yellow: #ffdf36;
    --bg: #f5f8f4;
    --text: #17231b;
}
* { box-sizing: border-box; }
body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: Arial, sans-serif;
}
header {
    background: var(--green);
    color: white;
    padding: 18px 5%;
    border-bottom: 5px solid var(--yellow);
}
.brand { font-size: 29px; font-weight: 900; }
.brand span { color: var(--yellow); }
nav {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 14px;
    padding: 14px 5%;
    background: white;
    border-bottom: 1px solid #ddd;
}
nav a, .navbtn {
    color: var(--darkgreen);
    font-weight: bold;
    text-decoration: none;
}
.inline { display: inline; margin: 0; }
.navbtn {
    border: 0;
    background: transparent;
    cursor: pointer;
    font-size: 15px;
}
main { max-width: 900px; margin: 25px auto; padding: 0 15px; }
.card {
    background: white;
    border-radius: 14px;
    padding: 20px;
    margin-bottom: 18px;
    box-shadow: 0 2px 9px #0000000c;
}
h1, h2 { color: var(--darkgreen); }
label { display: block; margin: 12px 0 5px; font-weight: bold; }
input, textarea {
    width: 100%;
    padding: 12px;
    border: 1px solid #cbd5cc;
    border-radius: 8px;
    font-size: 16px;
}
button, .button {
    display: inline-block;
    padding: 11px 17px;
    background: var(--green);
    color: white;
    border: 0;
    border-radius: 8px;
    cursor: pointer;
    text-decoration: none;
    font-weight: bold;
}
button:hover, .button:hover { background: var(--darkgreen); }
.yellow { background: var(--yellow); color: #17231b; }
.muted { color: #66736a; font-size: 14px; }
video { width: 100%; max-height: 520px; background: #111; border-radius: 10px; }
.balance { font-size: 30px; font-weight: bold; color: var(--green); }
footer { text-align: center; padding: 25px; color: #68746b; }
.stat { display: inline-block; padding: 12px; margin: 5px; background: #f0f7ee; border-radius: 9px; }
</style>
</head>
<body>
<header>
    <div class="brand">GO<span>&</span>GO</div>
    <div>Connect • Create • Discover</div>
</header>
${nav}
<main>${content}</main>
<footer>© ${new Date().getFullYear()} GO&GO — Connect the world.</footer>
${extra}
</body>
</html>`;
}

function resToken(req) {
    return req.session.formToken || '';
}

function renderPage(res, title, content, req, status = 200) {
    res.status(status).send(page(title, content, req));
}

app.get('/', (req, res) => {
    const user = req.session.userId
        ? q.userById.get(req.session.userId)
        : null;

    const videos = q.videos.all();

    const feed = videos.map(video => `
        <article class="card">
            <h3>${escapeHtml(video.title)}</h3>
            <p class="muted">
                By <a href="/u/${encodeURIComponent(video.username)}">
                @${escapeHtml(video.username)}</a>
            </p>
            <video controls preload="metadata" src="${escapeHtml(video.video_url)}"></video>
            <p>❤️ ${video.likes} likes</p>
            ${user ? `
                <form method="post" action="/videos/${video.id}/like">
                    <input type="hidden" name="_token" value="${escapeHtml(resToken(req))}">
                    <button type="submit" class="yellow">Like / Unlike</button>
                </form>
                <p><a href="/videos/${video.id}">View comments</a></p>
            ` : `<a href="/login">Login to like and comment</a>`}
        </article>
    `).join('');

    const content = `
        <section class="card">
            <h1>Welcome to GO&GO 💚💛</h1>
            <p>A place to share videos, meet people and discover creators.</p>
            ${user ? `
                <p>Murakaza neza, <b>@${escapeHtml(user.username)}</b>!</p>
                <p class="balance">${Number(user.balance).toFixed(2)} GOC</p>
                <a class="button" href="/upload">Share a video</a>
            ` : `
                <a class="button" href="/register">Join GO&GO</a>
                <a class="button yellow" href="/login">Login</a>
            `}
        </section>
        <h2>Video Feed</h2>
        ${feed || '<div class="card">Nta video irashyirwaho. Ba uwa mbere uyishyireho!</div>'}
    `;

    renderPage(res, 'Home', content, req);
});

app.get('/register', (req, res) => {
    const content = `
        <section class="card">
            <h1>Create account</h1>
            <form method="post" action="/register">
                <input type="hidden" name="_token" value="${escapeHtml(resToken(req))}">
                <label>Username</label>
                <input name="username" required minlength="3" maxlength="24"
                    pattern="[A-Za-z0-9_]+" autocomplete="username">
                <label>Email</label>
                <input type="email" name="email" required maxlength="254"
                    autocomplete="email">
                <label>Password</label>
                <input type="password" name="password" required minlength="10"
                    autocomplete="new-password">
                <label>Referral code (optional)</label>
                <input name="referral" maxlength="30">
                <p class="muted">Koresha password ikomeye, kandi ntuyisangize abandi.</p>
                <button type="submit">Create account</button>
            </form>
        </section>
    `;

    renderPage(res, 'Register', content, req);
});

app.post('/register', checkToken, async (req, res) => {
    const username = String(req.body.username || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const referral = String(req.body.referral || '').trim().toUpperCase();

    if (!validUsername(username)) {
        return res.status(400).send('Username igomba kuba inyuguti, imibare cyangwa _, kuva kuri 3 kugeza kuri 24.');
    }

    if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).send('Email ntabwo yemewe.');
    }

    if (password.length < 10 || password.length > 200) {
        return res.status(400).send('Password igomba kuba nibura inyuguti 10.');
    }

    if (q.userByEmail.get(email) || q.userByUsername.get(username)) {
        return res.status(409).send('Email cyangwa username isanzwe ikoreshwa.');
    }

    let referrer = null;

    if (referral) {
        const found = q.userByReferral.get(referral);
        if (found) referrer = found.id;
    }

    try {
        const passwordHash = await bcrypt.hash(password, 12);
        const result = q.createUser.run(
            username,
            email,
            passwordHash,
            newReferralCode(),
            referrer
        );

        const userId = Number(result.lastInsertRowid);

        if (referrer) {
            db.prepare(`
                INSERT OR IGNORE INTO referrals (referrer_id, referred_id)
                VALUES (?, ?)
            `).run(referrer, userId);
        }

        req.session.regenerate(err => {
            if (err) return res.status(500).send('Byanze. Ongera ugerageze.');

            req.session.userId = userId;
            req.session.formToken = crypto.randomBytes(24).toString('hex');
            res.redirect('/');
        });
    } catch (error) {
        console.error('Register error:', error.message);
        res.status(500).send('Konti ntiyakozwe. Ongera ugerageze.');
    }
});

app.get('/login', (req, res) => {
    const content = `
        <section class="card">
            <h1>Login to GO&GO</h1>
            <form method="post" action="/login">
                <input type="hidden" name="_token" value="${escapeHtml(resToken(req))}">
                <label>Email</label>
                <input type="email" name="email" required autocomplete="email">
                <label>Password</label>
                <input type="password" name="password" required autocomplete="current-password">
                <button type="submit">Login</button>
            </form>
        </section>
    `;

    renderPage(res, 'Login', content, req);
});

app.post('/login', checkToken, async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    const user = q.userByEmail.get(email);

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
        return res.status(401).send('Email cyangwa password si byo.');
    }

    req.session.regenerate(err => {
        if (err) return res.status(500).send('Login yanze. Ongera ugerageze.');

        req.session.userId = user.id;
        req.session.formToken = crypto.randomBytes(24).toString('hex');
        res.redirect('/');
    });
});

app.post('/logout', checkToken, requireLogin, (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

app.get('/upload', requireLogin, (req, res) => {
    const content = `
        <section class="card">
            <h1>Share a video</h1>
            <p>Shyiramo URL ya video iri kuri hosting yizewe. Video igomba kuba iyawe cyangwa ufite uburenganzira bwo kuyisangiza abandi.</p>
            <form method="post" action="/upload">
                <input type="hidden" name="_token" value="${escapeHtml(resToken(req))}">
                <label>Video title</label>
                <input name="title" maxlength="120" required>
                <label>Video URL (HTTPS)</label>
                <input name="video_url" type="url" required maxlength="1000"
                    placeholder="https://example.com/video.mp4">
                <button type="submit">Publish video</button>
            </form>
        </section>
    `;

    renderPage(res, 'Upload', content, req);
});

app.post('/upload', requireLogin, checkToken, (req, res) => {
    const title = String(req.body.title || '').trim();
    const videoUrl = String(req.body.video_url || '').trim();

    if (!title || title.length > 120) {
        return res.status(400).send('Title ntabwo yemewe.');
    }

    let parsed;

    try {
        parsed = new URL(videoUrl);
    } catch {
        return res.status(400).send('Video URL ntabwo yemewe.');
    }

    if (parsed.protocol !== 'https:') {
        return res.status(400).send('Koresha HTTPS video URL.');
    }

    q.createVideo.run(req.user.id, title, parsed.toString());
    res.redirect('/');
});

app.get('/videos/:id', (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isSafeInteger(id) || id < 1) {
        return res.status(400).send('Video ID ntabwo yemewe.');
    }

    const video = db.prepare(`
        SELECT videos.*, users.username
        FROM videos JOIN users ON users.id = videos.user_id
        WHERE videos.id = ?
    `).get(id);

    if (!video) return res.status(404).send('Video ntiyabonetse.');

    const comments = db.prepare(`
        SELECT comments.*, users.username
        FROM comments JOIN users ON users.id = comments.user_id
        WHERE comments.video_id = ?
        ORDER BY comments.id DESC
    `).all(id);

    const commentHtml = comments.map(c => `
        <div class="card">
            <b>@${escapeHtml(c.username)}</b>
            <p>${escapeHtml(c.comment)}</p>
            <small>${escapeHtml(c.created_at)}</small>
        </div>
    `).join('');

    const form = req.session.userId ? `
        <section class="card">
            <h3>Add a comment</h3>
            <form method="post" action="/videos/${id}/comment">
                <input type="hidden" name="_token" value="${escapeHtml(resToken(req))}">
                <textarea name="comment" maxlength="1000" required></textarea>
                <button type="submit">Comment</button>
            </form>
        </section>
    ` : '<p><a href="/login">Login to comment</a></p>';

    const content = `
        <article class="card">
            <h1>${escapeHtml(video.title)}</h1>
            <p>By @${escapeHtml(video.username)}</p>
            <video controls preload="metadata" src="${escapeHtml(video.video_url)}"></video>
            <p>❤️ ${video.likes} likes</p>
        </article>
        ${form}
        <h2>Comments</h2>
        ${commentHtml || '<p>No comments yet.</p>'}
    `;

    renderPage(res, 'Video', content, req);
});

app.post('/videos/:id/like', requireLogin, checkToken, (req, res) => {
    const videoId = Number(req.params.id);

    if (!Number.isSafeInteger(videoId) || videoId < 1 ||
        !q.videoById.get(videoId)) {
        return res.status(404).send('Video ntiyabonetse.');
    }

    if (q.hasLiked.get(req.user.id, videoId)) {
        q.deleteLike.run(req.user.id, videoId);
    } else {
        q.createLike.run(req.user.id, videoId);
    }

    q.updateLikes.run(videoId, videoId);
    res.redirect('/');
});

app.post('/videos/:id/comment', requireLogin, checkToken, (req, res) => {
    const videoId = Number(req.params.id);
    const comment = String(req.body.comment || '').trim();

    if (!Number.isSafeInteger(videoId) || videoId < 1 ||
        !q.videoById.get(videoId)) {
        return res.status(404).send('Video ntiyabonetse.');
    }

    if (!comment || comment.length > 1000) {
        return res.status(400).send('Comment ntabwo yemewe.');
    }

    db.prepare(`
        INSERT INTO comments (user_id, video_id, comment)
        VALUES (?, ?, ?)
    `).run(req.user.id, videoId, comment);

    res.redirect(`/videos/${videoId}`);
});

app.get('/search', (req, res) => {
    const search = String(req.query.q || '').trim().slice(0, 40);
    let results = [];

    if (search) {
        results = db.prepare(`
            SELECT id, username FROM users
            WHERE username LIKE ? ESCAPE '\\'
            ORDER BY username LIMIT 50
        `).all('%' + search.replace(/[\\%_]/g, '\\$&') + '%');
    }

    const rows = results.map(u => `
        <div class="card">
            <a href="/u/${encodeURIComponent(u.username)}">
                @${escapeHtml(u.username)}
            </a>
        </div>
    `).join('');

    const content = `
        <section class="card">
            <h1>Find people</h1>
            <form method="get" action="/search">
                <input name="q" value="${escapeHtml(search)}"
                    placeholder="Search username">
                <button type="submit">Search</button>
            </form>
        </section>
        ${rows || (search ? '<p>No users found.</p>' : '')}
    `;

    renderPage(res, 'Search', content, req);
});

app.get('/u/:username', (req, res) => {
    const username = String(req.params.username || '');
    const user = q.userByUsername.get(username);

    if (!user) return res.status(404).send('User ntiyabonetse.');

    const followers = q.followerCount.get(user.id).total;
    const following = q.followingCount.get(user.id).total;

    const isSelf = req.session.userId === user.id;

    const isFollowing = req.session.userId
        ? Boolean(db.prepare(`
            SELECT 1 FROM follows WHERE follower_id = ? AND following_id = ?
        `).get(req.session.userId, user.id))
        : false;

    const followForm = req.session.userId && !isSelf ? `
        <form method="post" action="/u/${encodeURIComponent(user.username)}/follow">
            <input type="hidden" name="_token" value="${escapeHtml(resToken(req))}">
            <button class="yellow">${isFollowing ? 'Unfollow' : 'Follow'}</button>
        </form>
    ` : '';

    const videos = db.prepare(`
        SELECT * FROM videos WHERE user_id = ? ORDER BY id DESC
    `).all(user.id);

    const videoHtml = videos.map(v => `
        <div class="card">
            <h3>${escapeHtml(v.title)}</h3>
            <video controls preload="metadata" src="${escapeHtml(v.video_url)}"></video>
            <p>❤️ ${v.likes}</p>
            <a href="/videos/${v.id}">Comments</a>
        </div>
    `).join('');

    const content = `
        <section class="card">
            <h1>@${escapeHtml(user.username)}</h1>
            <div class="stat">Followers: ${followers}</div>
            <div class="stat">Following: ${following}</div>
            ${followForm}
        </section>
        <h2>Videos</h2>
        ${videoHtml || '<p>This creator has not posted videos yet.</p>'}
    `;

    renderPage(res, 'Profile', content, req);
});

app.post('/u/:username/follow', requireLogin, checkToken, (req, res) => {
    const user = q.userByUsername.get(String(req.params.username || ''));

    if (!user) return res.status(404).send('User ntiyabonetse.');
    if (user.id === req.user.id) {
        return res.status(400).send('Ntushobora kwifollowinga.');
    }

    const existing = db.prepare(`
        SELECT 1 FROM follows WHERE follower_id = ? AND following_id = ?
    `).get(req.user.id, user.id);

    if (existing) {
        q.unfollow.run(req.user.id, user.id);
    } else {
        q.follow.run(req.user.id, user.id);
    }

    res.redirect(`/u/${encodeURIComponent(user.username)}`);
});

app.get('/wallet', requireLogin, (req, res) => {
    const transactions = q.transactions.all(req.user.id);

    const rows = transactions.map(t => `
        <tr>
            <td>${escapeHtml(t.type)}</td>
            <td>${Number(t.amount).toFixed(2)} GOC</td>
            <td>${escapeHtml(t.description)}</td>
            <td>${escapeHtml(t.created_at)}</td>
        </tr>
    `).join('');

    const content = `
        <section class="card">
            <h1>GO CASH Wallet</h1>
            <p class="balance">${Number(req.user.balance).toFixed(2)} GOC</p>
            <p>GOC ni amafaranga yo muri platform y'igerageza. Ntabwo ari amafaranga nyayo kugeza igihe uburyo bwo kuyishyura bwemejwe.</p>
            <p class="muted">Kubikuza ntibirafungurwa muri iyi version.</p>
        </section>
        <section class="card">
            <h2>Transaction history</h2>
            <div style="overflow-x:auto">
                <table>
                    <tr><th>Type</th><th>Amount</th><th>Description</th><th>Date</th></tr>
                    ${rows}
                </table>
            </div>
        </section>
    `;

    renderPage(res, 'Wallet', content, req);
});

app.get('/referrals', requireLogin, (req, res) => {
    const referrals = db.prepare(`
        SELECT users.username, referrals.created_at
        FROM referrals
        JOIN users ON users.id = referrals.referred_id
        WHERE referrals.referrer_id = ?
        ORDER BY referrals.id DESC
    `).all(req.user.id);

    const rows = referrals.map(r => `
        <div class="card">
            @${escapeHtml(r.username)}
            <p class="muted">${escapeHtml(r.created_at)}</p>
        </div>
    `).join('');

    const content = `
        <section class="card">
            <h1>Invite friends</h1>
            <p>Your referral code:</p>
            <h2>${escapeHtml(req.user.referral_code)}</h2>
            <p>Abantu biyandikisha bakoresheje iyi code bazagaragara mu mateka ya referrals yawe.</p>
            <p class="muted">Nta reward y'amafaranga ihita itangwa muri iyi version.</p>
        </section>
        <h2>Your referrals</h2>
        ${rows || '<p>You have no referrals yet.</p>'}
    `;

    renderPage(res, 'Referrals', content, req);
});

app.get('/admin', requireLogin, requireAdmin, (req, res) => {
    const userCount = db.prepare(
        'SELECT COUNT(*) AS n FROM users'
    ).get().n;

    const videoCount = db.prepare(
        'SELECT COUNT(*) AS n FROM videos'
    ).get().n;

    const commentCount = db.prepare(
        'SELECT COUNT(*) AS n FROM comments'
    ).get().n;

    const content = `
        <section class="card">
            <h1>GO&GO Admin Dashboard</h1>
            <div class="stat">Users: ${userCount}</div>
            <div class="stat">Videos: ${videoCount}</div>
            <div class="stat">Comments: ${commentCount}</div>
            <p>Admin dashboard y'ibanze. Ibikorwa byo guhindura balances, kwemeza withdrawals no gucunga adverts bigomba kubakwa byihariye kandi bigasuzumwa neza.</p>
        </section>
    `;

    renderPage(res, 'Admin', content, req);
});

// Health check for Render.
app.get('/health', (req, res) => {
    res.json({
        app: APP_NAME,
        status: 'ok',
        timestamp: new Date().toISOString()
    });
});

app.use((req, res) => {
    res.status(404).send(page(
        'Not found',
        '<section class="card"><h1>404</h1><p>Page ntiyabonetse.</p><a class="button" href="/">Back home</a></section>',
        req
    ));
});

app.use((err, req, res, next) => {
    console.error('Server error:', err.message);

    if (res.headersSent) return next(err);

    res.status(500).send(
        'Habaye ikibazo kuri server. Ongera ugerageze nyuma.'
    );
});

const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`${APP_NAME} running on port ${PORT}`);
});

function shutdown() {
    server.close(() => {
        try {
            db.close();
        } finally {
            process.exit(0);
        }
    });
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
