'use strict';
// QuadChat server - no dependencies, just Node.js 16+.  Run:  node server.js

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const MAX_PER_ROOM = 4;                 // max people per code
const GRACE_MS = 20 * 1000;             // closed tab / page reload grace before leaving the room
const SESSION_MS = 12 * 60 * 60 * 1000; // stay logged in for 12h at most
const CODE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I to avoid mix-ups
const USERS_FILE = process.env.USERS_FILE || path.join(__dirname, 'users.json');

// ---------------------------------------------------------------- accounts
let users = {};
try { users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch (_) { /* first run */ }
const saveUsers = () => fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { salt, hash: crypto.scryptSync(pw, salt, 64).toString('hex') };
}
function checkPassword(pw, rec) {
  const a = crypto.scryptSync(pw, rec.salt, 64);
  const b = Buffer.from(rec.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ------------------------------------------------------- sessions and rooms
const sessions = new Map();   // token -> session
const byUser = new Map();     // lowercase username -> token (one login per user)
const rooms = new Map();      // code -> { code, members: [session] }   (memory only)

function newCode() {
  let code;
  do {
    code = '';
    for (let i = 0; i < 6; i++) code += CODE_CHARS[crypto.randomInt(CODE_CHARS.length)];
  } while (rooms.has(code));
  return code;
}

function roomState(room) {
  return { code: room.code, max: MAX_PER_ROOM, members: room.members.map(m => m.username) };
}

function send(s, event, data) {
  const chunk = 'event: ' + event + '\ndata: ' + JSON.stringify(data) + '\n\n';
  for (const res of s.streams) res.write(chunk);
}
function broadcast(room, event, data) {
  for (const m of room.members) send(m, event, data);
}

function createRoom(s) {
  const room = { code: newCode(), members: [s] };
  rooms.set(room.code, room);
  s.room = room;
  return room;
}

function leaveRoom(s) {
  const room = s.room;
  if (!room) return;
  room.members = room.members.filter(m => m !== s);
  s.room = null;
  if (room.members.length === 0) {
    rooms.delete(room.code);            // empty -> the code is erased for good
    return;
  }
  broadcast(room, 'state', roomState(room));
  broadcast(room, 'system', { text: s.username + ' left the room' });
}

function joinRoom(s, room) {
  room.members.push(s);
  s.room = room;
  broadcast(room, 'state', roomState(room));
  broadcast(room, 'system', { text: s.username + ' joined the room' });
}

function createSession(username) {
  const key = username.toLowerCase();
  const old = byUser.get(key);
  if (old && sessions.has(old)) destroySession(sessions.get(old));
  const s = {
    token: crypto.randomBytes(24).toString('hex'),
    username,
    streams: new Set(),
    room: null,
    timer: null,
    expires: Date.now() + SESSION_MS,
    lastMsg: 0,
    fails: [],
  };
  sessions.set(s.token, s);
  byUser.set(key, s.token);
  createRoom(s);                        // every login gets a brand-new code
  return s;
}

function destroySession(s) {
  clearTimeout(s.timer);
  leaveRoom(s);                         // logging out erases your code if you were alone in it
  for (const res of s.streams) res.end();
  s.streams.clear();
  sessions.delete(s.token);
  if (byUser.get(s.username.toLowerCase()) === s.token) byUser.delete(s.username.toLowerCase());
}

// ------------------------------------------------------------------ helpers
function getSession(req, url) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : url.searchParams.get('token'); // SSE can't set headers
  const s = token && sessions.get(token);
  if (!s) return null;
  if (s.expires < Date.now()) { destroySession(s); return null; }
  return s;
}

function json(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    if (!(req.headers['content-type'] || '').startsWith('application/json')) return reject(new Error('bad type'));
    let data = '';
    req.on('data', c => { data += c; if (data.length > 10000) { reject(new Error('too big')); req.destroy(); } });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}

const loginAttempts = new Map(); // ip -> [timestamps]
function tooManyAttempts(ip) {
  const now = Date.now();
  const list = (loginAttempts.get(ip) || []).filter(t => now - t < 5 * 60 * 1000);
  loginAttempts.set(ip, list);
  return list.length >= 15;
}

// ------------------------------------------------------------------- server
const server = http.createServer(async (req, res) => {
  // CORS: lets the page work even if it was opened as a file or from VS Code Live Server
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  const url = new URL(req.url, 'http://localhost');
  const route = req.method + ' ' + url.pathname;
  const ip = req.socket.remoteAddress;

  try {
    // ---- the web page
    if (route === 'GET /' || route === 'GET /index.html') {
      return fs.readFile(path.join(__dirname, 'index.html'), (err, html) => {
        if (err) return json(res, 500, { error: 'index.html not found next to server.js' });
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'X-Content-Type-Options': 'nosniff',
          'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'",
        });
        res.end(html);
      });
    }

    // ---- lets the page check that this really is the QuadChat server
    if (route === 'GET /api/ping') return json(res, 200, { app: 'quadchat' });

    // ---- register / login
    if (route === 'POST /api/register' || route === 'POST /api/login') {
      const body = await readBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      if (tooManyAttempts(ip)) return json(res, 429, { error: 'Too many attempts. Wait a few minutes.' });
      loginAttempts.get(ip).push(Date.now());
      const key = username.toLowerCase();

      if (url.pathname === '/api/register') {
        if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) return json(res, 400, { error: 'Username: 3-20 letters, numbers or _' });
        if (password.length < 6 || password.length > 100) return json(res, 400, { error: 'Password must be at least 6 characters' });
        if (users[key]) return json(res, 409, { error: 'That username is taken' });
        users[key] = Object.assign({ name: username }, hashPassword(password));
        saveUsers();
      } else {
        const rec = users[key];
        if (!rec || !checkPassword(password, rec)) return json(res, 401, { error: 'Wrong username or password' });
      }
      const s = createSession(users[key].name);
      return json(res, 200, { username: s.username, token: s.token });
    }

    // ---- everything below needs a login
    const s = getSession(req, url);
    if (!s) return json(res, 401, { error: 'Please log in' });

    if (route === 'GET /api/me') return json(res, 200, { username: s.username });

    if (route === 'POST /api/logout') {
      destroySession(s);
      return json(res, 200, { ok: true });
    }

    // ---- live updates (Server-Sent Events)
    if (route === 'GET /api/events') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
        'X-Accel-Buffering': 'no',
      });
      res.write(': connected\n\n');
      clearTimeout(s.timer);
      s.streams.add(res);
      if (!s.room) createRoom(s);       // came back after the grace period -> fresh code
      send(s, 'state', roomState(s.room));
      req.on('close', () => {
        s.streams.delete(res);
        if (s.streams.size === 0 && sessions.get(s.token) === s) {
          s.timer = setTimeout(() => leaveRoom(s), GRACE_MS); // tab closed -> leave soon
        }
      });
      return;
    }

    // ---- join someone else's code
    if (route === 'POST /api/join') {
      const body = await readBody(req);
      const now = Date.now();
      s.fails = s.fails.filter(t => now - t < 60 * 1000);
      if (s.fails.length >= 10) return json(res, 429, { error: 'Too many wrong codes. Wait a minute.' });
      const code = String(body.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
      const room = rooms.get(code);
      if (!room) { s.fails.push(now); return json(res, 404, { error: 'No room with that code' }); }
      if (room === s.room) return json(res, 400, { error: 'You are already in this room' });
      if (room.members.length >= MAX_PER_ROOM) return json(res, 409, { error: 'That room is full (' + MAX_PER_ROOM + '/' + MAX_PER_ROOM + ')' });
      leaveRoom(s);                     // your old code is erased if you were alone
      joinRoom(s, room);
      return json(res, 200, { ok: true });
    }

    // ---- leave and get a brand-new code
    if (route === 'POST /api/newroom') {
      leaveRoom(s);
      const room = createRoom(s);
      send(s, 'state', roomState(room));
      send(s, 'system', { text: 'New room created. Share the code to invite people.' });
      return json(res, 200, { ok: true });
    }

    // ---- send a chat message
    if (route === 'POST /api/send') {
      const body = await readBody(req);
      const text = String(body.text || '').trim().slice(0, 500);
      if (!text) return json(res, 400, { error: 'Empty message' });
      const now = Date.now();
      if (now - s.lastMsg < 250) return json(res, 429, { error: 'Slow down a little' });
      s.lastMsg = now;
      if (!s.room) return json(res, 400, { error: 'You are not in a room' });
      broadcast(s.room, 'message', { from: s.username, text, ts: now });
      return json(res, 200, { ok: true });
    }

    json(res, 404, { error: 'Not found' });
  } catch (e) {
    if (!res.headersSent) json(res, 400, { error: 'Bad request' });
  }
});

// keep SSE connections alive and clean up old sessions
setInterval(() => {
  for (const s of sessions.values()) {
    if (s.expires < Date.now()) destroySession(s);
    else for (const res of s.streams) res.write(': ping\n\n');
  }
}, 25 * 1000);

server.on('error', err => {
  if (err.code === 'EADDRINUSE') {
    console.log('Port ' + PORT + ' is already in use (maybe QuadChat is already running in another terminal).');
    console.log('Close that one, or use another port:');
    console.log('  Windows PowerShell:  $env:PORT=3001; node server.js');
    console.log('  Mac / Linux:         PORT=3001 node server.js');
  } else {
    console.log(err);
  }
  process.exit(1);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('QuadChat running:  http://localhost:' + PORT);
  console.log('Friends on your Wi-Fi can use:  http://<your-PC-IP>:' + PORT);
  console.log('Open that address in your browser (not the .html file).');
});
