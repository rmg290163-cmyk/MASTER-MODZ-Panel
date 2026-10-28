#!/usr/bin/env node
/**
 * ============================================================
 *  MASTER MODZ PANEL — bot.js
 *  Single-file Node.js panel (ZERO dependencies — sirf Node.js chahiye)
 *
 *  Chalane ka tarika:
 *    node bot.js
 *    → http://localhost:3000
 *
 *  Login Password: anshika2meet  (kmj-data.json me edit kar sakte ho)
 *  Port badalna ho: PORT=8080 node bot.js
 * ============================================================
 */

'use strict'

const http = require('http')
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')

// ======================= CONFIG =======================
const PORT = parseInt(process.env.PORT || '3000', 10)
const DATA_FILE = path.join(__dirname, 'kmj-data.json')
const DEFAULT_PASSWORD = 'anshika2meet'

// ======================= STORAGE (JSON file) =======================
let db = null

function defaultDB () {
  return {
    secret: crypto.randomBytes(24).toString('hex'),
    password: DEFAULT_PASSWORD,
    settings: { appName: 'MASTER MODZ APP', packageName: 'com.master.modapp', apiUrl: '' },
    updates: [],
    keys: [],
    logs: [],
    announcement: { message: '', type: 'INFO', isActive: false }
  }
}

function loadDB () {
  try {
    if (fs.existsSync(DATA_FILE)) {
      db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'))
      const def = defaultDB()
      for (const k of Object.keys(def)) if (db[k] === undefined) db[k] = def[k]
      return
    }
  } catch (e) {
    console.error('[MASTER] Data file padhne me error, fresh bana rahe hai:', e.message)
  }
  db = defaultDB()
  saveDB()
}

function saveDB () {
  const tmp = DATA_FILE + '.tmp'
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2))
  fs.renameSync(tmp, DATA_FILE)
}

function uid () {
  return 'k' + Date.now().toString(36) + crypto.randomBytes(5).toString('hex')
}

// ======================= HELPERS =======================
function send (res, status, obj) {
  const body = JSON.stringify(obj)
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Days',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS'
  })
  res.end(body)
}

function readBody (req) {
  return new Promise((resolve) => {
    let data = ''
    req.on('data', (c) => { data += c; if (data.length > 1e6) req.destroy() })
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}) } catch { resolve({}) }
    })
    req.on('error', () => resolve({}))
  })
}

function sign (payload) {
  const p = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const s = crypto.createHmac('sha256', db.secret).update(p).digest('base64url')
  return p + '.' + s
}

function verify (token) {
  if (!token) return false
  const parts = String(token).split('.')
  if (parts.length !== 2) return false
  const expect = crypto.createHmac('sha256', db.secret).update(parts[0]).digest('base64url')
  try {
    if (!crypto.timingSafeEqual(Buffer.from(parts[1]), Buffer.from(expect))) return false
    const data = JSON.parse(Buffer.from(parts[0], 'base64url').toString())
    return Date.now() - data.t < 30 * 24 * 60 * 60 * 1000
  } catch { return false }
}

function auth (req) {
  const h = req.headers.authorization || ''
  const token = h.startsWith('Bearer ') ? h.slice(7) : null
  return verify(token)
}

const KEY_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
function generateKey (prefix) {
  const seg = (n) => {
    let s = ''
    for (let i = 0; i < n; i++) s += KEY_CHARS[crypto.randomInt(0, KEY_CHARS.length)]
    return s
  }
  const p = (prefix || 'MASTER').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 6) || 'MASTER'
  return p + '-' + seg(4) + '-' + seg(4) + '-' + seg(4)
}

function planToDate (plan) {
  const now = Date.now()
  switch (plan) {
    case 'DAY': return now + 1 * 86400000
    case 'WEEK': return now + 7 * 86400000
    case 'MONTH': return now + 30 * 86400000
    default: return now + 86400000
  }
}

function addLog (deviceId, deviceName, action, detail, keyUsed) {
  db.logs.unshift({
    id: uid(),
    deviceId: String(deviceId).slice(0, 100),
    deviceName: String(deviceName || '').slice(0, 60) || null,
    action,
    detail,
    keyUsed: keyUsed || null,
    createdAt: Date.now()
  })
  if (db.logs.length > 2000) db.logs.length = 2000
}

// ======================= APP APIs (dex contract — same as before) =======================

// GET /api/app/update?vc=N
function appUpdate (req, res, q) {
  const currentVc = parseInt(q.get('vc') || '0', 10) || 0
  const list = db.updates.filter((u) => u.isActive)
  if (!list.length) return send(res, 200, { hasUpdate: false, message: 'No updates available' })
  const update = list.reduce((a, b) => (b.versionCode > a.versionCode ? b : a))
  send(res, 200, {
    hasUpdate: update.versionCode > currentVc,
    version: update.version,
    versionCode: update.versionCode,
    changelog: update.changelog,
    downloadUrl: update.downloadUrl,
    force: !!update.isForced
  })
}

// POST /api/app/verify-key  { key, deviceId, deviceName }
function appVerifyKey (req, res, body) {
  const key = body.key
  const deviceId = body.deviceId
  const deviceName = body.deviceName || ''
  if (!key || !deviceId) return send(res, 400, { valid: false, message: 'Key and Device ID required' })

  const cleanKey = String(key).trim().toUpperCase()
  const license = db.keys.find((k) => k.key === cleanKey)

  if (!license) {
    addLog(deviceId, deviceName, 'REJECTED', 'Invalid key entered', cleanKey)
    saveDB()
    return send(res, 200, { valid: false, code: 'INVALID', message: 'Invalid license key' })
  }

  if (license.status === 'BLOCKED') {
    addLog(deviceId, deviceName, 'BLOCKED', 'Blocked key tried to login', cleanKey)
    saveDB()
    return send(res, 200, { valid: false, code: 'BLOCKED', message: 'This key has been blocked by admin' })
  }

  if (license.status === 'UNUSED') {
    const expiry = license.plan === 'LIFETIME' ? null : planToDate(license.plan)
    license.status = 'ACTIVE'
    license.deviceId = String(deviceId).slice(0, 100)
    license.deviceName = String(deviceName || '').slice(0, 60) || null
    license.activatedAt = Date.now()
    license.expiresAt = expiry
    addLog(deviceId, deviceName, 'ACTIVATED', 'Key activated on ' + (deviceName || 'unknown device'), cleanKey)
    saveDB()
    return send(res, 200, {
      valid: true, code: 'ACTIVATED', plan: license.plan,
      expiresAt: expiry, message: 'Key activated successfully'
    })
  }

  if (license.deviceId !== String(deviceId).slice(0, 100)) {
    addLog(deviceId, deviceName, 'REJECTED', 'Key used on another device', cleanKey)
    saveDB()
    return send(res, 200, { valid: false, code: 'DEVICE_MISMATCH', message: 'Key is already used on another device' })
  }

  if (license.expiresAt && license.expiresAt < Date.now()) {
    license.status = 'BLOCKED'
    addLog(deviceId, deviceName, 'EXPIRED', 'Key expired', cleanKey)
    saveDB()
    return send(res, 200, { valid: false, code: 'EXPIRED', message: 'Your key has expired. Contact admin.' })
  }

  addLog(deviceId, deviceName, 'VERIFIED', 'Key verified successfully', cleanKey)
  saveDB()
  send(res, 200, {
    valid: true, code: 'OK', plan: license.plan,
    expiresAt: license.expiresAt, message: 'License verified'
  })
}

// GET /api/app/announcement
function appAnnouncement (res) {
  const a = db.announcement
  if (!a || !a.isActive || !(a.message || '').trim()) {
    return send(res, 200, { active: false, message: '', type: 'INFO' })
  }
  send(res, 200, { active: true, message: a.message, type: a.type })
}

// ======================= ADMIN APIs =======================

function adminLogin (req, res, body) {
  if (!body.password) return send(res, 400, { error: 'Password required' })
  if (String(body.password) !== db.password) {
    return send(res, 401, { error: 'Galat password! Dobara try karo' })
  }
  send(res, 200, { token: sign({ u: 'admin', t: Date.now() }), username: 'admin', isFirstSetup: false })
}

function adminStats (res) {
  const now = Date.now()
  const activeKeys = db.keys.filter((k) => k.status === 'ACTIVE')
  const stats = {
    totalKeys: db.keys.length,
    activeKeys: activeKeys.length,
    unusedKeys: db.keys.filter((k) => k.status === 'UNUSED').length,
    blockedKeys: db.keys.filter((k) => k.status === 'BLOCKED').length,
    activeDevices: activeKeys.filter((k) => k.deviceId && (!k.expiresAt || k.expiresAt > now)).length,
    totalDevices: db.logs.length,
    latestVersion: db.updates.length ? db.updates[0].version : null,
    latestVersionCode: db.updates.length ? db.updates[0].versionCode : null,
    announcementActive: !!(db.announcement && db.announcement.isActive)
  }
  send(res, 200, { stats, recentLogs: db.logs.slice(0, 8) })
}

// ---- KEYS ----
function adminKeysList (res) {
  send(res, 200, { keys: db.keys })
}

function adminKeysCreate (res, body) {
  const n = Math.min(Math.max(parseInt(body.count, 10) || 1, 1), 100)
  const plan = body.plan || 'DAY'
  const made = []
  for (let i = 0; i < n; i++) {
    const key = generateKey(body.prefix || 'KMJ')
    db.keys.unshift({ id: uid(), key, plan, status: 'UNUSED', deviceId: null, deviceName: null, activatedAt: null, expiresAt: null, createdAt: Date.now() })
    made.push(key)
  }
  saveDB()
  send(res, 200, { created: made.length, keys: made })
}

function adminKeysPatch (res, body) {
  const { id, action } = body
  if (!id || !action) return send(res, 400, { error: 'ID and action required' })
  const key = db.keys.find((k) => k.id === id)
  if (!key) return send(res, 404, { error: 'Key not found' })

  switch (action) {
    case 'block':
      key.status = 'BLOCKED'
      break
    case 'unblock':
      key.status = key.deviceId ? 'ACTIVE' : 'UNUSED'
      break
    case 'reset-device':
      key.deviceId = null; key.deviceName = null; key.activatedAt = null; key.expiresAt = null; key.status = 'UNUSED'
      break
    case 'renew': {
      const days = parseInt(body.days, 10) || 30
      const base = key.expiresAt && key.expiresAt > Date.now() ? key.expiresAt : Date.now()
      key.expiresAt = base + days * 24 * 60 * 60 * 1000
      key.status = 'ACTIVE'
      break
    }
    default:
      return send(res, 400, { error: 'Unknown action' })
  }
  saveDB()
  send(res, 200, { ok: true })
}

function adminKeysDelete (res, id) {
  if (!id) return send(res, 400, { error: 'ID required' })
  db.keys = db.keys.filter((k) => k.id !== id)
  saveDB()
  send(res, 200, { ok: true })
}

// ---- UPDATES ----
function adminUpdatesList (res) {
  const updates = db.updates.slice().sort((a, b) => ((b.isActive - a.isActive) || (b.versionCode - a.versionCode)))
  send(res, 200, { updates })
}

function adminUpdatesCreate (res, body) {
  const { version, versionCode, changelog, downloadUrl, isForced } = body
  if (!version || !versionCode || !downloadUrl) {
    return send(res, 400, { error: 'Version, versionCode and downloadUrl are required' })
  }
  db.updates.forEach((u) => { u.isActive = false })
  const update = {
    id: uid(),
    version: String(version),
    versionCode: parseInt(versionCode, 10) || 1,
    changelog: changelog || '',
    downloadUrl,
    isForced: !!isForced,
    isActive: true,
    createdAt: Date.now(),
    updatedAt: Date.now()
  }
  db.updates.unshift(update)
  saveDB()
  send(res, 200, { update })
}

function adminUpdatesPatch (res, body) {
  const { id, action, version, versionCode, changelog, downloadUrl, isForced } = body
  if (!id) return send(res, 400, { error: 'ID required' })
  const update = db.updates.find((u) => u.id === id)
  if (!update) return send(res, 404, { error: 'Not found' })

  if (action === 'toggle-active') {
    if (!update.isActive) {
      db.updates.forEach((u) => { u.isActive = false })
      update.isActive = true
    } else {
      update.isActive = false
    }
    saveDB()
    return send(res, 200, { ok: true })
  }

  if (version !== undefined) update.version = version
  if (versionCode !== undefined) update.versionCode = parseInt(versionCode, 10) || update.versionCode
  if (changelog !== undefined) update.changelog = changelog
  if (downloadUrl !== undefined) update.downloadUrl = downloadUrl
  if (isForced !== undefined) update.isForced = !!isForced
  update.updatedAt = Date.now()
  saveDB()
  send(res, 200, { update })
}

function adminUpdatesDelete (res, id) {
  if (!id) return send(res, 400, { error: 'ID required' })
  db.updates = db.updates.filter((u) => u.id !== id)
  saveDB()
  send(res, 200, { ok: true })
}

// ---- DEVICES / ANNOUNCEMENT / SETTINGS ----
function adminDevices (res) {
  send(res, 200, { logs: db.logs.slice(0, 200) })
}

function adminAnnouncementGet (res) {
  send(res, 200, { announcement: db.announcement })
}

function adminAnnouncementPatch (res, body) {
  const a = db.announcement
  a.message = body.message !== undefined ? body.message : a.message
  a.type = body.type !== undefined ? body.type : a.type
  a.isActive = body.isActive !== undefined ? !!body.isActive : a.isActive
  saveDB()
  send(res, 200, { announcement: a })
}

function adminSettingsGet (res) {
  send(res, 200, { settings: db.settings })
}

function adminSettingsPatch (res, body) {
  const s = db.settings
  if (body.appName !== undefined) s.appName = body.appName
  if (body.packageName !== undefined) s.packageName = body.packageName
  if (body.apiUrl !== undefined) s.apiUrl = body.apiUrl
  saveDB()
  send(res, 200, { settings: s })
}

// ======================= ROUTER =======================
async function handle (req, res) {
  const u = new URL(req.url, 'http://x')
  const p = u.pathname
  const q = u.searchParams

  if (req.method === 'OPTIONS') return send(res, 200, { ok: true })

  // ---------- APP APIs (Android dex inhi ko call karta hai) ----------
  if (p === '/api/app/update' && req.method === 'GET') return appUpdate(req, res, q)
  if (p === '/api/app/verify-key' && req.method === 'POST') return appVerifyKey(req, res, await readBody(req))
  if (p === '/api/app/announcement' && req.method === 'GET') return appAnnouncement(res)

  // ---------- ADMIN APIs ----------
  if (p === '/api/admin/login' && req.method === 'POST') return adminLogin(req, res, await readBody(req))
  if (p === '/api/admin/status' && req.method === 'GET') return send(res, 200, { hasAdmin: true })

  const needAuth = p.startsWith('/api/admin/')
  if (needAuth && !auth(req)) return send(res, 401, { error: 'Unauthorized' })

  const body = (req.method === 'POST' || req.method === 'PATCH') ? await readBody(req) : {}

  if (p === '/api/admin/stats' && req.method === 'GET') return adminStats(res)

  if (p === '/api/admin/keys') {
    if (req.method === 'GET') return adminKeysList(res)
    if (req.method === 'POST') return adminKeysCreate(res, body)
    if (req.method === 'PATCH') return adminKeysPatch(res, body)
    if (req.method === 'DELETE') return adminKeysDelete(res, q.get('id'))
  }

  if (p === '/api/admin/updates') {
    if (req.method === 'GET') return adminUpdatesList(res)
    if (req.method === 'POST') return adminUpdatesCreate(res, body)
    if (req.method === 'PATCH') return adminUpdatesPatch(res, body)
    if (req.method === 'DELETE') return adminUpdatesDelete(res, q.get('id'))
  }

  if (p === '/api/admin/devices' && req.method === 'GET') return adminDevices(res)
  if (p === '/api/admin/announcement' && req.method === 'GET') return adminAnnouncementGet(res)
  if (p === '/api/admin/announcement' && req.method === 'PATCH') return adminAnnouncementPatch(res, body)
  if (p === '/api/admin/settings' && req.method === 'GET') return adminSettingsGet(res)
  if (p === '/api/admin/settings' && req.method === 'PATCH') return adminSettingsPatch(res, body)

  // ---------- PANEL UI ----------
  if (req.method === 'GET' && (p === '/' || p === '/panel')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' })
    return res.end(PANEL_HTML)
  }

  send(res, 404, { error: 'Not found' })
}

// ======================= PANEL UI (embedded single-page app) =======================
const PANEL_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MASTER MODZ PANEL</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
:root{
  --bg:#0b0b1a;--card:#15122b;--card2:#1a1636;--line:rgba(168,85,247,.28);
  --purple:#a855f7;--cyan:#22d3ee;--pink:#f472b6;--green:#34d399;--red:#fb7185;--orange:#fbbf24;
  --text:#f4f4fa;--muted:#8b8aa0;
}
body{
  font-family:'Segoe UI',system-ui,-apple-system,Roboto,sans-serif;background:var(--bg);color:var(--text);
  min-height:100vh;background-image:
    radial-gradient(60rem 40rem at 110% -10%,rgba(168,85,247,.13),transparent 60%),
    radial-gradient(50rem 35rem at -10% 110%,rgba(34,211,238,.10),transparent 60%);
}
.hidden{display:none!important}
button{font-family:inherit;cursor:pointer;border:none}
input,select,textarea{font-family:inherit;outline:none}
::placeholder{color:#55556e}

/* ---------- rotating neon border ---------- */
.neon{position:relative;border-radius:18px;padding:1.5px;overflow:hidden;background:rgba(168,85,247,.15)}
.neon::before{content:"";position:absolute;inset:-120%;
  background:conic-gradient(from 0deg,rgba(168,85,247,.12) 0deg,rgba(168,85,247,.12) 190deg,#a855f7 235deg,#22d3ee 285deg,#f472b6 325deg,rgba(168,85,247,.12) 360deg);
  animation:nrot 4s linear infinite}
.neon-in{position:relative;border-radius:16.5px;background:var(--card);height:100%}
@keyframes nrot{to{transform:rotate(1turn)}}
.neon-slow::before{animation-duration:7s}

/* ---------- login ---------- */
#login-screen{display:flex;min-height:100vh;align-items:center;justify-content:center;padding:18px}
.login-wrap{width:100%;max-width:400px;text-align:center}
.logo-box{width:82px;height:82px;margin:0 auto 20px;border-radius:22px;display:flex;align-items:center;justify-content:center;animation:float 3.2s ease-in-out infinite}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-9px)}}
.logo-zap{width:38px;height:38px;filter:drop-shadow(0 0 10px #a855f7)}
h1.title{font-size:30px;font-weight:900;letter-spacing:-.5px}
h1.title .np{background:linear-gradient(90deg,#a855f7,#f472b6);-webkit-background-clip:text;background-clip:text;color:transparent}
h1.title .nt{color:#e4e4f4}
.subtitle{margin-top:7px;font-size:13px;color:var(--muted)}
.login-card{margin-top:26px;text-align:left}
.login-card .neon-in{padding:26px}
.f-label{display:block;font-size:11px;font-weight:700;letter-spacing:1.5px;color:#a9a8c0;margin-bottom:8px;text-transform:uppercase}
.f-input{width:100%;border-radius:12px;border:1px solid rgba(120,110,190,.4);background:rgba(20,17,40,.7);
  padding:13px 15px;font-size:14px;color:var(--text);transition:.2s}
.f-input:focus{border-color:var(--purple);box-shadow:0 0 0 3px rgba(168,85,247,.18)}
.btn-neon{width:100%;border-radius:12px;padding:14px;font-size:14px;font-weight:800;color:#0b0b1a;
  background:linear-gradient(90deg,#a855f7,#22d3ee);transition:.2s;letter-spacing:.3px}
.btn-neon:hover{filter:brightness(1.15);box-shadow:0 6px 22px rgba(168,85,247,.4)}
.btn-neon:disabled{opacity:.6;cursor:wait}
.login-hint{margin-top:14px;font-size:11px;color:#6d6c85;text-align:center}

/* ---------- app shell ---------- */
header{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;max-width:1100px;margin:0 auto}
.brand{font-weight:900;font-size:19px;letter-spacing:-.3px}
.brand .np{background:linear-gradient(90deg,#a855f7,#f472b6);-webkit-background-clip:text;background-clip:text;color:transparent}
.brand .nt{color:#e4e4f4;font-weight:700}
.brand small{display:block;font-size:10.5px;color:var(--muted);font-weight:600;letter-spacing:1.5px;margin-top:2px}
.btn-ghost{border-radius:10px;padding:9px 16px;font-size:12.5px;font-weight:700;color:#cfcfe6;
  background:var(--card2);border:1px solid rgba(168,85,247,.35);transition:.2s}
.btn-ghost:hover{border-color:var(--purple);color:#fff;box-shadow:0 0 14px rgba(168,85,247,.25)}

nav#tabs{display:flex;gap:6px;max-width:1100px;margin:2px auto 0;padding:0 20px 14px;overflow-x:auto;scrollbar-width:none}
nav#tabs::-webkit-scrollbar{display:none}
.tab{flex-shrink:0;border-radius:11px;padding:10px 16px;font-size:13px;font-weight:700;color:#9b9ab5;
  background:var(--card2);border:1px solid rgba(120,110,190,.25);transition:.2s}
.tab:hover{color:#e4e4f4}
.tab.active{color:#fff;background:linear-gradient(90deg,rgba(168,85,247,.25),rgba(34,211,238,.18));
  border-color:var(--purple);box-shadow:0 0 16px rgba(168,85,247,.28)}

main{max-width:1100px;margin:0 auto;padding:6px 20px 60px}
section.tabpane{display:none}
section.tabpane.active{display:block}
.pane-title{font-size:16px;font-weight:800;margin:14px 0 12px;display:flex;align-items:center;gap:9px}
.pane-title .dot{width:8px;height:8px;border-radius:99px;background:linear-gradient(90deg,var(--purple),var(--cyan));box-shadow:0 0 8px var(--purple)}

.card{border-radius:16px;background:var(--card);border:1px solid rgba(168,85,247,.22);padding:18px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:840px){.grid2{grid-template-columns:1fr}}

/* ---------- dashboard ---------- */
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
@media(max-width:840px){.stat-grid{grid-template-columns:repeat(2,1fr)}}
.stat{border-radius:15px;background:var(--card);border:1px solid rgba(168,85,247,.22);padding:16px;position:relative;overflow:hidden;transition:.2s}
.stat:hover{transform:translateY(-3px);box-shadow:0 10px 26px rgba(0,0,0,.45);border-color:rgba(168,85,247,.5)}
.stat .sk{font-size:10.5px;font-weight:800;letter-spacing:1.4px;color:var(--muted);text-transform:uppercase}
.stat .sv{font-size:30px;font-weight:900;margin-top:7px;background:linear-gradient(90deg,#fff,#c9c6ee);-webkit-background-clip:text;background-clip:text;color:transparent}
.stat .ss{font-size:11px;color:#6d6c85;margin-top:4px}
.stat::after{content:"";position:absolute;right:-18px;top:-18px;width:64px;height:64px;border-radius:99px;opacity:.16;background:linear-gradient(135deg,var(--purple),var(--cyan));filter:blur(2px)}
.loglist{display:flex;flex-direction:column;gap:9px;margin-top:6px}
.logrow{display:flex;gap:11px;align-items:flex-start;padding:11px 13px;border-radius:12px;background:var(--card2);border:1px solid rgba(120,110,190,.18)}
.logrow .ld{flex:1;min-width:0}
.logrow .lt1{font-size:13px;font-weight:700}
.logrow .lt2{font-size:11.5px;color:var(--muted);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.logrow .lw{font-size:10.5px;color:#6d6c85;white-space:nowrap}

.badge{display:inline-block;border-radius:7px;padding:2.5px 8px;font-size:10px;font-weight:800;letter-spacing:.6px}
.b-VERIFIED{color:#34d399;background:rgba(52,211,153,.12);border:1px solid rgba(52,211,153,.4)}
.b-ACTIVATED{color:#22d3ee;background:rgba(34,211,238,.12);border:1px solid rgba(34,211,238,.4)}
.b-REJECTED{color:#fb7185;background:rgba(251,113,133,.12);border:1px solid rgba(251,113,133,.4)}
.b-BLOCKED{color:#fbbf24;background:rgba(251,191,36,.12);border:1px solid rgba(251,191,36,.4)}
.b-EXPIRED{color:#9b9ab5;background:rgba(155,154,181,.12);border:1px solid rgba(155,154,181,.4)}

/* ---------- keys ---------- */
.gen-form{display:grid;grid-template-columns:1.1fr .7fr 1fr auto;gap:10px;align-items:end}
@media(max-width:840px){.gen-form{grid-template-columns:1fr 1fr}}
.tbl-wrap{overflow-x:auto;margin-top:16px;border-radius:14px;border:1px solid rgba(168,85,247,.2)}
table{width:100%;border-collapse:collapse;min-width:760px}
th{font-size:10.5px;letter-spacing:1.2px;text-transform:uppercase;color:var(--muted);text-align:left;
  padding:11px 13px;background:rgba(168,85,247,.08);border-bottom:1px solid rgba(168,85,247,.22)}
td{padding:11px 13px;font-size:12.5px;border-bottom:1px solid rgba(120,110,190,.13);vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(168,85,247,.05)}
.keycode{font-family:Consolas,'Courier New',monospace;font-weight:700;color:#e4e4f4;letter-spacing:.5px}
.st-UNUSED{color:#9b9ab5}.st-ACTIVE{color:#34d399;font-weight:700}.st-BLOCKED{color:#fb7185;font-weight:700}
.mini{border-radius:8px;padding:6px 10px;font-size:11px;font-weight:700;background:var(--card2);
  color:#cfcfe6;border:1px solid rgba(120,110,190,.35);transition:.15s;margin:2px 3px 2px 0}
.mini:hover{border-color:var(--purple);color:#fff}
.mini.danger:hover{border-color:var(--red);color:var(--red)}
.mini.good:hover{border-color:var(--green);color:var(--green)}

/* ---------- updates ---------- */
.u-item{border-radius:14px;background:var(--card2);border:1px solid rgba(120,110,190,.2);padding:15px;margin-top:12px}
.u-top{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.u-ver{font-size:16px;font-weight:900}
.u-vc{font-size:11px;color:var(--muted)}
.pill{border-radius:99px;padding:3px 11px;font-size:10.5px;font-weight:800}
.pill.on{color:#34d399;background:rgba(52,211,153,.12);border:1px solid rgba(52,211,153,.4)}
.pill.off{color:#9b9ab5;background:rgba(155,154,181,.1);border:1px solid rgba(155,154,181,.35)}
.pill.force{color:#fbbf24;background:rgba(251,191,36,.12);border:1px solid rgba(251,191,36,.4)}
.u-cl{font-size:12.5px;color:#b9b8d4;margin-top:8px;white-space:pre-wrap}
.u-url{font-size:11.5px;color:#22d3ee;word-break:break-all;margin-top:6px}
.check{display:flex;align-items:center;gap:8px;font-size:13px;color:#cfcfe6;cursor:pointer;user-select:none}
.check input{width:16px;height:16px;accent-color:#a855f7}

/* ---------- announcement ---------- */
#ann-preview{border-radius:13px;padding:14px 16px;font-size:13.5px;border:1px solid;display:none;margin-top:10px}
#ann-preview.show{display:block}
.pv-INFO{color:#22d3ee;border-color:rgba(34,211,238,.4);background:rgba(34,211,238,.07)}
.pv-SUCCESS{color:#34d399;border-color:rgba(52,211,153,.4);background:rgba(52,211,153,.07)}
.pv-WARNING{color:#fbbf24;border-color:rgba(251,191,36,.4);background:rgba(251,191,36,.07)}

/* ---------- toast (MASTER 4D style) ---------- */
#toast-box{position:fixed;top:16px;right:16px;z-index:999;display:flex;flex-direction:column;gap:10px;perspective:900px;pointer-events:none}
.toast{min-width:270px;max-width:340px;border-radius:14px;background:rgba(23,18,46,.97);padding:13px 15px;
  border:1px solid var(--purple);box-shadow:0 10px 34px rgba(0,0,0,.55),0 0 20px rgba(168,85,247,.3);
  animation:tin .5s cubic-bezier(.2,.9,.3,1.25)}
.toast .tt{font-weight:800;font-size:13.5px;display:flex;align-items:center;gap:8px}
.toast .tm{font-size:12px;color:#9b9ab5;margin-top:4px;line-height:1.45}
.toast .bar{height:3px;border-radius:99px;margin-top:9px;background:linear-gradient(90deg,var(--purple),var(--cyan));transform-origin:left;animation:tbar 3.3s linear forwards}
.toast.success{border-color:rgba(52,211,153,.7);box-shadow:0 10px 34px rgba(0,0,0,.55),0 0 20px rgba(52,211,153,.28)}
.toast.success .bar{background:linear-gradient(90deg,#34d399,#22d3ee)}
.toast.error{border-color:rgba(251,113,133,.7);box-shadow:0 10px 34px rgba(0,0,0,.55),0 0 20px rgba(251,113,133,.28)}
.toast.error .bar{background:linear-gradient(90deg,#fb7185,#f472b6)}
.toast.warning{border-color:rgba(251,191,36,.7);box-shadow:0 10px 34px rgba(0,0,0,.55),0 0 20px rgba(251,191,36,.28)}
.toast.warning .bar{background:linear-gradient(90deg,#fbbf24,#fb7185)}
.toast.out{animation:tout .3s ease forwards}
@keyframes tin{from{opacity:0;transform:translateX(70px) rotateY(-28deg) rotateX(12deg) scale(.85)}to{opacity:1;transform:none}}
@keyframes tout{to{opacity:0;transform:translateX(70px) rotateY(20deg) scale(.88)}}
@keyframes tbar{to{transform:scaleX(0)}}

.empty{text-align:center;color:#6d6c85;font-size:13px;padding:34px 10px}
.mt10{margin-top:10px}.mt16{margin-top:16px}.mut{color:var(--muted);font-size:12px}
</style>
</head>
<body>

<!-- ================= LOGIN ================= -->
<div id="login-screen">
  <div class="login-wrap">
    <div class="logo-box neon neon-slow"><div class="neon-in" style="display:flex;align-items:center;justify-content:center;width:100%;height:100%">
      <svg class="logo-zap" viewBox="0 0 24 24" fill="none" stroke="#a855f7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
    </div></div>
    <h1 class="title"><span class="np">MASTER MODZ</span> <span class="nt">PANEL</span></h1>
    <div class="subtitle">App Control Center &mdash; single file edition</div>
    <div class="login-card neon"><div class="neon-in">
      <form id="login-form">
        <label class="f-label" for="login-pass">Password</label>
        <input class="f-input" type="password" id="login-pass" placeholder="Enter panel password" autocomplete="current-password" autofocus>
        <button class="btn-neon mt16" id="login-btn" type="submit">Login to Panel</button>
        <div class="login-hint">Protected area &mdash; authorized admins only</div>
      </form>
    </div></div>
  </div>
</div>

<!-- ================= MAIN APP ================= -->
<div id="app-screen" class="hidden">
  <header>
    <div class="brand"><span class="np">MASTER MODZ</span> <span class="nt">APP PANEL</span>
      <small id="hdr-sub">CONTROL CENTER</small></div>
    <button class="btn-ghost" id="logout-btn">Logout</button>
  </header>

  <nav id="tabs">
    <button class="tab active" data-tab="dash">Dashboard</button>
    <button class="tab" data-tab="keys">Keys</button>
    <button class="tab" data-tab="updates">Updates</button>
    <button class="tab" data-tab="devices">Devices</button>
    <button class="tab" data-tab="announce">Announcement</button>
    <button class="tab" data-tab="settings">Settings</button>
  </nav>

  <main>
    <!-- DASHBOARD -->
    <section class="tabpane active" id="tab-dash">
      <div class="stat-grid" id="stat-grid"></div>
      <div class="pane-title mt16"><span class="dot"></span>Recent Activity</div>
      <div class="loglist" id="recent-logs"></div>
    </section>

    <!-- KEYS -->
    <section class="tabpane" id="tab-keys">
      <div class="card">
        <div class="pane-title" style="margin-top:0"><span class="dot"></span>Generate Keys</div>
        <div class="gen-form">
          <div>
            <label class="f-label">Plan</label>
            <select class="f-input" id="k-plan">
              <option value="DAY">1 Day</option>
              <option value="WEEK">7 Days</option>
              <option value="MONTH" selected>30 Days</option>
              <option value="LIFETIME">Lifetime</option>
            </select>
          </div>
          <div>
            <label class="f-label">Count</label>
            <input class="f-input" type="number" id="k-count" value="1" min="1" max="100">
          </div>
          <div>
            <label class="f-label">Prefix</label>
            <input class="f-input" id="k-prefix" value="KMJ" maxlength="6">
          </div>
          <button class="btn-neon" id="k-gen" style="width:auto;padding:13px 22px">Generate</button>
        </div>
        <div id="k-made" class="mt10"></div>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead><tr><th>Key</th><th>Plan</th><th>Status</th><th>Device</th><th>Expires</th><th>Actions</th></tr></thead>
          <tbody id="keys-tbody"></tbody>
        </table>
      </div>
    </section>

    <!-- UPDATES -->
    <section class="tabpane" id="tab-updates">
      <div class="card">
        <div class="pane-title" style="margin-top:0"><span class="dot"></span>Publish Update</div>
        <div class="gen-form" style="grid-template-columns:1fr .6fr 1.6fr auto">
          <div>
            <label class="f-label">Version</label>
            <input class="f-input" id="u-version" placeholder="2.1">
          </div>
          <div>
            <label class="f-label">Version Code</label>
            <input class="f-input" type="number" id="u-vc" placeholder="3">
          </div>
          <div>
            <label class="f-label">Download URL</label>
            <input class="f-input" id="u-url" placeholder="https://... ">
          </div>
          <button class="btn-neon" id="u-add" style="width:auto;padding:13px 22px">Publish</button>
        </div>
        <label class="f-label" style="margin-top:12px">Changelog</label>
        <textarea class="f-input" id="u-cl" rows="2" placeholder="What is new..."></textarea>
        <label class="check mt10"><input type="checkbox" id="u-force" checked> Force update — NO cancel button, app tab tak band rahega jab tak user naya version install na kare</label>
      </div>
      <div id="u-list"></div>
    </section>

    <!-- DEVICES -->
    <section class="tabpane" id="tab-devices">
      <div class="tbl-wrap" style="margin-top:14px">
        <table>
          <thead><tr><th>Time</th><th>Action</th><th>Device</th><th>Detail</th><th>Key</th></tr></thead>
          <tbody id="dev-tbody"></tbody>
        </table>
      </div>
    </section>

    <!-- ANNOUNCEMENT -->
    <section class="tabpane" id="tab-announce">
      <div class="grid2">
        <div class="card">
          <div class="pane-title" style="margin-top:0"><span class="dot"></span>Announcement Editor</div>
          <label class="f-label">Message</label>
          <textarea class="f-input" id="a-msg" rows="4" placeholder="App ke andar users ko jo dikhana hai wo likho..."></textarea>
          <div class="gen-form mt10" style="grid-template-columns:1fr auto">
            <div>
              <label class="f-label">Type</label>
              <select class="f-input" id="a-type">
                <option value="INFO">INFO (blue)</option>
                <option value="SUCCESS">SUCCESS (green)</option>
                <option value="WARNING">WARNING (yellow)</option>
              </select>
            </div>
            <label class="check" style="margin-bottom:10px"><input type="checkbox" id="a-active"> Live</label>
          </div>
          <button class="btn-neon mt16" id="a-save">Save &amp; Go Live</button>
        </div>
        <div class="card">
          <div class="pane-title" style="margin-top:0"><span class="dot"></span>Live Preview</div>
          <div id="ann-preview"></div>
          <p class="mut mt10">Ye message app khulte waqt users ko neon toast me dikhega. Save karte hi turant live ho jata hai.</p>
        </div>
      </div>
    </section>

    <!-- SETTINGS -->
    <section class="tabpane" id="tab-settings">
      <div class="card" style="max-width:560px">
        <div class="pane-title" style="margin-top:0"><span class="dot"></span>App Settings</div>
        <label class="f-label">App Name</label>
        <input class="f-input" id="s-appname">
        <label class="f-label mt10">Package Name</label>
        <input class="f-input" id="s-pkg">
        <p class="mut mt10">Panel ka login password badalne ke liye bot.js ke bagal wali <b>kmj-data.json</b> file me "password" edit karo aur bot.js restart karo.</p>
        <button class="btn-neon mt16" id="s-save">Save Settings</button>
      </div>
    </section>
  </main>
</div>

<div id="toast-box"></div>
<script>
/* ================= MASTER PANEL CLIENT ================= */
var $ = function (id) { return document.getElementById(id) }
var token = localStorage.getItem('kmj_token') || ''
var ANN = null

function esc (s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

function fmtTime (t) {
  if (!t) return '-'
  var d = new Date(t)
  function p (n) { return (n < 10 ? '0' : '') + n }
  return d.getDate() + ' ' + ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][d.getMonth()] + ' ' + p(d.getHours()) + ':' + p(d.getMinutes())
}

function fmtDate (t) {
  if (!t) return 'Never'
  var d = new Date(t)
  function p (n) { return (n < 10 ? '0' : '') + n }
  return d.getDate() + ' ' + ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][d.getMonth()] + ' ' + d.getFullYear()
}

/* ---------- toast (MASTER 4D style) ---------- */
var T_ICONS = {
  success: '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#34d399" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M8 12l3 3 5-6"/></svg>',
  error: '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#fb7185" stroke-width="2.4" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>',
  warning: '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/><path d="M12 9v4M12 17h.01"/></svg>',
  neon: '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#a855f7" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>'
}
T_ICONS.info = T_ICONS.neon

function toast (type, title, msg) {
  var box = $('toast-box')
  var el = document.createElement('div')
  el.className = 'toast ' + type
  el.innerHTML = '<div class="tt">' + (T_ICONS[type] || T_ICONS.info) + '<span>' + esc(title) + '</span></div>' +
    (msg ? '<div class="tm">' + esc(msg) + '</div>' : '') + '<div class="bar"></div>'
  box.appendChild(el)
  setTimeout(function () {
    el.classList.add('out')
    setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el) }, 320)
  }, 3400)
}

/* ---------- api ---------- */
function api (path, opts, cb) {
  opts = opts || {}
  var h = { 'Content-Type': 'application/json' }
  if (token) h['Authorization'] = 'Bearer ' + token
  fetch(path, {
    method: opts.method || 'GET',
    headers: h,
    body: opts.body ? JSON.stringify(opts.body) : undefined
  }).then(function (r) {
    return r.json().then(function (d) { return { ok: r.ok, d: d } })
  }).then(function (r) {
    if (r.ok) return cb(null, r.d)
    if (r.d && r.d.error === 'Unauthorized') { logout(); return cb('Unauthorized') }
    cb((r.d && r.d.error) || 'Request failed', r.d)
  }).catch(function () { cb('Network error') })
}

/* ---------- auth ---------- */
$('login-form').addEventListener('submit', function (e) {
  e.preventDefault()
  var pass = $('login-pass').value
  if (!pass) { toast('warning', 'Password missing', 'Pehle password daalo'); return }
  var btn = $('login-btn')
  btn.disabled = true
  fetch('/api/admin/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: pass })
  }).then(function (r) { return r.json() }).then(function (d) {
    btn.disabled = false
    if (d.token) {
      token = d.token
      localStorage.setItem('kmj_token', token)
      toast('success', 'Login successful', 'Welcome back, ' + d.username)
      enterApp()
    } else {
      toast('error', 'Login failed', d.error || 'Galat password')
    }
  }).catch(function () { btn.disabled = false; toast('error', 'Network error', 'Server tak nahi pahunch paye') })
})

function logout () {
  localStorage.removeItem('kmj_token')
  token = ''
  $('app-screen').classList.add('hidden')
  $('login-screen').style.display = 'flex'
}
$('logout-btn').addEventListener('click', function () { logout(); toast('info', 'Logged out', 'Phir aana!') })

function enterApp () {
  $('login-screen').style.display = 'none'
  $('app-screen').classList.remove('hidden')
  refreshAll()
}

/* ---------- tabs ---------- */
var tabs = document.querySelectorAll('.tab')
for (var i = 0; i < tabs.length; i++) {
  tabs[i].addEventListener('click', function () {
    var t = this.getAttribute('data-tab')
    for (var j = 0; j < tabs.length; j++) tabs[j].classList.remove('active')
    this.classList.add('active')
    var panes = document.querySelectorAll('.tabpane')
    for (var k = 0; k < panes.length; k++) panes[k].classList.remove('active')
    $('tab-' + t).classList.add('active')
    if (t === 'dash') loadStats()
    if (t === 'keys') loadKeys()
    if (t === 'updates') loadUpdates()
    if (t === 'devices') loadDevices()
    if (t === 'announce') loadAnn()
    if (t === 'settings') loadSettings()
  })
}

function refreshAll () {
  loadStats(); loadKeys(); loadUpdates(); loadAnn(); loadSettings()
}

/* ---------- dashboard ---------- */
function loadStats () {
  api('/api/admin/stats', {}, function (err, d) {
    if (err) return
    var s = d.stats
    var cards = [
      ['Total Keys', s.totalKeys, s.unusedKeys + ' unused'],
      ['Active Keys', s.activeKeys, s.blockedKeys + ' blocked'],
      ['Live Devices', s.activeDevices, s.totalDevices + ' total logs'],
      ['Live Version', s.latestVersion || '-', s.latestVersionCode ? 'vCode ' + s.latestVersionCode : 'no update yet']
    ]
    var html = ''
    for (var i = 0; i < cards.length; i++) {
      html += '<div class="stat"><div class="sk">' + cards[i][0] + '</div><div class="sv">' + esc(cards[i][1]) + '</div><div class="ss">' + esc(cards[i][2]) + '</div></div>'
    }
    $('stat-grid').innerHTML = html
    var lg = ''
    if (!d.recentLogs.length) lg = '<div class="empty">Abhi koi activity nahi — app se key activate hone ka wait karo</div>'
    for (var j = 0; j < d.recentLogs.length; j++) {
      var L = d.recentLogs[j]
      lg += '<div class="logrow"><div class="ld"><div class="lt1"><span class="badge b-' + esc(L.action) + '">' + esc(L.action) + '</span> ' +
        esc(L.deviceName || L.deviceId) + '</div><div class="lt2">' + esc(L.detail || '') + '</div></div>' +
        '<div class="lw">' + fmtTime(L.createdAt) + '</div></div>'
    }
    $('recent-logs').innerHTML = lg
  })
}

/* ---------- keys ---------- */
function loadKeys () {
  api('/api/admin/keys', {}, function (err, d) {
    if (err) return
    var rows = ''
    if (!d.keys.length) rows = '<tr><td colspan="6"><div class="empty">Koi key nahi — upar se generate karo</div></td></tr>'
    for (var i = 0; i < d.keys.length; i++) {
      var k = d.keys[i]
      var acts = '<button class="mini" onclick="copyKey(\\'' + k.key + '\\')">Copy</button>'
      if (k.status === 'BLOCKED') {
        acts += '<button class="mini good" onclick="keyAction(\\'' + k.id + '\\',\\'unblock\\')">Unblock</button>'
      } else {
        acts += '<button class="mini danger" onclick="keyAction(\\'' + k.id + '\\',\\'block\\')">Block</button>'
      }
      if (k.deviceId) acts += '<button class="mini" onclick="keyAction(\\'' + k.id + '\\',\\'reset-device\\')">Unbind</button>'
      if (k.status === 'ACTIVE') acts += '<button class="mini" onclick="renewKey(\\'' + k.id + '\\')">+30d</button>'
      acts += '<button class="mini danger" onclick="delKey(\\'' + k.id + '\\')">Del</button>'
      rows += '<tr><td><span class="keycode">' + esc(k.key) + '</span></td>' +
        '<td>' + esc(k.plan) + '</td>' +
        '<td><span class="st-' + esc(k.status) + '">' + esc(k.status) + '</span></td>' +
        '<td>' + esc(k.deviceName || '-') + '<div class="mut" style="font-size:10.5px">' + esc(k.deviceId || '') + '</div></td>' +
        '<td>' + fmtDate(k.expiresAt) + '</td>' +
        '<td>' + acts + '</td></tr>'
    }
    $('keys-tbody').innerHTML = rows
  })
}

$('k-gen').addEventListener('click', function () {
  var body = { plan: $('k-plan').value, count: parseInt($('k-count').value, 10) || 1, prefix: $('k-prefix').value }
  var btn = this
  btn.disabled = true
  api('/api/admin/keys', { method: 'POST', body: body }, function (err, d) {
    btn.disabled = false
    if (err) { toast('error', 'Generate failed', err); return }
    toast('neon', d.created + ' keys generated!', d.keys[0] + (d.created > 1 ? ' +' + (d.created - 1) + ' more' : ''))
    var list = ''
    for (var i = 0; i < d.keys.length; i++) list += '<span class="keycode" style="margin-right:14px">' + esc(d.keys[i]) + '</span>'
    $('k-made').innerHTML = '<div class="card" style="background:var(--card2);font-size:13px">' + list + '</div>'
    loadKeys()
  })
})

window.keyAction = function (id, action) {
  api('/api/admin/keys', { method: 'PATCH', body: { id: id, action: action } }, function (err) {
    if (err) return toast('error', 'Action failed', err)
    toast('success', 'Done', 'Key updated: ' + action)
    loadKeys(); loadStats()
  })
}

window.renewKey = function (id) {
  var days = prompt('Kitne din badhana hai?', '30')
  if (!days) return
  api('/api/admin/keys', { method: 'PATCH', body: { id: id, action: 'renew', days: parseInt(days, 10) || 30 } }, function (err) {
    if (err) return toast('error', 'Renew failed', err)
    toast('success', 'Renewed', days + ' din badha diye')
    loadKeys()
  })
}

window.delKey = function (id) {
  if (!confirm('Ye key delete karni hai? Wapas nahi aayegi.')) return
  api('/api/admin/keys?id=' + id, { method: 'DELETE' }, function (err) {
    if (err) return toast('error', 'Delete failed', err)
    toast('success', 'Deleted', 'Key hata di gayi')
    loadKeys(); loadStats()
  })
}

window.copyKey = function (k) {
  if (navigator.clipboard) navigator.clipboard.writeText(k)
  toast('info', 'Copied', k)
}

/* ---------- updates ---------- */
function loadUpdates () {
  api('/api/admin/updates', {}, function (err, d) {
    if (err) return
    var html = ''
    if (!d.updates.length) html = '<div class="empty mt16">Koi update publish nahi hua abhi</div>'
    for (var i = 0; i < d.updates.length; i++) {
      var u = d.updates[i]
      html += '<div class="u-item"><div class="u-top">' +
        '<span class="u-ver">v' + esc(u.version) + '</span>' +
        '<span class="u-vc">vCode ' + esc(u.versionCode) + '</span>' +
        '<span class="pill ' + (u.isActive ? 'on' : 'off') + '">' + (u.isActive ? 'LIVE' : 'OFF') + '</span>' +
        (u.isForced ? '<span class="pill force">FORCED</span>' : '') +
        '<span style="flex:1"></span>' +
        '<button class="mini" onclick="toggleUpd(\\'' + u.id + '\\')">' + (u.isActive ? 'Take Offline' : 'Go Live') + '</button>' +
        '<button class="mini danger" onclick="delUpd(\\'' + u.id + '\\')">Delete</button></div>' +
        (u.changelog ? '<div class="u-cl">' + esc(u.changelog) + '</div>' : '') +
        '<div class="u-url">' + esc(u.downloadUrl) + '</div></div>'
    }
    $('u-list').innerHTML = html
  })
}

$('u-add').addEventListener('click', function () {
  var body = {
    version: $('u-version').value.trim(),
    versionCode: parseInt($('u-vc').value, 10),
    changelog: $('u-cl').value,
    downloadUrl: $('u-url').value.trim(),
    isForced: $('u-force').checked
  }
  if (!body.version || !body.versionCode || !body.downloadUrl) {
    toast('warning', 'Fields missing', 'Version, Version Code aur Download URL zaroori hai')
    return
  }
  api('/api/admin/updates', { method: 'POST', body: body }, function (err, d) {
    if (err) { toast('error', 'Publish failed', err); return }
    toast('neon', 'Update live!', 'v' + d.update.version + ' ab users ko dikhega')
    $('u-version').value = ''; $('u-vc').value = ''; $('u-cl').value = ''; $('u-url').value = ''
    loadUpdates(); loadStats()
  })
})

window.toggleUpd = function (id) {
  api('/api/admin/updates', { method: 'PATCH', body: { id: id, action: 'toggle-active' } }, function (err) {
    if (err) return toast('error', 'Failed', err)
    toast('success', 'Updated', 'Update status badal diya')
    loadUpdates(); loadStats()
  })
}

window.delUpd = function (id) {
  if (!confirm('Ye update delete karna hai?')) return
  api('/api/admin/updates?id=' + id, { method: 'DELETE' }, function (err) {
    if (err) return toast('error', 'Delete failed', err)
    toast('success', 'Deleted', 'Update hata diya')
    loadUpdates(); loadStats()
  })
}

/* ---------- devices ---------- */
function loadDevices () {
  api('/api/admin/devices', {}, function (err, d) {
    if (err) return
    var rows = ''
    if (!d.logs.length) rows = '<tr><td colspan="5"><div class="empty">Abhi koi device activity nahi</div></td></tr>'
    for (var i = 0; i < d.logs.length; i++) {
      var L = d.logs[i]
      rows += '<tr><td style="white-space:nowrap">' + fmtTime(L.createdAt) + '</td>' +
        '<td><span class="badge b-' + esc(L.action) + '">' + esc(L.action) + '</span></td>' +
        '<td>' + esc(L.deviceName || '-') + '<div class="mut" style="font-size:10.5px">' + esc(L.deviceId || '') + '</div></td>' +
        '<td>' + esc(L.detail || '-') + '</td>' +
        '<td><span class="keycode" style="font-size:11px">' + esc(L.keyUsed || '-') + '</span></td></tr>'
    }
    $('dev-tbody').innerHTML = rows
  })
}

/* ---------- announcement ---------- */
function loadAnn () {
  api('/api/admin/announcement', {}, function (err, d) {
    if (err) return
    ANN = d.announcement || { message: '', type: 'INFO', isActive: false }
    $('a-msg').value = ANN.message || ''
    $('a-type').value = ANN.type || 'INFO'
    $('a-active').checked = !!ANN.isActive
    annPreview()
  })
}

function annPreview () {
  var m = $('a-msg').value.trim()
  var pv = $('ann-preview')
  if (!m) { pv.className = ''; return }
  pv.className = 'show pv-' + $('a-type').value
  pv.textContent = m
}
$('a-msg').addEventListener('input', annPreview)
$('a-type').addEventListener('change', annPreview)

$('a-save').addEventListener('click', function () {
  var body = { message: $('a-msg').value, type: $('a-type').value, isActive: $('a-active').checked }
  api('/api/admin/announcement', { method: 'PATCH', body: body }, function (err, d) {
    if (err) return toast('error', 'Save failed', err)
    toast('neon', d.announcement.isActive ? 'Announcement LIVE!' : 'Announcement saved', 'App me turant effect hoga')
    loadStats()
  })
})

/* ---------- settings ---------- */
function loadSettings () {
  api('/api/admin/settings', {}, function (err, d) {
    if (err) return
    $('s-appname').value = d.settings.appName || ''
    $('s-pkg').value = d.settings.packageName || ''
  })
}

$('s-save').addEventListener('click', function () {
  api('/api/admin/settings', { method: 'PATCH', body: { appName: $('s-appname').value, packageName: $('s-pkg').value } }, function (err) {
    if (err) return toast('error', 'Save failed', err)
    toast('success', 'Settings saved', 'App settings update ho gayi')
  })
})

/* ---------- boot ---------- */
if (token) {
  api('/api/admin/stats', {}, function (err) {
    if (!err) enterApp()
    else logout()
  })
}
</script>
</body>
</html>`

// ======================= START =======================
loadDB()
http.createServer(handle).listen(PORT, () => {
  console.log('')
  console.log('  ██  MASTER MODZ PANEL  ██')
  console.log('  ─────────────────────────────────')
  console.log('  Panel chalu! Kholo:  http://localhost:' + PORT)
  console.log('  Password:            ' + db.password)
  console.log('  Data file:           ' + DATA_FILE)
  console.log('  ─────────────────────────────────')
  console.log('  App APIs:')
  console.log('    GET  /api/app/update?vc=N')
  console.log('    POST /api/app/verify-key')
  console.log('    GET  /api/app/announcement')
  console.log('')
})
