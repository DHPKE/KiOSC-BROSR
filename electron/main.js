'use strict'

const { app, BrowserWindow, dialog } = require('electron')
const path  = require('path')
const fs    = require('fs')
const os    = require('os')
const http  = require('http')
const dgram = require('dgram')
const yaml  = require('js-yaml')
const { execFileSync } = require('child_process')
const { Server: OscServer } = require('node-osc')
const { Bonjour } = require('bonjour-service')

// ── Config ─────────────────────────────────────────────────────────────────

const DEFAULTS = {
  start_url:      'https://example.com',
  osc_bind:       '0.0.0.0',
  osc_port:       9000,
  udp_text_bind:  '0.0.0.0',
  udp_text_port:  9100,
  web_bind:       '0.0.0.0',
  web_port:       8080,
  web_user:       'admin',
  web_pass:       'changeme',
  reset_time:     3600,
  hmac_secret:    '',
  allowed_ips:    [],
  kiosk:          true,
  mdns_name:      os.hostname(),
  autostart:      true
}

let cfg = { ...DEFAULTS }

function getConfigPaths () {
  return [
    process.env.KIOSC_CONFIG,
    path.join(app.getPath('userData'), 'config.yaml'),
    '/etc/kiosc-browsr/config.yaml'
  ].filter(Boolean)
}

function loadConfig () {
  for (const p of getConfigPaths()) {
    if (fs.existsSync(p)) {
      try {
        const loaded = yaml.load(fs.readFileSync(p, 'utf8'))
        cfg = { ...DEFAULTS, ...loaded }
        console.log(`[config] loaded: ${p}`)
        return
      } catch (e) {
        console.error(`[config] ${p}: ${e.message}`)
      }
    }
  }
  console.log('[config] using defaults')
}

function saveConfig () {
  const paths = getConfigPaths()
  // Prefer the userData path (always writable)
  const p = paths[1]
  fs.mkdirSync(path.dirname(p), { recursive: true })
  fs.writeFileSync(p, yaml.dump(cfg), 'utf8')
  console.log(`[config] saved: ${p}`)
}

// ── State ──────────────────────────────────────────────────────────────────

let mainWindow = null
let oscServer  = null
let udpSock    = null
let bonjour    = null
let resetTimer = null
let currentUrl = null

// ── Helpers ────────────────────────────────────────────────────────────────

function getLocalIPs () {
  const result = []
  for (const ifaces of Object.values(os.networkInterfaces())) {
    for (const iface of ifaces) {
      if (!iface.internal && iface.family === 'IPv4') result.push(iface.address)
    }
  }
  return result
}

function getStatus () {
  return {
    active:         !!(mainWindow && !mainWindow.isDestroyed()),
    url:            currentUrl,
    home:           cfg.start_url,
    reset_interval: cfg.reset_time,
    mdns_name:      cfg.mdns_name,
    hostname:       os.hostname(),
    ip_addresses:   getLocalIPs(),
    osc_port:       cfg.osc_port,
    udp_text_port:  cfg.udp_text_port,
    web_port:       cfg.web_port
  }
}

// ── Commands ───────────────────────────────────────────────────────────────

function navigate (url) {
  if (!url) return
  currentUrl = url
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.loadURL(url)
  scheduleReset()
  console.log(`[nav] → ${url}`)
}

function reload () {
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.reload()
  scheduleReset()
  console.log('[nav] reload')
}

function clearData () {
  if (!mainWindow || mainWindow.isDestroyed()) return
  const ses = mainWindow.webContents.session
  ses.clearCache()
  ses.clearStorageData()
  console.log('[nav] cache + storage cleared')
}

function scheduleReset () {
  if (resetTimer) clearTimeout(resetTimer)
  if (cfg.reset_time > 0) {
    resetTimer = setTimeout(() => {
      console.log('[reset] auto-reset to home')
      navigate(cfg.start_url)
    }, cfg.reset_time * 1000)
  }
}

function dispatch (cmd, params = {}) {
  console.log(`[cmd] ${cmd}`, params)
  switch (cmd) {
    case 'goto':
    case 'start':
      navigate(params.url || cfg.start_url)
      break
    case 'home':
      navigate(cfg.start_url)
      break
    case 'stop':
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.loadURL('about:blank')
      break
    case 'restart':
      navigate(params.url || cfg.start_url)
      break
    case 'reload':
      reload()
      break
    case 'clear':
      clearData()
      break
    case 'set_reset_time':
      cfg.reset_time = parseInt(params.seconds, 10) || 0
      scheduleReset()
      break
    case 'status':
      console.log('[status]', JSON.stringify(getStatus(), null, 2))
      break
    default:
      console.warn(`[cmd] unknown command: ${cmd}`)
  }
}

// ── OSC server ─────────────────────────────────────────────────────────────

function startOsc () {
  oscServer = new OscServer(cfg.osc_port, cfg.osc_bind, () => {
    console.log(`[osc] listening on ${cfg.osc_bind}:${cfg.osc_port}`)
  })

  oscServer.on('message', (msg, rinfo) => {
    // IP allowlist check
    const wl = cfg.allowed_ips
    if (wl && wl.length && rinfo && !wl.includes(rinfo.address)) {
      console.warn(`[osc] blocked ${rinfo.address}`)
      return
    }

    const address = msg[0]
    const args    = msg.slice(1)
    const cmd     = address.replace(/^\//, '')
    const params  = {}
    if (['start', 'restart', 'goto'].includes(cmd)) params.url = args[0]
    if (cmd === 'set_reset_time') params.seconds = args[0]
    dispatch(cmd, params)
  })
}

// ── UDP plaintext server ───────────────────────────────────────────────────

function startUdp () {
  udpSock = dgram.createSocket('udp4')
  udpSock.on('error', (e) => console.error('[udp] error:', e.message))

  udpSock.bind(cfg.udp_text_port, cfg.udp_text_bind, () => {
    console.log(`[udp] listening on ${cfg.udp_text_bind}:${cfg.udp_text_port}`)
  })

  udpSock.on('message', (buf, rinfo) => {
    const wl = cfg.allowed_ips
    if (wl && wl.length && !wl.includes(rinfo.address)) {
      console.warn(`[udp] blocked ${rinfo.address}`)
      return
    }

    const tokens = buf.toString('utf8').trim().split(/\s+/)
    if (!tokens.length) return
    const [verb, ...rest] = tokens
    const params = {}
    if (['start', 'restart', 'goto'].includes(verb)) params.url = rest[0]
    if (verb === 'set_reset_time') params.seconds = rest[0]
    dispatch(verb, params)
  })
}

// ── mDNS advertisement ────────────────────────────────────────────────────
//
//  Advertises two services on the local network so clients can be found
//  without knowing IP addresses:
//
//   _osc._udp  "KiOSC-BrowsR (<hostname>)"   → OSC control port
//   _http._tcp "KiOSC-BrowsR Admin (<name>)"  → web admin port
//
//  From any OSC app on the LAN: browse _osc._udp to find kiosk instances.
//  From a browser: http://<hostname>.local:<web_port>
// ──────────────────────────────────────────────────────────────────────────

function startMdns () {
  try {
    bonjour = new Bonjour()

    bonjour.publish({
      name:     `KiOSC-BrowsR (${cfg.mdns_name})`,
      type:     'osc',
      protocol: 'udp',
      port:     cfg.osc_port,
      txt: {
        udp_text_port: String(cfg.udp_text_port),
        app:           'kiosc-browsr',
        version:       '2'
      }
    })

    bonjour.publish({
      name:     `KiOSC-BrowsR Admin (${cfg.mdns_name})`,
      type:     'http',
      protocol: 'tcp',
      port:     cfg.web_port,
      txt: {
        path: '/',
        app:  'kiosc-browsr'
      }
    })

    console.log(`[mdns] advertising "${cfg.mdns_name}"`)
    console.log(`[mdns]   OSC  → ${os.hostname()}.local:${cfg.osc_port} (_osc._udp)`)
    console.log(`[mdns]   HTTP → ${os.hostname()}.local:${cfg.web_port} (_http._tcp)`)
  } catch (e) {
    console.error('[mdns] error:', e.message)
  }
}

// ── Web admin HTTP server ──────────────────────────────────────────────────

function startWebAdmin () {
  const htmlPath = path.join(__dirname, 'webadmin', 'index.html')

  const server = http.createServer((req, res) => {
    // Basic auth
    const auth  = req.headers['authorization'] || ''
    const creds = Buffer.from(auth.replace('Basic ', ''), 'base64').toString()
    const colon = creds.indexOf(':')
    const user  = creds.slice(0, colon)
    const pass  = creds.slice(colon + 1)

    if (user !== cfg.web_user || pass !== cfg.web_pass) {
      res.writeHead(401, {
        'WWW-Authenticate': 'Basic realm="KiOSC-BrowsR Admin"',
        'Content-Type':     'text/plain'
      })
      return res.end('Unauthorized')
    }

    let url
    try {
      url = new URL(req.url, `http://${req.headers.host}`)
    } catch {
      res.writeHead(400)
      return res.end('Bad request')
    }

    // GET /  → serve admin UI
    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      return res.end(fs.readFileSync(htmlPath, 'utf8'))
    }

    // GET /api/status
    if (req.method === 'GET' && url.pathname === '/api/status') {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      return res.end(JSON.stringify(getStatus()))
    }

    // GET /api/config  (password and hmac_secret omitted)
    if (req.method === 'GET' && url.pathname === '/api/config') {
      const safe = { ...cfg }
      delete safe.web_pass
      delete safe.hmac_secret
      res.writeHead(200, { 'Content-Type': 'application/json' })
      return res.end(JSON.stringify(safe))
    }

    // POST /api/command
    if (req.method === 'POST' && url.pathname === '/api/command') {
      return readBody(req, res, (body) => {
        const { cmd, params } = body
        if (typeof cmd !== 'string') throw new Error('cmd must be a string')
        dispatch(cmd, params || {})
        return { ok: true }
      })
    }

    // POST /api/config  (only live-editable keys; ports/binds require restart)
    if (req.method === 'POST' && url.pathname === '/api/config') {
      return readBody(req, res, (body) => {
        const editable = ['start_url', 'reset_time', 'mdns_name', 'kiosk']
        for (const k of editable) {
          if (k in body) cfg[k] = body[k]
        }
        saveConfig()
        return { ok: true }
      })
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' })
    res.end('Not found')
  })

  server.listen(cfg.web_port, cfg.web_bind, () => {
    console.log(`[webadmin] http://${cfg.web_bind}:${cfg.web_port}`)
  })
}

/** Helper: read + parse JSON body, send JSON response, catch errors. */
function readBody (req, res, handler) {
  let raw = ''
  req.on('data', (c) => { raw += c })
  req.on('end', () => {
    try {
      const body   = JSON.parse(raw)
      const result = handler(body)
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(result))
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: e.message }))
    }
  })
}

// ── Electron window ────────────────────────────────────────────────────────

function createWindow () {
  const devMode = process.argv.includes('--no-kiosk')
  const useKiosk = cfg.kiosk === true && !devMode

  mainWindow = new BrowserWindow({
    width:            1920,
    height:           1080,
    kiosk:            useKiosk,
    fullscreen:       useKiosk,
    frame:            !useKiosk,
    autoHideMenuBar:  true,
    backgroundColor:  '#000000',
    webPreferences: {
      nodeIntegration:  false,
      contextIsolation: true,
      sandbox:          true,
      webSecurity:      true
    }
  })

  // F12 opens devtools only in non-kiosk / dev mode
  if (!useKiosk) {
    mainWindow.webContents.on('before-input-event', (_e, input) => {
      if (input.key === 'F12') {
        mainWindow.webContents.openDevTools({ mode: 'detach' })
      }
    })
  }

  mainWindow.on('closed', () => { mainWindow = null })

  currentUrl = cfg.start_url
  mainWindow.loadURL(cfg.start_url)
  scheduleReset()
  console.log(`[window] kiosk=${useKiosk}, loading ${cfg.start_url}`)
}

// ── macOS: enforce running from Applications folder ──────────────────────
//
//  Running from a mounted DMG causes SIGBUS when the DMG is ejected while
//  the app is running (kernel unmounts the vnode that backs the mmap'd binary).
//  Standard macOS pattern: detect non-Applications path and offer to move.
// ─────────────────────────────────────────────────────────────────────────────

async function checkMacOSAppLocation () {
  if (process.platform !== 'darwin') return true

  const exePath = process.execPath
  const validPrefixes = [
    '/Applications/',
    path.join(os.homedir(), 'Applications') + '/'
  ]
  if (validPrefixes.some(p => exePath.startsWith(p))) return true

  // Resolve .app bundle path from the inner MacOS/binary path
  const appPath = path.resolve(exePath, '../../..')
  const appName = path.basename(appPath)
  const dest    = path.join('/Applications', appName)

  const { response } = await dialog.showMessageBox({
    type:      'warning',
    buttons:   ['Move to Applications', 'Quit'],
    defaultId: 0,
    cancelId:  1,
    message:   `Move ${appName} to the Applications folder?`,
    detail:    'Running from a disk image or Downloads folder can cause crashes when the ' +
               'disk image is ejected. Move to Applications to fix this.'
  })

  if (response === 1) {
    app.quit()
    return false
  }

  try {
    if (fs.existsSync(dest)) execFileSync('rm', ['-rf', dest])
    execFileSync('cp', ['-R', appPath, dest])
    // Remove quarantine flag so macOS doesn't re-prompt Gatekeeper
    try { execFileSync('xattr', ['-dr', 'com.apple.quarantine', dest]) } catch (_) {}
    // Re-launch from the new location and exit this instance
    execFileSync('open', [dest])
    app.quit()
    return false
  } catch (e) {
    console.error('[macos] move to Applications failed:', e.message)
    const { response: r2 } = await dialog.showMessageBox({
      type:    'error',
      buttons: ['Continue Anyway', 'Quit'],
      message: 'Could not move to Applications',
      detail:  `Please drag ${appName} to your Applications folder manually, then re-open it.\n\n${e.message}`
    })
    if (r2 === 1) { app.quit(); return false }
  }
  return true
}

// ── App lifecycle ──────────────────────────────────────────────────────────

app.whenReady().then(async () => {
  if (!(await checkMacOSAppLocation())) return
  loadConfig()
  if (cfg.autostart) createWindow()
  startOsc()
  startUdp()
  startMdns()
  startWebAdmin()
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow()
})

app.on('before-quit', () => {
  if (resetTimer) clearTimeout(resetTimer)
  if (oscServer)  oscServer.close()
  if (udpSock)    udpSock.close()
  if (bonjour)    bonjour.destroy()
  console.log('[app] exit')
})
