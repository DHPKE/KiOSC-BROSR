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
  kiosk:            true,
  mdns_name:        os.hostname(),
  autostart:        true,
  hide_cursor:      false,
  disable_touch:    false,
  disable_keyboard: false,
  test_mode:        false,
  always_on_top:    false,
  launch_at_login:  false
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

let mainWindow      = null
let oscServer       = null
let udpSock         = null
let bonjour         = null
let resetTimer      = null
let currentUrl      = null
let keyboardBlocker      = null
let blurRefocusHandler   = null

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
    active:           !!(mainWindow && !mainWindow.isDestroyed()),
    url:              currentUrl,
    home:             cfg.start_url,
    reset_interval:   cfg.reset_time,
    mdns_name:        cfg.mdns_name,
    hostname:         os.hostname(),
    ip_addresses:     getLocalIPs(),
    osc_port:         cfg.osc_port,
    udp_text_port:    cfg.udp_text_port,
    web_port:         cfg.web_port,
    hide_cursor:      cfg.hide_cursor,
    disable_touch:    cfg.disable_touch,
    disable_keyboard: cfg.disable_keyboard,
    test_mode:        cfg.test_mode,
    always_on_top:    cfg.always_on_top,
    launch_at_login:  cfg.launch_at_login
  }
}

// ── Commands ───────────────────────────────────────────────────────────────

function navigate (url) {
  if (!url) return
  if (cfg.test_mode) { cfg.test_mode = false; saveConfig() }
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

// ── Input / Display helpers ────────────────────────────────────────────────

function parseBool (v) {
  if (typeof v === 'boolean') return v
  if (typeof v === 'number')  return v !== 0
  if (typeof v === 'string')  return ['1', 'true', 'on', 'yes'].includes(v.toLowerCase())
  return !!v
}

function testModeHtml () {
  const name   = cfg.mdns_name || os.hostname()
  const ips    = getLocalIPs()
  const ipRows = ips.map(ip => `<div class="ip">${ip}</div>`).join('')
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KiOSC-BrowsR \u00b7 Test Mode</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#000;color:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,monospace;
  width:100vw;height:100vh;display:flex;flex-direction:column;align-items:center;
  justify-content:center;overflow:hidden;user-select:none}
.badge{position:fixed;top:4vh;right:4vw;background:#fbbf24;color:#000;
  padding:.5em 1.4em;border-radius:2em;font-size:clamp(12px,1.2vw,18px);
  font-weight:800;letter-spacing:.12em;text-transform:uppercase;
  animation:pulse 1.8s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.label{font-size:clamp(11px,1.1vw,16px);text-transform:uppercase;letter-spacing:.25em;
  color:#34d399;margin-bottom:3vh}
.name{font-size:clamp(40px,10vw,160px);font-weight:800;letter-spacing:-.02em;
  color:#fff;margin-bottom:5vh;word-break:break-all;text-align:center;
  line-height:1;padding:0 4vw}
.ips{display:flex;flex-direction:column;align-items:center;gap:1vh}
.ip{font-size:clamp(14px,2vw,32px);color:#6b7280;font-family:monospace;letter-spacing:.05em}
.clock{position:fixed;bottom:4vh;font-size:clamp(20px,4vw,64px);color:#1f2937;
  font-family:monospace;letter-spacing:.1em}
.version{position:fixed;top:4vh;left:4vw;font-size:clamp(10px,.9vw,14px);
  color:#374151;font-family:monospace}
</style>
</head>
<body>
<div class="badge">Test Mode</div>
<div class="version">KiOSC-BrowsR v2</div>
<div class="label">Kiosk Name</div>
<div class="name">${name}</div>
<div class="ips">${ipRows}</div>
<div class="clock" id="clk"></div>
<script>
function tick(){
  var n=new Date()
  document.getElementById('clk').textContent=n.toTimeString().slice(0,8)
  setTimeout(tick,1000-n.getMilliseconds())
}
tick()
<\/script>
</body></html>`
}

function applyInputSettings () {
  if (!mainWindow || mainWindow.isDestroyed()) return
  const wc = mainWindow.webContents

  // Cursor — injected <style> tag; persists within a page, re-injected on each navigation
  wc.executeJavaScript(`(function(){
    var el=document.getElementById('__kc_cur')
    if(!el){el=document.createElement('style');el.id='__kc_cur';
      (document.head||document.documentElement).appendChild(el)}
    el.textContent=${JSON.stringify(cfg.hide_cursor ? '*,*::before,*::after{cursor:none!important}' : '')}
  })()`).catch(() => {})

  // Touch — capture-phase listeners that block all touch events
  wc.executeJavaScript(`(function(){
    var id='__kc_touch',ev=['touchstart','touchend','touchmove','touchcancel']
    if(${cfg.disable_touch}){
      if(!window[id]){
        var h=function(e){e.preventDefault();e.stopImmediatePropagation()}
        window[id]=h
        ev.forEach(function(t){document.addEventListener(t,h,{capture:true,passive:false})})
      }
    }else{
      if(window[id]){
        ev.forEach(function(t){document.removeEventListener(t,window[id],{capture:true})})
        delete window[id]
      }
    }
  })()`).catch(() => {})

  // Keyboard — Electron-level before-input-event; blocks all key input to the renderer
  if (cfg.disable_keyboard && !keyboardBlocker) {
    keyboardBlocker = (event) => { event.preventDefault() }
    wc.on('before-input-event', keyboardBlocker)
  } else if (!cfg.disable_keyboard && keyboardBlocker) {
    wc.removeListener('before-input-event', keyboardBlocker)
    keyboardBlocker = null
  }
}

function loadTestMode () {
  // Serve via the local HTTP server so file:// path-resolution and CSP
  // sandbox restrictions cannot interfere with inline scripts/styles.
  mainWindow.loadURL(`http://127.0.0.1:${cfg.web_port}/__testmode`)
}

function restartApp () {
  console.log('[app] restarting…')
  app.relaunch()
  app.quit()
}

function applyLoginItem () {
  if (process.platform === 'linux') {
    const desktopDir  = path.join(os.homedir(), '.config', 'autostart')
    const desktopFile = path.join(desktopDir, 'kiosc-browsr.desktop')
    if (cfg.launch_at_login) {
      try {
        fs.mkdirSync(desktopDir, { recursive: true })
        fs.writeFileSync(desktopFile, [
          '[Desktop Entry]',
          'Type=Application',
          'Name=KiOSC-BrowsR',
          `Exec=${process.execPath}`,
          'Hidden=false',
          'NoDisplay=false',
          'X-GNOME-Autostart-enabled=true'
        ].join('\n') + '\n', 'utf8')
        console.log('[autostart] desktop entry written:', desktopFile)
      } catch (e) {
        console.error('[autostart]', e.message)
      }
    } else {
      try { fs.unlinkSync(desktopFile) } catch (_) {}
      console.log('[autostart] desktop entry removed')
    }
  } else {
    try {
      app.setLoginItemSettings({ openAtLogin: cfg.launch_at_login })
      console.log(`[autostart] login item set: ${cfg.launch_at_login}`)
    } catch (e) {
      console.error('[autostart]', e.message)
    }
  }
}

function applyWindowBehavior () {
  if (!mainWindow || mainWindow.isDestroyed()) return
  mainWindow.setAlwaysOnTop(cfg.always_on_top, 'screen-saver')
  if (blurRefocusHandler) {
    mainWindow.removeListener('blur', blurRefocusHandler)
    blurRefocusHandler = null
  }
  if (cfg.always_on_top) {
    blurRefocusHandler = () => {
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.focus()
    }
    mainWindow.on('blur', blurRefocusHandler)
  }
}

// ── Commands ───────────────────────────────────────────────────────────────

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
    case 'hide_cursor':
      cfg.hide_cursor = parseBool(params.value)
      applyInputSettings()
      saveConfig()
      console.log(`[input] hide_cursor=${cfg.hide_cursor}`)
      break
    case 'disable_touch':
      cfg.disable_touch = parseBool(params.value)
      applyInputSettings()
      saveConfig()
      console.log(`[input] disable_touch=${cfg.disable_touch}`)
      break
    case 'disable_keyboard':
      cfg.disable_keyboard = parseBool(params.value)
      applyInputSettings()
      saveConfig()
      console.log(`[input] disable_keyboard=${cfg.disable_keyboard}`)
      break
    case 'test_mode':
      cfg.test_mode = parseBool(params.value)
      if (cfg.test_mode) {
        if (mainWindow && !mainWindow.isDestroyed()) loadTestMode()
      } else {
        navigate(currentUrl || cfg.start_url)
      }
      saveConfig()
      console.log(`[input] test_mode=${cfg.test_mode}`)
      break
    case 'restart_app':
      restartApp()
      break
    case 'always_on_top':
      cfg.always_on_top = parseBool(params.value)
      applyWindowBehavior()
      saveConfig()
      console.log(`[window] always_on_top=${cfg.always_on_top}`)
      break
    case 'launch_at_login':
      cfg.launch_at_login = parseBool(params.value)
      applyLoginItem()
      saveConfig()
      console.log(`[autostart] launch_at_login=${cfg.launch_at_login}`)
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
    if (['hide_cursor', 'disable_touch', 'disable_keyboard', 'test_mode',
         'always_on_top', 'launch_at_login'].includes(cmd)) params.value = args[0]
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
    if (['hide_cursor', 'disable_touch', 'disable_keyboard', 'test_mode',
         'always_on_top', 'launch_at_login'].includes(verb)) params.value = rest[0]
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
    let url
    try {
      url = new URL(req.url, `http://${req.headers.host}`)
    } catch {
      res.writeHead(400)
      return res.end('Bad request')
    }

    // GET /__testmode — no-auth internal route; only reachable via loopback
    if (req.method === 'GET' && url.pathname === '/__testmode') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' })
      return res.end(testModeHtml())
    }

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

    // URL already parsed above

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
        const editable = ['start_url', 'reset_time', 'mdns_name', 'kiosk',
                          'hide_cursor', 'disable_touch', 'disable_keyboard', 'test_mode',
                          'always_on_top', 'launch_at_login']
        const prevTestMode      = cfg.test_mode
        const prevLaunchAtLogin = cfg.launch_at_login
        for (const k of editable) {
          if (k in body) cfg[k] = body[k]
        }
        saveConfig()
        applyInputSettings()
        applyWindowBehavior()
        if (cfg.launch_at_login !== prevLaunchAtLogin) applyLoginItem()
        if (cfg.test_mode && !prevTestMode) {
          if (mainWindow && !mainWindow.isDestroyed()) loadTestMode()
        } else if (!cfg.test_mode && prevTestMode) {
          navigate(currentUrl || cfg.start_url)
        }
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

  // Re-apply input/display settings after every page load (injections reset on navigation)
  mainWindow.webContents.on('did-finish-load', () => applyInputSettings())

  currentUrl = cfg.start_url
  if (cfg.test_mode) {
    loadTestMode()
  } else {
    mainWindow.loadURL(cfg.start_url)
  }
  scheduleReset()
  applyWindowBehavior()
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
  applyLoginItem()
  startOsc()
  startUdp()
  startMdns()
  startWebAdmin()
  if (cfg.autostart) createWindow()
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
