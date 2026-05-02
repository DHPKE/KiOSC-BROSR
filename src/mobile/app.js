/**
 * KiOSC-BrowsR — mobile app (Capacitor / Android / iOS)
 *
 * Capabilities:
 *  - Fullscreen kiosk iframe driven by OSC/UDP commands
 *  - Listens for OSC on a configurable UDP port
 *  - Advertises itself via mDNS (_osc._udp) so controllers can find it
 *  - Browses mDNS to discover other KiOSC-BrowsR instances on the LAN
 *  - Triple-tap anywhere opens the settings/admin overlay
 *
 * Build:
 *   cd src/mobile
 *   npm install
 *   npm run build          # bundles to dist/
 *   npx cap add android    # first time
 *   npx cap add ios        # first time
 *   npx cap sync           # after every build
 *   npx cap open android   # opens Android Studio
 *   npx cap open ios       # opens Xcode
 */

import { UdpPlugin }  from '@capacitor-community/udp'
import { Zeroconf }   from 'capacitor-zeroconf'
import { StatusBar, Style } from '@capacitor/status-bar'

// ── Persistent config (localStorage) ──────────────────────────────────────

const STORAGE_KEY = 'kiosc-cfg'

const DEFAULT_CFG = {
  home_url:    'https://example.com',
  osc_port:    9000,
  device_name: 'kiosc-mobile',
  reset_time:  0          // seconds, 0 = disabled
}

function loadCfg () {
  try {
    return { ...DEFAULT_CFG, ...JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}') }
  } catch { return { ...DEFAULT_CFG } }
}

function saveCfg (c) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(c))
}

let cfg = loadCfg()

// ── DOM refs ───────────────────────────────────────────────────────────────

const kiosk      = document.getElementById('kiosk')
const overlay    = document.getElementById('overlay')
const oscStatus  = document.getElementById('osc-status')
const deviceList = document.getElementById('device-list')

// Populate settings form
document.getElementById('cfg-home').value = cfg.home_url
document.getElementById('cfg-port').value = cfg.osc_port
document.getElementById('cfg-name').value = cfg.device_name

// ── Kiosk navigation ───────────────────────────────────────────────────────

let resetTimer   = null
let currentUrl   = cfg.home_url

function goTo (url) {
  if (!url) return
  currentUrl = url
  kiosk.src  = url
  scheduleReset()
  console.log('[nav] →', url)
}

function doReload () {
  kiosk.src = kiosk.src   // forces reload of iframe
  scheduleReset()
}

function scheduleReset () {
  if (resetTimer) clearTimeout(resetTimer)
  if (cfg.reset_time > 0) {
    resetTimer = setTimeout(() => goTo(cfg.home_url), cfg.reset_time * 1000)
  }
}

function dispatchCmd (cmd, params = {}) {
  console.log('[cmd]', cmd, params)
  switch (cmd) {
    case 'goto':
    case 'start':   goTo(params.url || cfg.home_url); break
    case 'home':    goTo(cfg.home_url);               break
    case 'reload':  doReload();                       break
    case 'stop':    kiosk.src = 'about:blank';        break
    case 'restart': goTo(params.url || cfg.home_url); break
    case 'clear':
      // Clear iframe session by navigating away and back
      kiosk.src = 'about:blank'
      setTimeout(() => goTo(currentUrl), 300)
      break
    case 'set_reset_time':
      cfg.reset_time = parseInt(params.seconds, 10) || 0
      saveCfg(cfg)
      scheduleReset()
      break
  }
}

// ── OSC packet parser ──────────────────────────────────────────────────────
//  Parses the most common OSC types: s (string), i (int32), f (float32)

function parseOsc (buf) {
  function readStr (off) {
    let end = off
    while (end < buf.length && buf[end] !== 0) end++
    const s = String.fromCharCode(...buf.slice(off, end))
    return { s, next: Math.ceil((end + 1) / 4) * 4 }
  }

  const { s: address, next: i1 } = readStr(0)
  if (!address.startsWith('/')) return null

  const args = []

  if (i1 < buf.length && buf[i1] === 0x2c) {   // ','
    const { s: types, next: i2 } = readStr(i1)
    let i = i2
    for (let t = 1; t < types.length; t++) {
      switch (types[t]) {
        case 's': {
          const { s, next } = readStr(i)
          args.push(s)
          i = next
          break
        }
        case 'i': {
          const v = (buf[i] << 24 | buf[i+1] << 16 | buf[i+2] << 8 | buf[i+3]) | 0
          args.push(v); i += 4
          break
        }
        case 'f': {
          const dv = new DataView(buf.buffer, buf.byteOffset + i, 4)
          args.push(dv.getFloat32(0, false)); i += 4
          break
        }
        default: i += 4
      }
    }
  }

  return { address, args }
}

// ── UDP / OSC listener ─────────────────────────────────────────────────────

let socketId = null

async function startUdp (port) {
  try {
    if (socketId !== null) {
      await UdpPlugin.close({ socketId })
      socketId = null
    }

    const result = await UdpPlugin.create({ properties: { name: 'kiosc', bufferSize: 8192 } })
    socketId = result.socketId

    await UdpPlugin.bind({ socketId, address: '0.0.0.0', port })

    UdpPlugin.addListener('receive', (info) => {
      const raw = Uint8Array.from(atob(info.data), c => c.charCodeAt(0))
      const msg = parseOsc(raw)
      if (!msg) return

      const cmd   = msg.address.replace(/^\//, '')
      const parms = {}
      if (['start', 'restart', 'goto'].includes(cmd)) parms.url = msg.args[0]
      if (cmd === 'set_reset_time') parms.seconds = msg.args[0]
      dispatchCmd(cmd, parms)
    })

    UdpPlugin.addListener('receiveError', (err) => {
      console.error('[udp] error', err)
    })

    oscStatus.textContent = `listening on :${port}`
    console.log(`[udp] bound to 0.0.0.0:${port}`)
  } catch (e) {
    console.error('[udp] start failed', e)
    oscStatus.textContent = `UDP error: ${e.message}`
  }
}

// ── mDNS: advertise + browse ───────────────────────────────────────────────

const peers = new Map()   // name → { hostname, port, ipv4 }

async function startMdns () {
  try {
    // Advertise this device so OSC controllers can discover it
    await Zeroconf.register({
      domain: 'local.',
      type:   '_osc._udp',
      name:   `KiOSC-BrowsR (${cfg.device_name})`,
      port:   cfg.osc_port,
      props:  { app: 'kiosc-browsr', version: '2' }
    })
    console.log(`[mdns] advertising "${cfg.device_name}" on :${cfg.osc_port}`)

    // Browse for other instances on the LAN
    await Zeroconf.watch({ type: '_osc._udp', domain: 'local.' })

    Zeroconf.addListener('update', (result) => {
      const { action, service } = result
      if (!service) return

      if (action === 'added' || action === 'resolved') {
        peers.set(service.name, service)
      } else if (action === 'removed') {
        peers.delete(service.name)
      }
      renderDeviceList()
    })
  } catch (e) {
    console.warn('[mdns] not available:', e.message)
  }
}

function renderDeviceList () {
  if (peers.size === 0) {
    deviceList.innerHTML = '<p style="font-size:0.82rem;color:#9ca3af">No devices found yet…</p>'
    return
  }

  const isSelf = (name) => name === `KiOSC-BrowsR (${cfg.device_name})`

  deviceList.innerHTML = ''
  for (const [name, svc] of peers) {
    const ip   = (svc.ipv4Addresses && svc.ipv4Addresses[0]) || svc.hostname || ''
    const port = svc.port || 9000
    const self = isSelf(name)

    const div = document.createElement('div')
    div.className = 'device-item' + (self ? ' own' : '')
    div.innerHTML = `
      <div>
        <div class="dname">${esc(name)}${self ? ' (this device)' : ''}</div>
        <div class="daddr">${esc(ip)}:${port}</div>
      </div>
      ${!self ? `<button onclick="relayTo('${esc(ip)}',${port})">Control</button>` : ''}
    `
    deviceList.appendChild(div)
  }
}

// Open the web admin of a discovered peer in the kiosk iframe
window.relayTo = (ip, port) => {
  const url = `http://${ip}:${port}`
  goTo(url)
  closeOverlay()
  toast(`Opening admin for ${ip}:${port}`)
}

// ── Overlay ────────────────────────────────────────────────────────────────

window.closeOverlay = () => overlay.classList.remove('open')

window.navigate = () => {
  const url = document.getElementById('nav-url').value.trim()
  if (!url) return
  goTo(url)
  document.getElementById('nav-url').value = ''
  closeOverlay()
}

window.applySettings = async () => {
  cfg.home_url    = document.getElementById('cfg-home').value.trim() || cfg.home_url
  cfg.osc_port    = parseInt(document.getElementById('cfg-port').value, 10) || 9000
  cfg.device_name = document.getElementById('cfg-name').value.trim() || cfg.device_name
  saveCfg(cfg)

  // Restart UDP on new port
  await startUdp(cfg.osc_port)
  toast('Settings saved. Restart app to update mDNS name.')
  closeOverlay()
}

// Triple-tap anywhere to open overlay
let tapCount = 0, tapTimer = null
document.addEventListener('click', () => {
  tapCount++
  if (tapCount === 3) {
    tapCount = 0
    overlay.classList.add('open')
  }
  clearTimeout(tapTimer)
  tapTimer = setTimeout(() => { tapCount = 0 }, 600)
})

// ── Toast ──────────────────────────────────────────────────────────────────

let toastTimer = null
window.toast = (msg) => {
  const t = document.getElementById('toast')
  t.textContent = msg
  t.classList.add('show')
  if (toastTimer) clearTimeout(toastTimer)
  toastTimer = setTimeout(() => t.classList.remove('show'), 2400)
}

function esc (s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

// ── Init ───────────────────────────────────────────────────────────────────

async function init () {
  // Hide status bar on native
  try { await StatusBar.setStyle({ style: Style.Dark }); await StatusBar.hide() } catch {}

  // Load kiosk home
  goTo(cfg.home_url)

  // Start OSC listener
  await startUdp(cfg.osc_port)

  // mDNS (native only)
  if (window.Capacitor && window.Capacitor.isNativePlatform()) {
    await startMdns()
  } else {
    oscStatus.textContent = `web preview — UDP not available`
    deviceList.innerHTML = '<p style="font-size:0.82rem;color:#9ca3af">mDNS available on device only</p>'
  }
}

init()
