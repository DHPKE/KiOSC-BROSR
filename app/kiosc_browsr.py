#!/usr/bin/env python3
"""KiOSC-BrowsR main service implementation"""

import os
import sys
import time
import hmac
import hashlib
import socket
import subprocess
import threading
import signal
import yaml
import logging
from pythonosc.dispatcher import Dispatcher
from pythonosc.osc_server import ThreadingOSCUDPServer
import pychrome

# Setup logging
logger = logging.getLogger('kiosc')
logger.setLevel(logging.INFO)
fh = logging.FileHandler('/var/log/kiosc-browsr.log')
ch = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(ch)

# Global state
config = {}
chrome_proc = None
chrome_browser = None
chrome_tab = None
reset_timer_obj = None
running = True
osc_srv = None
udp_sock = None


def load_config(path):
    """Load YAML config"""
    global config
    try:
        with open(path) as f:
            config = yaml.safe_load(f)
        logger.info(f"Config loaded from {path}")
    except:
        config = {
            'start_url': 'https://example.com',
            'debug_port': 9222,
            'autostart': True,
            'osc_bind': '0.0.0.0',
            'osc_port': 9000,
            'udp_text_bind': '0.0.0.0',
            'udp_text_port': 9100,
            'chrome_cmd_template': "chromium --no-first-run --disable-infobars --kiosk --start-maximized --remote-debugging-port={debug} '{url}'",
            'reset_time': 3600,
            'hmac_secret': '',
            'allowed_ips': []
        }
        logger.warning("Using default config")


def check_ip(ip):
    """Check if IP is allowed"""
    allowed = config.get('allowed_ips', [])
    return not allowed or ip in allowed


def check_hmac(msg, sig):
    """Verify HMAC signature"""
    secret = config.get('hmac_secret', '')
    if not secret:
        return True
    calc = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calc, sig)


def start_watchdog():
    """Start systemd watchdog thread"""
    usec = os.environ.get('WATCHDOG_USEC')
    if not usec:
        return
    interval = int(usec) / 2000000.0
    
    def ping():
        while running:
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                s.sendto(b'WATCHDOG=1', os.environ.get('NOTIFY_SOCKET', ''))
                s.close()
            except:
                pass
            time.sleep(interval)
    
    threading.Thread(target=ping, daemon=True).start()
    logger.info(f"Watchdog started: {interval}s")


def start_browser(url=None):
    """Start Chrome browser"""
    global chrome_proc, chrome_browser, chrome_tab
    
    if chrome_proc:
        logger.warning("Browser already running")
        return
    
    url = url or config.get('start_url')
    cmd = config.get('chrome_cmd_template').format(
        debug=config.get('debug_port', 9222),
        url=url
    )
    
    logger.info(f"Starting browser: {cmd}")
    chrome_proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(3)
    
    try:
        chrome_browser = pychrome.Browser(url=f"http://127.0.0.1:{config.get('debug_port', 9222)}")
        tabs = chrome_browser.list_tab()
        if tabs:
            chrome_tab = tabs[0]
            chrome_tab.start()
            logger.info("Browser connected")
            start_reset_timer()
    except Exception as e:
        logger.error(f"Failed to connect: {e}")


def stop_browser():
    """Stop Chrome browser"""
    global chrome_proc, chrome_browser, chrome_tab, reset_timer_obj
    
    if reset_timer_obj:
        reset_timer_obj.cancel()
        reset_timer_obj = None
    
    if chrome_tab:
        try:
            chrome_tab.stop()
        except:
            pass
        chrome_tab = None
    
    chrome_browser = None
    
    if chrome_proc:
        try:
            chrome_proc.terminate()
            chrome_proc.wait(timeout=5)
        except:
            chrome_proc.kill()
        chrome_proc = None
    
    logger.info("Browser stopped")


def navigate(url):
    """Navigate to URL"""
    if chrome_tab:
        try:
            chrome_tab.call_method("Page.navigate", url=url, _timeout=5)
            logger.info(f"Navigated to {url}")
            start_reset_timer()
        except Exception as e:
            logger.error(f"Navigate failed: {e}")


def reload():
    """Reload page"""
    if chrome_tab:
        try:
            chrome_tab.call_method("Page.reload", _timeout=5)
            logger.info("Page reloaded")
            start_reset_timer()
        except Exception as e:
            logger.error(f"Reload failed: {e}")


def clear():
    """Clear cache"""
    if chrome_tab:
        try:
            chrome_tab.call_method("Network.clearBrowserCache", _timeout=5)
            chrome_tab.call_method("Network.clearBrowserCookies", _timeout=5)
            logger.info("Cache cleared")
        except Exception as e:
            logger.error(f"Clear failed: {e}")


def get_status():
    """Get status"""
    return {
        'running': chrome_proc is not None,
        'pid': chrome_proc.pid if chrome_proc else None,
        'url': config.get('start_url'),
        'reset_time': config.get('reset_time')
    }


def start_reset_timer():
    """Start auto-reset timer"""
    global reset_timer_obj
    
    if reset_timer_obj:
        reset_timer_obj.cancel()
    
    reset_time = config.get('reset_time', 0)
    if reset_time > 0:
        def reset():
            logger.info("Auto-reset triggered")
            navigate(config.get('start_url'))
        
        reset_timer_obj = threading.Timer(reset_time, reset)
        reset_timer_obj.start()
        logger.info(f"Reset timer: {reset_time}s")


def handle_cmd(cmd, params):
    """Handle command"""
    logger.info(f"Command: {cmd} {params}")
    
    if cmd == 'start':
        start_browser(params.get('url'))
    elif cmd == 'stop':
        stop_browser()
    elif cmd == 'restart':
        stop_browser()
        time.sleep(1)
        start_browser(params.get('url'))
    elif cmd == 'reload':
        reload()
    elif cmd == 'goto':
        if params.get('url'):
            navigate(params['url'])
    elif cmd == 'clear':
        clear()
    elif cmd == 'status':
        logger.info(f"Status: {get_status()}")
    elif cmd == 'set_reset_time':
        config['reset_time'] = int(params.get('seconds', 0))
        start_reset_timer()


def start_osc():
    """Start OSC server"""
    global osc_srv
    
    disp = Dispatcher()
    disp.map("/start", lambda a, *args: handle_cmd('start', {'url': args[0] if args else None}))
    disp.map("/stop", lambda a, *args: handle_cmd('stop', {}))
    disp.map("/restart", lambda a, *args: handle_cmd('restart', {'url': args[0] if args else None}))
    disp.map("/reload", lambda a, *args: handle_cmd('reload', {}))
    disp.map("/goto", lambda a, url: handle_cmd('goto', {'url': url}))
    disp.map("/set_reset_time", lambda a, s: handle_cmd('set_reset_time', {'seconds': s}))
    disp.map("/clear", lambda a, *args: handle_cmd('clear', {}))
    disp.map("/status", lambda a, *args: handle_cmd('status', {}))
    
    osc_srv = ThreadingOSCUDPServer(
        (config.get('osc_bind', '0.0.0.0'), config.get('osc_port', 9000)),
        disp
    )
    threading.Thread(target=osc_srv.serve_forever, daemon=True).start()
    logger.info(f"OSC: {config.get('osc_bind')}:{config.get('osc_port')}")


def start_udp():
    """Start UDP server"""
    global udp_sock
    
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind((config.get('udp_text_bind', '0.0.0.0'), config.get('udp_text_port', 9100)))
    
    def recv():
        while running:
            try:
                data, addr = udp_sock.recvfrom(4096)
                ip = addr[0]
                
                if not check_ip(ip):
                    logger.warning(f"Blocked {ip}")
                    continue
                
                msg = data.decode('utf-8').strip()
                parts = msg.split()
                if not parts:
                    continue
                
                cmd = parts[0]
                args = parts[1:]
                
                if config.get('hmac_secret') and args:
                    sig = args[-1]
                    payload = ' '.join([cmd] + args[:-1])
                    if not check_hmac(payload, sig):
                        logger.warning(f"Bad HMAC from {ip}")
                        continue
                    args = args[:-1]
                
                params = {}
                if cmd in ['start', 'restart', 'goto']:
                    params['url'] = args[0] if args else None
                
                handle_cmd(cmd, params)
            except Exception as e:
                if running:
                    logger.error(f"UDP error: {e}")
    
    threading.Thread(target=recv, daemon=True).start()
    logger.info(f"UDP: {config.get('udp_text_bind')}:{config.get('udp_text_port')}")


def sig_handler(signum, frame):
    """Signal handler"""
    global running
    logger.info(f"Signal {signum}")
    running = False


def main():
    """Main entry point"""
    global running
    
    cfg_path = os.environ.get('KIOSC_CONFIG', '/etc/kiosc-browsr/config.yaml')
    load_config(cfg_path)
    
    start_watchdog()
    start_osc()
    start_udp()
    
    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)
    
    if config.get('autostart', True):
        start_browser()
    
    logger.info("Service running")
    
    try:
        while running:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    
    logger.info("Shutting down")
    stop_browser()
    if osc_srv:
        osc_srv.shutdown()
    if udp_sock:
        udp_sock.close()
    logger.info("Stopped")


if __name__ == '__main__':
    main()
