#!/usr/bin/env python3
"""KiOSC-BrowsR Service - Browser remote control for kiosk systems"""

import os, sys, time, hmac, hashlib, socket, subprocess, threading, signal, yaml, logging
from pythonosc.dispatcher import Dispatcher
from pythonosc.osc_server import ThreadingOSCUDPServer
import pychrome

# Logging
logger = logging.getLogger('kiosc')
logger.setLevel(logging.INFO)
fh = logging.FileHandler('/var/log/kiosc-browsr.log')
ch = logging.StreamHandler(sys.stdout)
fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
fh.setFormatter(fmt)
ch.setFormatter(fmt)
logger.addHandler(fh)
logger.addHandler(ch)

# State
state = {
    'config': {},
    'chrome_process': None,
    'chrome_browser': None,
    'chrome_tab': None,
    'reset_timer': None,
    'running': True,
    'osc_server': None,
    'udp_socket': None
}


def read_yaml_config(path):
    """Read configuration from YAML file"""
    try:
        with open(path) as f:
            state['config'] = yaml.safe_load(f)
        logger.info(f"Loaded config: {path}")
    except:
        state['config'] = {
            'start_url': 'https://example.com', 'debug_port': 9222, 'autostart': True,
            'osc_bind': '0.0.0.0', 'osc_port': 9000, 'udp_text_bind': '0.0.0.0',
            'udp_text_port': 9100, 'reset_time': 3600, 'hmac_secret': '', 'allowed_ips': [],
            'chrome_cmd_template': "chromium --no-first-run --disable-infobars --kiosk --start-maximized --remote-debugging-port={debug} '{url}'"
        }
        logger.warning("Using defaults")


def validate_client_ip(ip):
    """Check if IP is in whitelist"""
    whitelist = state['config'].get('allowed_ips', [])
    return not whitelist or ip in whitelist


def validate_hmac_auth(message, signature):
    """Verify HMAC signature"""
    secret = state['config'].get('hmac_secret', '')
    if not secret:
        return True
    computed = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, signature)


def init_watchdog_thread():
    """Initialize systemd watchdog"""
    watchdog_usec = os.environ.get('WATCHDOG_USEC')
    if not watchdog_usec:
        return
    
    interval_seconds = int(watchdog_usec) / 2000000.0
    
    def watchdog_loop():
        while state['running']:
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                sock.sendto(b'WATCHDOG=1', os.environ.get('NOTIFY_SOCKET', ''))
                sock.close()
            except:
                pass
            time.sleep(interval_seconds)
    
    threading.Thread(target=watchdog_loop, daemon=True).start()
    logger.info(f"Watchdog: {interval_seconds}s")


def launch_chrome(target_url=None):
    """Launch Chrome browser process"""
    if state['chrome_process']:
        logger.warning("Chrome already running")
        return
    
    url = target_url or state['config'].get('start_url')
    cmd = state['config'].get('chrome_cmd_template').format(
        debug=state['config'].get('debug_port', 9222),
        url=url
    )
    
    logger.info(f"Launching: {cmd}")
    state['chrome_process'] = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(3)
    
    try:
        state['chrome_browser'] = pychrome.Browser(url=f"http://127.0.0.1:{state['config'].get('debug_port', 9222)}")
        tabs = state['chrome_browser'].list_tab()
        if tabs:
            state['chrome_tab'] = tabs[0]
            state['chrome_tab'].start()
            logger.info("Chrome connected")
            schedule_auto_reset()
    except Exception as e:
        logger.error(f"Connection error: {e}")


def terminate_chrome():
    """Terminate Chrome browser"""
    if state['reset_timer']:
        state['reset_timer'].cancel()
        state['reset_timer'] = None
    
    if state['chrome_tab']:
        try:
            state['chrome_tab'].stop()
        except:
            pass
        state['chrome_tab'] = None
    
    state['chrome_browser'] = None
    
    if state['chrome_process']:
        try:
            state['chrome_process'].terminate()
            state['chrome_process'].wait(timeout=5)
        except:
            state['chrome_process'].kill()
        state['chrome_process'] = None
    
    logger.info("Chrome terminated")


def goto_url(url):
    """Navigate to URL"""
    if state['chrome_tab']:
        try:
            state['chrome_tab'].call_method("Page.navigate", url=url, _timeout=5)
            logger.info(f"Navigated: {url}")
            schedule_auto_reset()
        except Exception as e:
            logger.error(f"Nav error: {e}")


def refresh_page():
    """Reload current page"""
    if state['chrome_tab']:
        try:
            state['chrome_tab'].call_method("Page.reload", _timeout=5)
            logger.info("Reloaded")
            schedule_auto_reset()
        except Exception as e:
            logger.error(f"Reload error: {e}")


def purge_browser_data():
    """Clear cache and cookies"""
    if state['chrome_tab']:
        try:
            state['chrome_tab'].call_method("Network.clearBrowserCache", _timeout=5)
            state['chrome_tab'].call_method("Network.clearBrowserCookies", _timeout=5)
            logger.info("Data cleared")
        except Exception as e:
            logger.error(f"Clear error: {e}")


def query_status():
    """Get current status"""
    return {
        'active': state['chrome_process'] is not None,
        'pid': state['chrome_process'].pid if state['chrome_process'] else None,
        'home': state['config'].get('start_url'),
        'reset_interval': state['config'].get('reset_time')
    }


def schedule_auto_reset():
    """Schedule automatic reset timer"""
    if state['reset_timer']:
        state['reset_timer'].cancel()
    
    interval = state['config'].get('reset_time', 0)
    if interval > 0:
        def execute_reset():
            logger.info("Auto-reset")
            goto_url(state['config'].get('start_url'))
        
        state['reset_timer'] = threading.Timer(interval, execute_reset)
        state['reset_timer'].start()
        logger.info(f"Reset timer: {interval}s")


def dispatch_command(cmd_name, cmd_params):
    """Dispatch command to appropriate handler"""
    logger.info(f"Cmd: {cmd_name} {cmd_params}")
    
    if cmd_name == 'start':
        launch_chrome(cmd_params.get('url'))
    elif cmd_name == 'stop':
        terminate_chrome()
    elif cmd_name == 'restart':
        terminate_chrome()
        time.sleep(1)
        launch_chrome(cmd_params.get('url'))
    elif cmd_name == 'reload':
        refresh_page()
    elif cmd_name == 'goto':
        if cmd_params.get('url'):
            goto_url(cmd_params['url'])
    elif cmd_name == 'clear':
        purge_browser_data()
    elif cmd_name == 'status':
        logger.info(f"Status: {query_status()}")
    elif cmd_name == 'set_reset_time':
        state['config']['reset_time'] = int(cmd_params.get('seconds', 0))
        schedule_auto_reset()


def init_osc_protocol():
    """Initialize OSC protocol server"""
    disp = Dispatcher()
    disp.map("/start", lambda a, *args: dispatch_command('start', {'url': args[0] if args else None}))
    disp.map("/stop", lambda a, *args: dispatch_command('stop', {}))
    disp.map("/restart", lambda a, *args: dispatch_command('restart', {'url': args[0] if args else None}))
    disp.map("/reload", lambda a, *args: dispatch_command('reload', {}))
    disp.map("/goto", lambda a, url: dispatch_command('goto', {'url': url}))
    disp.map("/set_reset_time", lambda a, s: dispatch_command('set_reset_time', {'seconds': s}))
    disp.map("/clear", lambda a, *args: dispatch_command('clear', {}))
    disp.map("/status", lambda a, *args: dispatch_command('status', {}))
    
    state['osc_server'] = ThreadingOSCUDPServer(
        (state['config'].get('osc_bind', '0.0.0.0'), state['config'].get('osc_port', 9000)),
        disp
    )
    threading.Thread(target=state['osc_server'].serve_forever, daemon=True).start()
    logger.info(f"OSC server: {state['config'].get('osc_bind')}:{state['config'].get('osc_port')}")


def init_udp_protocol():
    """Initialize UDP plaintext server"""
    state['udp_socket'] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    state['udp_socket'].setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    state['udp_socket'].bind((
        state['config'].get('udp_text_bind', '0.0.0.0'),
        state['config'].get('udp_text_port', 9100)
    ))
    
    def udp_receiver_loop():
        while state['running']:
            try:
                packet, sender = state['udp_socket'].recvfrom(4096)
                sender_ip = sender[0]
                
                if not validate_client_ip(sender_ip):
                    logger.warning(f"Blocked: {sender_ip}")
                    continue
                
                message = packet.decode('utf-8').strip()
                tokens = message.split()
                if not tokens:
                    continue
                
                verb = tokens[0]
                arguments = tokens[1:]
                
                if state['config'].get('hmac_secret') and arguments:
                    signature = arguments[-1]
                    plaintext = ' '.join([verb] + arguments[:-1])
                    if not validate_hmac_auth(plaintext, signature):
                        logger.warning(f"HMAC fail: {sender_ip}")
                        continue
                    arguments = arguments[:-1]
                
                params = {}
                if verb in ['start', 'restart', 'goto']:
                    params['url'] = arguments[0] if arguments else None
                
                dispatch_command(verb, params)
            except Exception as e:
                if state['running']:
                    logger.error(f"UDP error: {e}")
    
    threading.Thread(target=udp_receiver_loop, daemon=True).start()
    logger.info(f"UDP server: {state['config'].get('udp_text_bind')}:{state['config'].get('udp_text_port')}")


def handle_signal(signum, frame):
    """Handle termination signal"""
    logger.info(f"Signal: {signum}")
    state['running'] = False


def main():
    """Main entry point"""
    config_file = os.environ.get('KIOSC_CONFIG', '/etc/kiosc-browsr/config.yaml')
    read_yaml_config(config_file)
    
    init_watchdog_thread()
    init_osc_protocol()
    init_udp_protocol()
    
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    
    if state['config'].get('autostart', True):
        launch_chrome()
    
    logger.info("Service active")
    
    try:
        while state['running']:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    
    logger.info("Shutdown")
    terminate_chrome()
    if state['osc_server']:
        state['osc_server'].shutdown()
    if state['udp_socket']:
        state['udp_socket'].close()
    logger.info("Exit")


if __name__ == '__main__':
    main()
