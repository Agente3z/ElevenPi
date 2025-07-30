from flask import Flask, render_template, send_from_directory
from flask_socketio import SocketIO
from main import Dot11Pi, AccessPoint
import os, sys, logging
from threading import Thread
from subprocess import Popen, PIPE
from time import sleep

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), '../templates'), static_folder=os.path.join(os.path.dirname(__file__), '../static'))
socketio = SocketIO(app)
dot11pi = Dot11Pi(logging_level=logging.DEBUG)

@app.route('/')
def index():
    logging.info("Rendering frontend.html")
    return render_template('frontend.html')

@app.route('/webfonts/<path:filename>')
def webfonts(filename):
    logging.info(f"Serving webfont: {filename}")
    return send_from_directory(os.path.join(app.root_path, '../static/webfonts'), filename)

@socketio.on('manage_services')
def handle_manage_services(data):
    option = data['option']
    logging.info(f"Managing services: {option}")
    dot11pi.manage_services(option)
    socketio.emit('manage_services_data', {'option': option})

@socketio.on('list_interfaces')
def handle_list_interfaces():
    logging.info("Listing interfaces")
    interfaces = dot11pi.list_interfaces()
    interfaces_with_modes = [{'iface': iface, 'mode': dot11pi.check_interface_mode(iface)} for iface in interfaces]
    socketio.emit('interfaces_data', {'interfaces': interfaces_with_modes})

@socketio.on('iface_set_mode')
def handle_iface_set_mode(data):
    iface = data['iface']
    mode = data['mode']
    logging.info(f"Setting interface {iface} to mode {mode}")
    dot11pi.iface_set_mode(iface, mode)
    socketio.emit('iface_set_mode_data', {'message': f'Interface {iface} set to mode {mode}'})

@socketio.on('scan_ap')
def handle_scan_ap(data):
    iface = data['iface']
    logging.info(f"Starting AP scan on interface {iface}")
    socketio.emit('scan_ap_data', {'message': 'Scan started'})
    aps = dot11pi.scan_ap(iface)
    while not dot11pi.events["ap_scan"].is_set():
        try:
            ap = aps.get(timeout=1)
            socketio.emit('new_ap', {'ssid': ap.ssid, 'bssid': ap.bssid, 'channel': ap.channel})
        except:
            pass

@socketio.on('stop_scan_ap')
def handle_stop_scan_ap():
    logging.info("Stopping AP scan")
    dot11pi.stop_scan_ap()
    socketio.emit('scan_ap_data', {'message': 'Scan stopped'})

@socketio.on('start_sniffing')
def handle_start_sniffing(data):
    iface = data['iface']
    ap = AccessPoint(data['ssid'], data['bssid'], data['channel'])
    logging.info(f"Starting sniffing on interface {iface} for AP {ap}")
    socketio.emit('sniffing_data', {'message': 'Sniffing started'})
    dot11pi.start_sniffing(iface, ap)
    while not dot11pi.events["sniff"].is_set():
        dot11pi.events["hash_found"].wait(timeout=1)
        if dot11pi.events["hash_found"].is_set():
            socketio.emit('sniffing_data', {'message': 'Hash found'})

@socketio.on('stop_sniffing')
def handle_stop_sniffing():
    logging.info("Stopping sniffing")
    dot11pi.stop_sniffing()
    socketio.emit('sniffing_data', {'message': 'Sniffing stopped'})

@socketio.on('sniff_clients')
def handle_sniff_clients(data):
    iface = data['iface']
    ap = AccessPoint(data['ssid'], data['bssid'], data['channel'])
    logging.info(f"Starting client sniffing on interface {iface} for AP {ap}")
    socketio.emit('sniff_clients_data', {'message': 'Sniffing clients started'})
    clients = dot11pi.sniff_clients(iface, ap)
    while not dot11pi.events["sniff_clients"].is_set():
        try:
            client = clients.get(timeout=1)
            socketio.emit('new_client', {'client': client})
        except:
            pass

@socketio.on('stop_sniff_clients')
def handle_stop_sniff_clients():
    logging.info("Stopping client sniffing")
    dot11pi.stop_sniffing_clients()
    socketio.emit('sniff_clients_data', {'message': 'Sniffing clients stopped'})

@socketio.on('deauth')
def handle_deauth(data):
    iface = data['iface']
    ap = AccessPoint(data['ssid'], data['bssid'], data['channel'])
    client = data['client']
    logging.info(f"Sending deauth to client {client} on AP {ap} using interface {iface}")
    dot11pi.deauth(client, ap, iface)
    socketio.emit('deauth_data', {'message': 'Deauth sent'})

@socketio.on('start_captive_portal')
def handle_start_captive_portal(data):
    iface = data['iface']
    ap = AccessPoint(data['ssid'], data['bssid'], data['channel'])
    logging.info(f"Starting captive portal on interface {iface} for AP {ap}")
    flask_output = dot11pi.start_captive_portal(iface, ap)
    socketio.emit('captive_portal_data', {'message': 'Captive portal started'})
    while not dot11pi.events["key_found"].is_set():
        try:
            output = flask_output.get(timeout=1)
            if "INFO" in output:
                socketio.emit('captive_portal_data', {'message': output})
        except:
            pass
        if dot11pi.events["key_found"].is_set():
            socketio.emit('captive_portal_data', {'message': 'Key found'})
            break

@socketio.on('stop_captive_portal')
def handle_stop_captive_portal():
    logging.info("Stopping captive portal")
    dot11pi.stop_captive_portal()
    socketio.emit('captive_portal_data', {'message': 'Captive portal stopped'})

@socketio.on('shutdown')
def handle_shutdown():
    logging.info("Shutting down system")
    os.system('shutdown now')

@socketio.on('reboot')
def handle_reboot():
    logging.info("Rebooting system")
    os.system('reboot')

@socketio.on('logins')
def handle_logins():
    logging.info("Getting logins")
    logins = dot11pi.get_logins()
    socketio.emit('logins_data', {'logins': logins})

@socketio.on('start_sharing_hashes')
def handle_start_sharing_hashes(data):
    iface = data['iface']
    logging.info(f"Starting hash sharing on interface {iface}")
    password = dot11pi.start_sharing_hashes(iface)
    socketio.emit('hash_sharing_data', {'message': 'Hash sharing started', 'password': password})

@socketio.on('stop_sharing_hashes')
def handle_stop_sharing_hashes():
    logging.info("Stopping hash sharing")
    dot11pi.stop_sharing_hashes()
    socketio.emit('hash_sharing_data', {'message': 'Hash sharing stopped'})

def elevate_to_root():
    if os.geteuid() != 0:
        logging.info("Elevating to root")
        args = ['sudo', sys.executable] + sys.argv
        os.execvp('sudo', args)

def monitor_journalctl():
    sleep(5)
    first = Popen(['journalctl', '-u', 'dot11pi', '--no-pager'], stdout=PIPE, stderr=PIPE).stdout.read().decode()
    socketio.emit('journalctl_output', {'message': first})
    process = Popen(['journalctl', '-fu', 'dot11pi'], stdout=PIPE, stderr=PIPE)
    while True:
        output = process.stdout.readline().decode().strip()
        if output and 'Running DEBUG' not in output:
            socketio.emit('journalctl_output', {'message': output})

# Start the journalctl monitoring thread
Thread(target=monitor_journalctl, daemon=True).start()

if __name__ == "__main__":
    elevate_to_root()
    socketio.run(app, host='127.0.0.1', port=5000, allow_unsafe_werkzeug=True)