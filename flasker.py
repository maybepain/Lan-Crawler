#PACKAGE_IMPORT
import os
import threading
import psutil
from scapy.all import arping, sniff, IP
from flask import Flask, render_template, request, redirect, url_for
from flask_socketio import SocketIO
from mac_vendor_lookup import MacLookup

#GLOBAL VARIABLES

interfaces = psutil.net_if_stats()
shared_storage = {}

#FLASK STARTING
app=Flask(__name__)


#DISCLAIMER PAGE
@app.route("/",methods=["GET","POST"])
def home():
	if request.method == "POST":
		return redirect(url_for("interface_page"))
	return render_template("disclaimer.html")


#CHOOSE INTERFACE PAGE
@app.route("/interface_page",methods=["GET","POST"])
def interface_page():
	if request.method == "POST":
		global interface_now
		interface_now = request.form.get("interface")
		shared_storage.update({"ipaddress" : interface_now})
		print(interface_now)
		return redirect(url_for("home_page"))
	interfaces_list=[ i for i in interfaces]
	return 	render_template("interface.html",interfaces_list=interfaces_list)

#HOMEPAGE	
@app.route("/home", methods=['GET','POST'])
def home_page():
	return render_template("home_page.html")

#INTERFACE DETAILS
@app.route("/details", methods=["POST","GET"])
def interface_details():
	if request.method == "POST":
		return redirect(url_for("interface_page"))
	if shared_storage:
		interface_name = shared_storage["ipaddress"] 	
		interface=psutil.net_if_addrs().get(interface_name)
		ipv4address = None
		ipv4address_subnet = None
		ipv4address_broadcast = None
		ipv6address = None
		mac_address = None
		
		for i in interface:
			if i.family == 2:
				ipv4address = i.address
				ipv4address_subnet = i.netmask
				ipv4address_broadcast = i.broadcast
			elif i.family == 10:
				ipv6address = i.address
			elif i.family == 17:
				mac_address = i.address
			return render_template("interface_details.html", 
			ipv4address=ipv4address,
			ipv4address_subnet=ipv4address_subnet,
			ipv4address_broadcast=ipv4address_broadcast,
			ipv6address=ipv6address,
			mac_address=mac_address,
			interface_name=interface_name)
	else:
		return '''
		<h1>hello interface not selected </h1>
		<form method = "POST">
		<button type="submit">GO INTERFACE PAGE</button>
		</form>
		'''
#DEVICE DISCOVERY 
@app.route("/discovery")
def discovery():
	answered, unanswerd = arping("192.168.1.0/24", verbose=False)
	ip_recieved = {}
	ip_vendor_name_list = {}
	for sent, recieved in answered:
		ip_recieve = recieved.psrc
		mac_recieve = recieved.hwsrc
		try:
			ip_vendor_name = MacLookup().lookup( mac_recieve )
		except:
			ip_vendor_name = "unknown vendor"
			
		ip_recieved[ip_recieve] = mac_recieve
		ip_vendor_name_list[ip_recieve] = ip_vendor_name 
	return render_template ("discovery.html",
	ip_recieved = ip_recieved,
	ip_vendor_name_list = ip_vendor_name_list)


#PACKET_SENDER

#PACKET_SNIFFER
socketio = SocketIO(app, async_mode="threading")
MAX_PACKETS = 100
recent_packets = []
packets_lock = threading.Lock()


@app.route("/packet_sniffer")
def getter():
    return render_template("packet_sniffer.html")


@socketio.on("connect")
def handle_connect():
    with packets_lock:
        snapshot = list(recent_packets)
    socketio.emit("sniff_list", snapshot)


def packet_getter(packet):
    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]

    entry = {
        "source_mac": getattr(packet, "src", None),
        "destination_mac": getattr(packet, "dst", None),
        "source_ip_address": ip_layer.src,
        "destination_ip_address": ip_layer.dst,
        "protocol": ip_layer.proto,
        "version": "ipv4" if ip_layer.version == 4 else "ipv6",

    }

    with packets_lock:
        recent_packets.append(entry)
        if len(recent_packets) > MAX_PACKETS:
            del recent_packets[:-MAX_PACKETS]
    socketio.emit("new_packet", entry)


def sniffer_process():
    sniff(prn=packet_getter, filter="ip", store=False)


def start_sniffer_once():
    if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        sniff_thread = threading.Thread(target=sniffer_process, daemon=True)
        sniff_thread.start()

#APP_RUNNER
if __name__ == ("__main__"):
	start_sniffer_once()
	app.run(debug=True,  use_reloader=True)
	
