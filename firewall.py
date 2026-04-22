from pox.core import core
import pox.openflow.libopenflow_01 as of
import datetime
import os

log = core.getLogger()

# =========================
# RULES 
# =========================
BLOCK_IP_RULES = [("10.0.0.1", "10.0.0.2")]   # h1 -> h2
BLOCK_MACS = ["82:00:cf:dd:38:55"]
BLOCK_PORTS = [80, 443]

# =========================
#  LOG FUNCTION
# =========================
def log_to_file(msg):
    path = os.path.expanduser("~/firewall.log")
    with open(path, "a") as f:
        f.write(f"{datetime.datetime.now()} {msg}\n")

# =========================
#  INSTALL DROP RULE
# =========================
def install_drop(event, ip=None, mac=None, port=None):
    flow = of.ofp_flow_mod()
    flow.priority = 100  # higher priority than normal forwarding
    flow.idle_timeout = 30
    flow.hard_timeout = 60

    if ip:
        flow.match.dl_type = 0x0800
        flow.match.nw_src = ip[0]
        flow.match.nw_dst = ip[1]

    if mac:
        flow.match.dl_src = mac

    if port:
        flow.match.dl_type = 0x0800
        flow.match.tp_dst = port

    flow.actions = []  # DROP
    event.connection.send(flow)

# =========================
#  PACKET HANDLER
# =========================
def _handle_PacketIn(event):
    packet = event.parsed

    if not packet:
        return

    ip_pkt = packet.find('ipv4')
    tcp_pkt = packet.find('tcp')
    eth_pkt = packet.find('ethernet')

    #  MAC FILTER
    if eth_pkt:
        if str(eth_pkt.src) in BLOCK_MACS:
            msg = f"[BLOCKED MAC] {eth_pkt.src}"
            log.info(msg)
            log_to_file(msg)

            install_drop(event, mac=eth_pkt.src)
            return

    #  IP + PORT FILTER
    if ip_pkt:
        src_ip = str(ip_pkt.srcip)
        dst_ip = str(ip_pkt.dstip)

        if (src_ip, dst_ip) in BLOCK_IP_RULES:
            msg = f"[BLOCKED IP] {src_ip} → {dst_ip}"
            log.info(msg)
            log_to_file(msg)

            install_drop(event, ip=(ip_pkt.srcip, ip_pkt.dstip))
            return

        if tcp_pkt and tcp_pkt.dstport in BLOCK_PORTS:
            msg = f"[BLOCKED PORT] {src_ip} → {dst_ip} PORT {tcp_pkt.dstport}"
            log.info(msg)
            log_to_file(msg)

            install_drop(event, port=tcp_pkt.dstport)
            return

    #  IMPORTANT: DO NOTHING for allowed traffic
    # Let forwarding.l2_learning handle it
    return

# =========================
#  START MODULE
# =========================
def launch():
    log.info("------- Advanced SDN Firewall Loaded-------")
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
