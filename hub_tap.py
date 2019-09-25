from pox.lib.recoco import Timer
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr

log = core.getLogger()
syn_counter = 0

def send_packet (event, dst_port = of.OFPP_ALL):
  msg = of.ofp_packet_out(in_port=event.ofp.in_port)
  if event.ofp.buffer_id != -1 and event.ofp.buffer_id is not None:
    msg.buffer_id = event.ofp.buffer_id
  else:
    if event.ofp.data:
      return
    msg.data = event.ofp.data
  msg.actions.append(of.ofp_action_output(port = dst_port))
  event.connection.send(msg)

def _handle_PacketIn (event):

  global syn_counter
  packet =event.parsed
  send_packet(event, of.OFPP_ALL)
  log.debug("[+] Broadcasting %s.%i -> %s.%i" %
    (packet.src, event.ofp.in_port, packet.dst, of.OFPP_ALL))

  p = packet
  while p:
    ic = packet.find("icmp")
    i4 = packet.find("ipv4")
    if not hasattr(p, 'next'): break
    p = p.next

    #if ic:
            #log.debug("ICMP Packet")
    if i4:
            log.debug("IP: "+str(i4.srcip)+"<->"+str(i4.dstip))
            tcp = packet.find("tcp")
            if tcp:
              log.debug("TCP pakcet! - SYN : %d   FIN: %d  ACK: %d ", tcp.SYN, tcp.FIN, tcp.ACK)
              if tcp.SYN and (not tcp.ACK):
                log.debug("SYN Packet!!")
                syn_counter = syn_counter + 1
            

def _handle_ConnectionUp (event):
  log.debug("[!] HubACLs v0.0.1 Running %s", dpidToStr(event.dpid))

def check_flows ():
  log.debug("[!] +5s Periodic Interval. Total SYN pakcets served : %d", syn_counter)

def launch ():
  Timer(5,check_flows,recurring = True)
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("PacketIn",_handle_PacketIn)

