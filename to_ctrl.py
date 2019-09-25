import numpy as np
import time
from pox.lib.recoco import Timer
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr

log = core.getLogger()
syn_counter = 0
forward_rule_set = 0
backward_rule_set = 0
counter_s1 = 1
counter_s2 = 1
samples1 = []
samples2 = []
mac_port_dict = {}

def flood_packet (event, dst_port = of.OFPP_ALL):
  msg = of.ofp_packet_out(in_port=event.ofp.in_port)
  if event.ofp.buffer_id != -1 and event.ofp.buffer_id is not None:
    msg.buffer_id = event.ofp.buffer_id
  else:
    if event.ofp.data:
      return
    msg.data = event.ofp.data
  msg.actions.append(of.ofp_action_output(port = dst_port))
  event.connection.send(msg)

def initialize_watermark_array(mu, sigma):
  log.debug("creating watermaek array with params : "+ str(mu) + "    "+ str(sigma))
  samples = np.random.normal(mu, sigma, 1000)
  return samples

def _handle_PacketIn (event):

  global syn_counter
  packet =event.parsed
  global forward_rule_set
  global backward_rule_set
  global counter_s1
  global counter_s2
  global samples1
  global samples2
  global mac_port_dict
  skip_add_to_dict = 0

  ipv4_pack = packet.find("ipv4")
  if ipv4_pack:
            log.debug("IP: trying to send a message "+str(ipv4_pack.srcip)+"<->"+str(ipv4_pack.dstip))
	    if (forward_rule_set == 0):
            	   log.debug("forward rule set 0. setting rule")
		   msg = of.ofp_flow_mod()
            	   msg.priority = 65535
                   msg.match.dl_type = 0x800
	    	   #msg.match.dl_dst = "00:00:00:00:00:03"
                   msg.match.nw_dst = "10.0.0.3"
            	   msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
            	   #event.connection.send(msg)
                   #forward_rule_set = 1
                   #send_packet(event, of.OFPP_ALL)
	    if (backward_rule_set == 0):
		   log.debug("backward rule set 0. setting rule")
		   msg = of.ofp_flow_mod()
		   msg.priority = 65535
		   msg.match.dl_type = 0x800
		   #msg.match.dl_src = "00:00:00:00:00:03"
		   msg.match.nw_src = "10.0.0.3"
		   msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
		   #event.connection.send(msg)
		   #backward_rule_set = 1
		   #send_packet(event, of.OFPP_ALL)
	    log.debug("packet forwarding  " + str(packet.src) + "  " + str(packet.dst))
            if (str(packet.dst) == "00:00:00:00:00:03"):
		   log.debug("***bound to protected resource from controller***")
		   #send_packet(event, packet)
		   skip_add_to_dict = 1
		   if forward_rule_set == 0:
			log.debug("****** Setting forward rule ********")
		   	msg = of.ofp_flow_mod()
		   	msg.match = of.ofp_match.from_packet(packet, event.port)
		   	msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
		   	msg.data = event.ofp
		   	#event.connection.send(msg)
		   	forward_rule_set = 1
            if (str(packet.src) == "00:00:00:00:00:03"):
		   if backward_rule_set == 0:
			log.debug("**** Setting backward rule *******")
			msg = of.ofp_flow_mod()
			msg.match = of.ofp_match.from_packet(packet, event.port)
			msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
			msg.data = event.ofp
			#event.connection.send(msg)
			backward_rule_set = 1
                   log.debug("****inserting"+str(samples1[counter_s1%1000])+" seconds delay here - src Protected***")
                   time.sleep(samples1[counter_s1 % 1000])
                   counter_s1 = counter_s1 + 1
                   skip_add_to_dict = 1
		   #send_packet(event, of.OFPP_ALL)
  if skip_add_to_dict != 1:
  	mac_port_dict[packet.src] = event.port
  if packet.dst not in mac_port_dict:
	flood_packet(event, of.OFPP_ALL)
	log.debug("flooding to all ports as no entry in dictionary")
  else:
	port = mac_port_dict[packet.dst]
	log.debug("setting a flow table entry - matching entry found in dict")
	msg = of.ofp_flow_mod()
	#msg.priority = 1009
	msg.match = of.ofp_match.from_packet(packet, event.port)
	msg.priority = 1009
	msg.actions.append(of.ofp_action_output(port = port))
	msg.data = event.ofp
	event.connection.send(msg)
  #send_packet(event, of.OFPP_ALL)
  #log.debug("[+] Broadcasting %s.%i -> %s.%i" %
   # (packet.src, event.ofp.in_port, packet.dst, of.OFPP_ALL))

  p = packet
  while p:
    ic = packet.find("icmp")
    i4 = packet.find("ipv4")
    if not hasattr(p, 'next'): break
    p = p.next

def _handle_ConnectionUp (event):
  log.debug("[!] HubACLs v0.0.1 Running %s", dpidToStr(event.dpid))
  global samples1
  global samples2
  samples1 = initialize_watermark_array(1,0.3)
  samples2 = initialize_watermark_array(2.5,1.2)

def check_flows ():
  log.debug("[!] +5s Periodic Interval. Total SYN pakcets served : %d", syn_counter)

def launch ():
  Timer(5,check_flows,recurring = True)
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("PacketIn",_handle_PacketIn)

