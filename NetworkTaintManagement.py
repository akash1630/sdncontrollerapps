import time
import random as random
import pprint
from pox.lib.recoco import Timer
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
import socket
import ipaddr
import threading
import SocketServer
from threading import Thread
import numpy as np
import scipy as sp

import config

from pox.openflow.of_json import *

log = core.getLogger()
tainted_hosts = {}                       #dict: key - tainted hosts (ip addresses), val - timestamp
tainted_hosts_ports = {}                 #dict: key - tainted hosts (ip addresses), val - ports list
suspected_hosts = []                     #list of suspected hosts acting as pivots
isolated_host = []
restricted_hosts = []
spawned_threads_send = {}
spawned_threads_receive = {}
taint_notif_ack_recv = {}
mac_ip_map = {}
ip_mac_map = {}
waiting_for_message = []
tracked_flows = {}
check_for_stats_ctr = 1
data_recvd_from_protected = {}
prune_counter = 0
samples = np.random.normal(250, 35, 1000)
current_inbound_notif = []

############################################################################
#    **** FOR TESTING PURPOSES ****
############################################################################

temp_map = config.temp_map
temp_inverse_map = config.temp_inverse_map


#############################################################################
#define internal network here - ****IMPORTANT****
#############################################################################
internal_ips = config.internal_ips
internal_network = ipaddr.IPNetwork(internal_ips)
protected_resources = config.protected_resources       #list of protected resources
#protected_network = ipaddr.IPNetwork(protected_resources)
hosts_without_agent = config.hosts_without_agent
network_hosts_without_agent = ipaddr.IPNetwork(hosts_without_agent)
isolate_if_pivot_ips = config.isolate_if_pivot_ips
isolate_if_pivot_network = ipaddr.IPNetwork(isolate_if_pivot_ips)
restrict_if_pivot_ips = config.restrict_if_pivot_ips
restrict_if_pivot_network = ipaddr.IPNetwork(restrict_if_pivot_ips)
throttle_outbound_if_pivot_ips = config.throttle_outbound_if_pivot_ips
throttle_outbound_if_pivot_network = ipaddr.IPNetwork(throttle_outbound_if_pivot_ips)
redirect_to_honeynet_ips = config.redirect_to_honeynet_ips
redirect_to_honeynet_network = ipaddr.IPNetwork(redirect_to_honeynet_ips)


#############################################################################
#function to flood packets
#############################################################################
def flood_packet (event, dst_port = of.OFPP_ALL):
  msg = of.ofp_packet_out(in_port=event.ofp.in_port)
  #log.debug("flooding packet for buffer_id " + str(event.ofp.buffer_id))
  if event.ofp.buffer_id != -1 and event.ofp.buffer_id is not None:
    msg.buffer_id = event.ofp.buffer_id
  else:
    if event.ofp.data:
      return
    msg.data = event.ofp.data

  msg.actions.append(of.ofp_action_output(port = dst_port))
  event.connection.send(msg)


##############################################################################
#function to drop packets for isolating pivots
##############################################################################
def drop_packet(event):
  msg = of.ofp_packet_out(in_port=event.ofp.in_port)
  #log.debug("dropping packet for buffer_id " + str(event.ofp.buffer_id))
  if event.ofp.buffer_id != -1 and event.ofp.buffer_id is not None:
    msg.buffer_id = event.ofp.buffer_id
  else:
    if event.ofp.data:
      return
    msg.data = event.ofp.data

  #msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
  event.connection.send(msg)


#############################################################################
#function to add a host to the tainted list
#############################################################################
def add_to_tainted_hosts(host):
  global tainted_hosts
  if host in protected_resources:
    return
  if (tainted_hosts.has_key(host)):
    log.debug("host already present in tainted list. Refreshing time")
    #tainted_hosts[host] = time.time()
  else:
    tainted_hosts[host] = time.time()
    log.debug("added %s to tainted_hosts list ", host)
  pprint.pprint(tainted_hosts)


##############################################################################
#function to add/append tainted ports to the global dict
##############################################################################
def append_to_tainted_ports(host, port):
  global tainted_hosts_ports
  log.debug('Appending a new tainted port')
  if port > 0:
    if tainted_hosts_ports.has_key(host):
      if port not in tainted_hosts_ports[host]:
        tainted_hosts_ports[host].append(port)
    else:
      tainted_hosts_ports[host] = [port]
  pprint.pprint(tainted_hosts_ports)


##############################################################################
#function to delete flow entries for a tainted host from all switches
##############################################################################
def delete_flow_entries(host):
  log.debug("deleting flow table entries for " + str(host))
  msg = of.ofp_flow_mod(command = of.OFPFC_DELETE)
  #msg.priority = 65635
  msg.match.dl_type = 0x800
  msg.match.nw_src = host
  msg2 = of.ofp_flow_mod(command = of.OFPFC_DELETE)
  msg2.match.dl_type = 0x800
  msg2.match.nw_dst = host
  for conn in core.openflow.connections:
    conn.send(msg)
    conn.send(msg2)

##############################################################################
#function tro delete flow entries for a specific host-port pair
##############################################################################
def delete_flow(host, port):
  log.debug("deleting flow entries with src host-port " + str(host) + ": " + str(port))
  msg = of.ofp_flow_mod(command = of.OFPFC_DELETE)
  #msg.priority = 65635
  msg.match.dl_type = 0x800
  msg.match.nw_proto = 6
  msg.match.nw_src = host
  msg.match.tp_src = int(port)
  for conn in core.openflow.connections:
    conn.send(msg)


###############################################################################
#Function to delete all outgoing flows for a host
###############################################################################
def delete_outgoing_flows(host):
  log.debug("deleting all outgoing flows for host: " + str(host))
  msg = of.ofp_flow_mod(command = of.OFPFC_DELETE)
  #msg.priority = 65635
  msg.match.dl_type = 0x800
  msg.match.nw_src = host
  for conn in core.openflow.connections:
    conn.send(msg)


def isolate_host(host):
  log.debug('----------------isolating host : ' + host + ' -------------')
  

#################################################################################
#function to prune tainted list based on a distributed interval - NOT BEING USED
#################################################################################
def prune_tainted_list():
  global prune_counter
  global samples
  log.debug("****** pruning tainted hosts list **********")
  if(prune_counter%30 == 29):
    mu = random.uniform(250, 50)
    sigma = random.uniform(0, 35)
    mu_sigma_vals = [0,0]
    mu_sigma_vals[0] = mu
    mu_sigma_vals[1] = sigma
    samples = np.random.normal(mu, sigma, 1000)
    prune_counter = 0
  else:
    prune_counter =+ 1

  marked_for_deletion = []
  get_flow_stats()
  pprint.pprint(tracked_flows)
  pprint.pprint(data_recvd_from_protected)
  index = random.randint(0,999)
  log.debug("***** selected index : " + str(index) + "    and pruning interval : " + str(samples[index]) + " *****")
  for key in tracked_flows.keys():
    host = (key.split('-'))[0]
    log.debug('   ******* check for host : ' + host + "  and flow : " + key + "  traffic : " + str(tracked_flows[key][0]))
    if data_recvd_from_protected.has_key(host):
      if tracked_flows[key][0] >= data_recvd_from_protected[host] and tracked_flows[key][0] <= 1.15*data_recvd_from_protected[host]:
        log.debug('********** suspected pivot *********' + host)
        suspected_hosts.append(host)
        isolate_host(host)
      else:
        log.debug(' ******** deleting a flow from tracked flows as sizes do not correlate  - ' + key)
        del tracked_flows[key]
    else:
      log.debug('******* deleting a flow from tracked flows as no data info from protected_resources  - ' + key)
      del tracked_flows[key]
  for key in tainted_hosts.keys():
    if (key not in suspected_hosts) and (time.time() - tainted_hosts[key] >= samples[index]):
      #if time.time() - last_watermarked_flow_time[key] >= 121:
      #get_flow_stats(key)
      marked_for_deletion.append(key)

  for host in marked_for_deletion:
    del tainted_hosts[host]
    del data_recvd_from_protected[host]
  log.debug(" ****** deleted %i hosts from the tainted list *********", len(marked_for_deletion))


##############################################################################
#function to send taint message to hosts
##############################################################################
def send_message(ip_taint_msg, local_tainted_port, remote_ip, remote_port):
  #log.debug('##### sending taint message : ' + 'taint, ' + str(ip) + ', '+ str(port))
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  if(temp_map.has_key(ip_taint_msg)):
    host = temp_map.get(ip_taint_msg)
  else:
    host = ip_taint_msg
  log.debug("@@@@@@@@@@@@@@@@@@@   host being contacted : " + ip_taint_msg + " at : " +host)
  #host = '172.16.229.133'
  port = 8888
  sock.settimeout(50)
  #os.system('nc ')
  try:
    sock.connect((host,port))
    #r=input('taint, ' + host + ', '+ str(port)) 
    #r = input('taint,172.16.229.128,1339,8080')
    r = "taint,"+remote_ip+","+str(remote_port)+","+str(local_tainted_port)
    log.debug('##### sending taint message : ' + r)
    sock.sendall(r.encode())
    sock.shutdown(socket.SHUT_WR)
    data = ''
    waiting_for_ack = True
    while waiting_for_ack:
      data = sock.recv(4096).decode()
      #log.debug('-----------reading data----------')
      #if (data.find('ack') >= 0 and data.find(str(ip)) >=0 and data.find(str(port)) >= 0): 
      if(data.find('ack') >= 0):
        log.debug('-------received ack!! -------' + data)
        taint_notif_ack_recv[ip_taint_msg + str(local_tainted_port)] = 1
        current_inbound_notif.remove(remote_ip)
        waiting_for_ack = False
    sock.close()
  except Exception as e:
    log.debug(" Host port denied connection: " + str(e))
    sock.close()


##############################################################################
#function to start a listener thread
##############################################################################
def taint_msg_listener():
  log.debug('------- taint message listener thread setup start ------')
  listener = ListenThread('0.0.0.0',9999)
  listener.daemon = True
  listener.start()


##############################################################################
#function to request flow stats from switches
##############################################################################
def get_flow_stats():
  for conn in core.openflow.connections:
    log.debug("********* requesting flow stats from switch : %s :", dpidToStr(conn.dpid))
    conn.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))






#############################################################################
#function to perform the taint operations
#############################################################################
def taint_action(dstip, dstport, srcip, srcport):
  if dstip in protected_resources:
    log.debug(" ------ Host to be tainted is a protected resource. No Action. Returning. --------------")
    return
  log.debug("Taint action arguments - dstip: %s  dstport: %d  srcip: %s  srcport: %d" %(dstip, int(dstport), srcip, int(srcport)))
  if(int(dstport) < 1 or int(dstport) > 65534):
  	log.debug("----- Either ICMP packet or port not valid. No Action. Returning. ------------ ")
  	return
  log.debug("<<<<<<<  Performing taint actions ip : "+dstip + "  port :"+ str(dstport) +" >>>>>>>>>>")
  if(network_hosts_without_agent.Contains(ipaddr.IPAddress(dstip))):
    log.debug("### Host does not have an agent running - taint the whole host   ###")
    dstport = -1
  if temp_inverse_map.has_key(srcip):
    srcip = temp_inverse_map[srcip]
  add_to_tainted_hosts(dstip)
  #append_to_tainted_ports(dstip, int(dstport))
  if (srcip not in protected_resources):
    add_to_tainted_hosts(srcip)
    append_to_tainted_ports(srcip, int(srcport))
  if(not network_hosts_without_agent.Contains(ipaddr.IPAddress(dstip)) and not taint_notif_ack_recv.has_key(dstip + str(dstport))):
    taint_notif_ack_recv[dstip + str(dstport)] = 0
  #if(dstport not in tainted_hosts_ports[dstip]):
  delete_flow_entries(dstip)
  delete_flow(srcip, srcport)
  
  if(taint_notif_ack_recv[dstip + str(dstport)] == 0):
    if(dstport > 0):
      t = Thread(target = send_message, name = 'send_thread' + dstip, args = (dstip, dstport, srcip, srcport))
      t.start()
  else:
    log.debug("--------------- taint notification for this host:port was already sent and ack received -----------")


#############################################################################
#function to check if the current tainted connection indicates pivoting
#############################################################################
def check_for_pivot(ip):
  log.debug("------ Checking if pivot (tainted connection to external network) ----------")
  ipaddr_to_check = ipaddr.IPAddress(ip)
  is_external = not (internal_network.Contains(ipaddr_to_check))
  return is_external


#############################################################################
#function to decide the action to be performed after pivot detection
#############################################################################
def decide_action_pivot(client_address):
  action = "restrict"
  ip = ipaddr.IPAddress(client_address)
  if(isolate_if_pivot_network.Contains(ip)):
    return "isolate"
  elif(restrict_if_pivot_network.Contains(ip)):
    return "restrict"
  elif(throttle_outbound_if_pivot_network.Contains(ip)):
    return "throttle"
  #log.debug("*** Developer machine - Isolating " + client_address)
  return action


#############################################################################
#function to take the decided counter measure against detected  pivot
#############################################################################
def take_counter_action(action, pivot_host):
  log.debug("###### Action decided for pivot : " + action)
  if(action == "isolate"):
    suspected_hosts.append(pivot_host)
    isolated_host.append(pivot_host)
    delete_flow_entries(pivot_host)
  elif(action == "pivot"):
    suspected_hosts.append(pivot_host)
    restricted_hosts.append(pivot_host)
    delete_outgoing_flows(pivot_host)
  elif(action == "throttle"):
    pass



#############################################################################
  #class
#############################################################################


class Switch(object):
  def __init__ (self, connection):
    log.debug("####**** object created for %s", connection)
    self.connection = connection

    self.ip_port_dict_local = {}                  #mapping for destination mac addr and egres port

    
    connection.addListeners(self)

  #############################################################################
  #Event handler for packet_in event
  #############################################################################
  def _handle_PacketIn (self, event):
    
    log.debug("~~~~~~ packet in event from switch %s and object is %s", event.connection, self.connection)
    global forward_rule_set
    global backward_rule_set
    global protected_resources
    global tainted_hosts
    global mac_ip_map
    skip_add_to_dict_dest = 0
    skip_add_to_dict_src = 0
    is_tcp_ack = 0
    is_icmp_pack = 0
    srcport = 0
    dstport = 0


    packet =event.parsed
    #log.debug("packet in buffer_id check : " +str(event.ofp.buffer_id))

    dest_eth_addr = str(packet.dst)
    src_eth_addr = str(packet.src)
    key = src_eth_addr + '-' + dest_eth_addr
    srcip = ''
    dstip = ''

    ipv4_pack = packet.find("ipv4")
    if ipv4_pack:
      log.debug("IP packet in transit from  "+str(ipv4_pack.srcip)+"<->"+str(ipv4_pack.dstip))
      srcip = str(ipv4_pack.srcip)
      dstip = str(ipv4_pack.dstip)
      mac_ip_map[src_eth_addr] = srcip
      mac_ip_map[dest_eth_addr] = dstip
      ip_mac_map[srcip] = src_eth_addr
      ip_mac_map[dstip] = dest_eth_addr
      key = srcip + '-' + dstip

    tcp = packet.find("tcp")
    if tcp:
      #log.debug("TCP pakcet! - SYN : %d   FIN: %d  ACK: %d ", tcp.SYN, tcp.FIN, tcp.ACK)
      srcport = tcp.srcport
      dstport = tcp.dstport
      if tcp.ACK: 
        is_tcp_ack = 1

    icmp = packet.find("icmp")
    if icmp:
      is_icmp_pack = 1

    if srcip in suspected_hosts:
      if (srcip in isolated_host or srcip in restricted_hosts):
        delete_flow_entries(srcip)
        drop_packet(event)
        return
      else:
        pass
    
    if dstip in isolated_host:
      drop_packet(event)
      return

    def flood (message = None):
      msg = of.ofp_packet_out()
      if message is not None: log.debug(message)
      #log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)
      # OFPP_FLOOD is optional; on some switches you may need to change
      # this to OFPP_ALL.
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.data = event.ofp
      msg.in_port = event.port
      #log.debug("===== flood message to switch %s : %i", self.connection, event.port)
      self.connection.send(msg)



    #log.debug("packet forwarding  " + src_eth_addr + "  " + dest_eth_addr)
    is_tcp_ack = 0
    
    if (is_tcp_ack == 0 and is_icmp_pack == 0):
      if (srcip in protected_resources):
        if(dstip in protected_resources):
          log.debug("protected to protected communication")
          skip_add_to_dict_dest = 0
        else:
          log.debug(" __________ Traffic from protected resource to internal host __________ ")
          taint_action(dstip, dstport, srcip, srcport)

      elif(tainted_hosts.has_key(srcip) and (dstip not in protected_resources)):
        if(network_hosts_without_agent.Contains(ipaddr.IPAddress(srcip))):
          log.debug("-------- Traffic coming from tainted host without agent --------")
          taint_action(dstip, dstport, srcip, srcport)
        else:
          if(tainted_hosts_ports.has_key(srcip)):
            if(srcport in tainted_hosts_ports[srcip]):
              log.debug("-------- traffic coming from a tainted port on a tainted host --------")
              taint_action(dstip, dstport, srcip, srcport)
            else:
              log.debug("------ Clean traffic from a tainted host---------- ")


    if (skip_add_to_dict_dest == 0 and skip_add_to_dict_src == 0):
      if (srcip != "" and srcip != ''):
        log.debug("  adding to dictionary skip_add_to_dict_src is %i and skip_add_to_dict_dest is %i", skip_add_to_dict_src, skip_add_to_dict_dest)
        self.ip_port_dict_local[srcip] = event.port
        pprint.pprint(self.ip_port_dict_local)
      if dstip not in self.ip_port_dict_local:
        if(taint_notif_ack_recv.has_key(dstip+str(dstport))):
          while(taint_notif_ack_recv[dstip + str(dstport)] == 0):
            time.sleep(0.02)
        #while (srcip in current_inbound_notif):
          #time.sleep(0.02)
        log.debug("flooding to all ports as no entry in dictionary" + srcip + "->" + dstip)
        flood()
        #flood_packet(event, of.OFPP_ALL)
      else:
        if(taint_notif_ack_recv.has_key(dstip+str(dstport))):
          while(taint_notif_ack_recv[dstip + str(dstport)] == 0):
            time.sleep(0.02)
        #while (srcip in current_inbound_notif):
          #time.sleep(0.02)
        port = self.ip_port_dict_local[dstip]
        log.debug("setting a flow table entry as matching entry found in dict - " + srcip + ":" + str(srcport) + " ->  " + dstip + ":" + str(dstport))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.priority = 1009
        msg.idle_timeout = 10
        msg.flags = of.OFPFF_SEND_FLOW_REM
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp
        self.connection.send(msg)


    elif (skip_add_to_dict_dest == 1) and (skip_add_to_dict_src == 0):
      log.debug("  ready to flood. skip_add_to_dict_src is %i and skip_add_to_dict_dest is %i", skip_add_to_dict_src, skip_add_to_dict_dest)
      flood_packet(event, of.OFPP_ALL)  

##############################################################################
#EVent handler for flow stats recieved event
##############################################################################
def _handle_flowstats_received(event):
  stats = flow_stats_to_list(event.stats)
  #log.debug("FlowStatsReceived from %s: %s", dpidToStr(event.connection.dpid), stats)
  log.debug("FlowStatsReceived from %s", dpidToStr(self.connection.dpid))
  
  for f in event.stats:

    if tainted_hosts.has_key(str(f.match.dl_src)) or str(f.match.dl_src) in protected_resources:
      print('***** storing statstics ******')
      bytes_count = 0
      flows_count = 0
      packets_count = 0
      dst = str(f.match.dl_dst)
      src = str(f.match.dl_src)
      bytes_count += f.byte_count
      packets_count += f.packet_count
      flows_count += 1

      if src in protected_resources:
        data_recvd_from_protected[dst] = bytes_count

      if not tracked_flows.has_key(src + '-' + dst):
        tracked_flows[src + '-' + dst] = [0,0,0]

      (tracked_flows.get(src + '-' + dst))[0] = bytes_count
      (tracked_flows.get(src + '-' + dst))[1] = packets_count
      (tracked_flows.get(src + '-' + dst))[2] = flows_count
      log.debug("traffic switch %s: %s bytes %s packets  %s flows", dpidToStr(event.connection.dpid), bytes_count, packets_count, flows_count)

############################################################################
#Event handler for flow removed from switch event
############################################################################
def _handle_flow_removed(event):

  msg = event.ofp
  dstip = str(msg.match.nw_dst)
  dstport = msg.match.tp_dst
  reason = msg.reason
  if reason == 0:
    reason = "idle_timeout"
  elif reason == 1:
    reason = "hard_timeout"
  elif reason == 2:
    reason = "controller explicitly removed"
  #log.debug("^^^^^ handling flow removed: "+ reason + " - dstip:" + dstip + "  dstport: "+ str(dstport))
  key = dstip + str(dstport)
  if taint_notif_ack_recv.has_key(key):
    log.debug("----- tainted flow removed from switch due " + reason + " - dstip:" + dstip + "  dstport: "+ str(dstport))
    del taint_notif_ack_recv[key]


class Launcher (object):
  def __init__ (self):
    log.debug("--- init for launcher ----")
    core.openflow.addListeners(self)

  #############################################################################
  #Event handler for connectionUp event
  #############################################################################
  def _handle_ConnectionUp (self,event):
    log.debug("ConnectionUp %s" % (event.connection,))
    Switch(event.connection)


#############################################################################
#Launch method for the controller app
#############################################################################
def launch ():
  #Timer(50, prune_tainted_list, recurring = True)
  Timer(.5, taint_msg_listener, recurring = False)
  import pox.openflow.discovery
  pox.openflow.discovery.launch()
  import pox.openflow.spanning_tree
  pox.openflow.spanning_tree.launch()
  core.registerNew(Launcher)
  #core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  #core.openflow.addListenerByName("PacketIn",_handle_PacketIn)
  core.openflow.addListenerByName("FlowStatsReceived", _handle_flowstats_received) 
  core.openflow.addListenerByName("FlowRemoved", _handle_flow_removed)
  #thr = Thread(target = taint_msg_listener, name = 'listen_for_messages')
  #thr.start()


##############################################################################
#class to handle the taint notification messages from hosts to ctrl
##############################################################################
class MessageHandler(SocketServer.StreamRequestHandler):
    def handle(self):
      try:
        log.debug("----- Receiving message from : " + str(self.client_address[0]) +" ------")
    	self.data = self.request.recv(1024).strip()
    	log.debug("received message : " + self.data)
	client_addr = str(self.client_address[0])
        if temp_inverse_map.has_key(client_addr):
          current_inbound_notif.append(temp_inverse_map[client_addr])
        else:
          current_inbound_notif.append(client_addr)
        host_msg = self.data.split(',')
        if ('taint' in host_msg[0].lower()):
            #rhost = ipaddr.IPAddress(host_msg[1])
      	    host_to_taint = host_msg[1]
            tainted_dest_port = host_msg[2]
            tainted_src_port = host_msg[3]

      	log.debug("[+] Rcvd Tainted Conn: "+str(self.data))

      	if ((host_to_taint) and (int(tainted_dest_port) > 0) and (int(tainted_dest_port) < 65535)):
        	if((int(tainted_src_port) > 0) and (int(tainted_src_port) < 65535)):
          		rtn_msg = 'ack,'+str(host_to_taint)+','+str(tainted_dest_port)+","+str(tainted_src_port)+'\n'
                	self.wfile.write(rtn_msg)
                	self.wfile.close()
                  	pivot = False
                  	pivot = check_for_pivot(host_to_taint)
                  	if(pivot):
                    		log.debug('######---- Pivot Detected : '+ client_addr + ' - check action---------------######')
                        	action = decide_action_pivot(client_addr)
				take_counter_action(action, client_addr)
                  	else:
                    		log.debug('------ tainted host sending tainted data to internal hosts ----------')
                	  	taint_action(host_to_taint, tainted_dest_port, client_addr, tainted_src_port)

      except Exception as e:
	log.error('[!] Failed Handler: '+str(e))

class ListenThread(threading.Thread):
  def __init__(self,host,port):
    try:
      threading.Thread.__init__(self)
      self.host='0.0.0.0'
      self.port=port
      self.server = SocketServer.TCPServer((self.host,self.port), MessageHandler)
      log.debug(' -----    Listener Initialized.     ------')
    except Exception as e:
      log.error('----- Failed to Initialize: '+str(e))

  def run(self):
    try:
      self.server.allow_reuse_address = True
      log.debug('----running listener thread-----') 
      self.server.serve_forever()
    except Exception as e:
      log.error('Error during Run: '+str(e))

  def end(self):
    try:
      log.debug(' ------  SocketServer shutting down now -------')
      self.server.shutdown()
    except Exception as e:
      log.error('Failed to Shutdown SocketServer: '+str(e))
