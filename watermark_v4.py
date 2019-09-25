import numpy as np
import scipy as sp
import scipy.stats as stats
import time
import random as random
import pprint
from pox.lib.recoco import Timer
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr

log = core.getLogger()
watermark_samples = []                                      #array to store arrays of watermark samples - induced ipd
#watermark_samples.append(np.random.normal(.1, 0.03, 1000))
mac_port_dict = {}                                          #mapping for destination mac addr and egres port
protected_resources = ["00:00:00:00:00:03"]                 #list of protected resources
tainted_hosts = {}                                          #dictionary: key - tainted hosts , value - time of taint 
last_watermarked_flow_time = {}                             #dictionary: key - tainted hosts , value - time of receipt of last watermarked flow
watermarks_received_on_hosts = {}                           #dictionary: key - tainted hosts , value - watermarks received on the host
watermark_index = -1                                        #indexes to keep track of generated watermarks
watermarks_created_for_hosts = {}                           #dictionary: key - tainted hosts , value - watermark indexes created for flows from host
correlated_flows = {}                                       #record correlated flows
suspected_hosts = []                                        #list of suspected hosts acting as pivots
flow_last_packet_received_time = {}                                  #dictionary: key - suspected flows being monitored , value - time since last packet 
flow_ipds = {}                                              #dictionary: key - suspected flows being monitored , value - ipd arrays
watermark_index_to_params_map = {}                          #dictioanry: key - watermark indexes , value - mean and stddev for the dist
flow_last_packet_sent_time = {}
flow_packets_queues = {}

#for host in protected_resources:
  #watermarks_created_for_hosts[host] = 0

#function to flood packets
def flood_packet (event, dst_port = of.OFPP_ALL):
  msg = of.ofp_packet_out(in_port=event.ofp.in_port)
  log.debug("flooding packet for buffer_id " + str(event.ofp.buffer_id))
  if event.ofp.buffer_id != -1 and event.ofp.buffer_id is not None:
    msg.buffer_id = event.ofp.buffer_id
  else:
    if event.ofp.data:
      return
    msg.data = event.ofp.data

  msg.actions.append(of.ofp_action_output(port = dst_port))
  event.connection.send(msg)

#function to create a watermark for the passed host
def create_watermark(host):
  global watermark_samples
  global watermark_index
  global watermarks_created_for_hosts
  if watermarks_created_for_hosts.has_key(host):
    log.debug("host has watermark created already!")
    return watermarks_created_for_hosts.get(host)
  else:
    mu = random.uniform(0.003, 0.009)
    sigma = random.uniform(0, 0.002)
    mu_sigma_vals = [0,0]
    mu_sigma_vals[0] = mu
    mu_sigma_vals[1] = sigma
    watermark_index = watermark_index + 1
    watermark_index_to_params_map[watermark_index] = mu_sigma_vals
    log.debug("&&&&&&&& creating watermark: "+ str(mu) + "  "+ str(sigma) + " for host : " + host + "  with watermark index : " +str(watermark_index))
    samples = np.random.normal(mu, sigma, 1000)
    #watermark_samples = np.vstack((watermark_samples, samples))
    watermark_samples.append(samples)
    watermarks_created_for_hosts[host] = watermark_index
    pprint.pprint(watermarks_created_for_hosts)
    return watermark_index

#function to add a host to the tainted list
def add_to_tainted_hosts(host):
  global tainted_hosts
  global watermarks_received_on_hosts
  if (tainted_hosts.has_key(host)) or (host in protected_resources):
    log.debug("host already present in tainted list")
  else:
    tainted_hosts[host] = time.time()
    #watermarks_received_on_hosts = np.vstack((watermarks_received_on_hosts, [host]))
    #watermarks_received_on_hosts.append(h)
    log.debug("added %s to tainted_hosts list ", host)
  last_watermarked_flow_time[host] = time.time()

#function to add a new watermark to a host that received the watermarked flow
def add_to_watermarks_received_on_hosts(host, watermark):
  global watermarks_received_on_hosts
  if watermarks_received_on_hosts.has_key(host):
    if watermark not in watermarks_received_on_hosts.get(host):
      log.debug("appended watermark to list")
      watermarks_received_on_hosts.get(host).append(watermark)
      pprint.pprint(watermarks_received_on_hosts)
  else:
    log.debug("host not found in the watermarks_received_on_hosts list")
    watermarks_received_on_hosts[host] = [watermark]
    pprint.pprint(watermarks_received_on_hosts)

#function to delete flow entries for a tainted host from all switches
def delete_flow_entries(event, packet, host):
  #if (host_address not in protected_resources)
  log.debug("deleting flow table entries for " + str(host))
  msg = of.ofp_flow_mod(command = of.OFPFC_DELETE)
  #msg.priority = 65635
  msg.match.dl_src = host
  event.connection.send(msg)
  for conn in core.openflow.connections:
    #log.debug("********* sending a flow removal message to switch : %s ", dpidToStr(conn.dpid))
    conn.send(msg)
  #log.debug("successfully sent delete flow messages!!!!!!")

def delete_flows_for_watermark_detection():
  for host in tainted_hosts:
    log.debug("****** deleting flows for tainted hosts to check for correlation ***" + str(host))
    msg = of.ofp_flow_mod(command = of.OFPFC_DELETE)
    msg.match.dl_src = host
    for conn in core.openflow.connections:
      conn.send(msg)

#function called after a delay to flood packets
def delay_and_flood(event):
  log.debug("++++++++++ flooding after wait ++++++++++++")
  flood_packet(event, of.OFPP_ALL)

#function tp prune the tailted hosts list
def prune_tainted_list():
  log.debug("****** pruning tainted hosts list **********")
  marked_for_deletion = []
  for key in tainted_hosts.keys():
    if (key not in suspected_hosts) and (time.time() - tainted_hosts[key] >= 121):
      if time.time() - last_watermarked_flow_time[key] >= 121:
        marked_for_deletion.append(key)

  for host in marked_for_deletion:
    del tainted_hosts[host]
  log.debug(" ****** deleted %i hosts from the tainted list *********", len(marked_for_deletion))

#function to update the interpacket-delay arrical times array for a given flow
def update_ipd_arrays(src_eth_addr, dest_eth_addr):
  key = src_eth_addr + dest_eth_addr
  log.debug(" updating ipd array for : " + key)
  curr_time = time.time()
  packet_delay = 0
  if flow_last_packet_received_time.has_key(key):
    packet_delay = curr_time - flow_last_packet_received_time[key]
  flow_last_packet_received_time[key] = curr_time
  if flow_ipds.has_key(key):
    flow_ipds.get(key).append(packet_delay)
  else:
    flow_ipds[key] = []

#function to check whether the passed array's elements are normaly distributed
def check_distribution(ipd_array, src_eth_addr, dest_eth_addr):
  log.debug(" Checking for a normal distribution")
  key  = src_eth_addr + dest_eth_addr
  chi_stats = stats.normaltest(ipd_array)
  p_val = chi_stats[1]
  if p_val > 0.1:
    log.debug("******** Sample follows a normal distribution *********")
    return 1
  log.debug(" ------- sample Does Not follow a normal distribution ----------")
  del flow_ipds[key]
  del flow_last_packet_received_time[key]
  return 0

#function to find the mean and stddev for a normally distributed sample 
def find_mu_sigma(ipd_array):
  log.debug(" calculating mu and sigma for a normal distribution")
  mu_sigma_vals = [0,0]
  mu_sigma_vals[0] = np.mean(ipd_array)
  mu_sigma_vals[1] = np.std(ipd_array, axis = None)
  log.debug(" calculated mean = %f  and std-dev = %f ", mu_sigma_vals[0], mu_sigma_vals[1])
  return mu_sigma_vals

#function to check for a correlation
def find_correlation(src_eth_addr, dest_eth_addr, mu_sigma_vals):
  log.debug("**** performing correlation tests for src: "+ src_eth_addr + " dest: " + dest_eth_addr)
  watermarks_to_check = []
  key = src_eth_addr + dest_eth_addr
  if (watermarks_received_on_hosts.has_key(src_eth_addr)):
    watermarks_to_check = watermarks_received_on_hosts[src_eth_addr]
  else:
    log.debug(" No watermarks received reorded for src : " + src_eth_addr)
    return
  for watermark_index in watermarks_to_check:
    recorded_mu_sigma = watermark_index_to_params_map[watermark_index]
    if (0.9*recorded_mu_sigma[0] <= mu_sigma_vals[0]  <= 1.1*recorded_mu_sigma[0]) and (0.9*recorded_mu_sigma[1] <= mu_sigma_vals[1]  <= 1.1*recorded_mu_sigma[1]):
      log.debug(" ########### correlation found : %s -> %s  ###########", src_eth_addr, dest_eth_addr)
      del flow_ipds[key]
      del flow_last_packet_received_time[key]
      return 1
  log.debug(" --------- No correlation found ------------")
  del flow_ipds[key]
  del flow_last_packet_received_time[key]
  return 0

def release_packets(key):
  log.debug("releasing packet")
  if flow_packets_queues.has_key(key):
    event = (flow_packets_queues.get(key)).pop()
    flood_packet(event, of.OFPP_ALL)

def _handle_PacketIn (event):

  global forward_rule_set
  global backward_rule_set
  global mac_port_dict
  global watermark_samples
  global protected_resources
  global tainted_hosts
  global watermark_count
  skip_add_to_dict_dest = 0
  skip_add_to_dict_src = 0
  mu_sigma_vals = [0,0]
  is_correlated = 0
  is_tcp_ack = 0

  packet =event.parsed

  log.debug("packet in buffer_id check : " +str(event.ofp.buffer_id))

  dest_eth_addr = str(packet.dst)
  src_eth_addr = str(packet.src)
  key = src_eth_addr + dest_eth_addr

  ipv4_pack = packet.find("ipv4")
  if ipv4_pack:
    log.debug("IP packet in transit from  "+str(ipv4_pack.srcip)+"<->"+str(ipv4_pack.dstip))

  tcp = packet.find("tcp")
  if tcp:
    #log.debug("TCP pakcet! - SYN : %d   FIN: %d  ACK: %d ", tcp.SYN, tcp.FIN, tcp.ACK)
    if tcp.ACK:
      log.debug("!!!!!!   TCP ack packet  %s   !!!!!!", key)
      flood_packet(event, of.OFPP_ALL)
      is_tcp_ack = 1


  #log.debug("packet forwarding  " + src_eth_addr + "  " + dest_eth_addr)
  if is_tcp_ack == 0:
    if (dest_eth_addr in protected_resources):
      log.debug("***traffic going to protected resource***")
      #log.debug("***FLow rule not added to switches. Send to controller***")
      #send_packet(event, packet)
      #skip_add_to_dict_dest = 1

    elif (tainted_hosts.has_key(dest_eth_addr)):
      log.debug("***traffic going to Tainted host ***")
      #log.debug("***FLow rule not added to switches. Send to controller***")
      #send_packet(event, packet)
      #skip_add_to_dict_dest = 1

    if (src_eth_addr in protected_resources):
      if(dest_eth_addr in protected_resources):
        log.debug("protected to protected communication")
        skip_add_to_dict_dest = 0
      else:
        #log.debug("*** traffic from protected resource***")
        #log.debug("***FLow rule not added to switches. Send to controller***")
        add_to_tainted_hosts(dest_eth_addr)
        #add_to_watermarks_received_on_hosts(dest_eth_addr, 0)
        if flow_packets_queues.has_key(key):
          (flow_packets_queues.get(key)).insert(0,event)
        else:
          flow_packets_queues[key] = [event]
        watermark = create_watermark(src_eth_addr)
        log.debug("*** traffic from protected resource and watermark creation result : %i", watermark)
        add_to_watermarks_received_on_hosts(dest_eth_addr, watermark)
        index = random.randint(0,1000)
        log.debug("index %i", index)
        induced_delay = watermark_samples[watermark][index]
        absolute_delay = 0
        if flow_last_packet_sent_time.has_key(src_eth_addr+dest_eth_addr):
          absolute_delay = flow_last_packet_sent_time[src_eth_addr+dest_eth_addr]
        else:
          flow_last_packet_sent_time[src_eth_addr+dest_eth_addr] = induced_delay
        absolute_delay = absolute_delay + induced_delay
        log.debug("****inserting  "+str(watermark_samples[watermark][index])+" seconds delay here - src Protected***")
        #log.debug("***** absolute packet release time after delay addition since t0 : " + str(absolute_delay))
        #Timer(watermark_samples[0][index], delay_and_flood, event)
        #core.callDelayed(absolute_delay, delay_and_flood, event)
        core.callDelayed(induced_delay, release_packets, key)
        flow_last_packet_sent_time[src_eth_addr + dest_eth_addr] = absolute_delay
        skip_add_to_dict_src = 1
        #flood_packet(event, of.OFPP_ALL)
        delete_flow_entries(event, packet, packet.dst)
         #send_packet(event, of.OFPP_ALL)

    elif(tainted_hosts.has_key(src_eth_addr) and (dest_eth_addr not in protected_resources)):
      update_ipd_arrays(src_eth_addr, dest_eth_addr)
      flow_ipd_array = flow_ipds.get(src_eth_addr+dest_eth_addr)
      if (len(flow_ipd_array) > 0 and (len(flow_ipd_array)) % 50 == 0):
        print flow_ipd_array
        if (check_distribution(flow_ipd_array, src_eth_addr, dest_eth_addr) == 1):
          mu_sigma_vals = find_mu_sigma(flow_ipd_array)
          is_correlated = find_correlation(src_eth_addr, dest_eth_addr, mu_sigma_vals)
          if is_correlated == 1:
            log.debug(" #######@@@@@@@@ correlated flows - Take appropriate actions @@@@@@@@########")
          else:
            log.debug(" -------- No correlation. Adding flow entry to the flow tables")
            skip_add_to_dict_src = 0
            skip_add_to_dict_dest = 0
        else:
          log.debug(" -------- No normal distribution. Adding flow entry to the flow tables")
          skip_add_to_dict_src = 0
          skip_add_to_dict_dest = 0
      else:
        if (dest_eth_addr in protected_resources):
          log.debug("tainted to protected communication")
          skip_add_to_dict_dest = 0
        else:
          #log.debug("***** traffic from  a tainted host *********")
          #log.debug("***FLow rule not added to switches. Send to controller***")

          #add_to_tainted_hosts(dest_eth_addr)
          if flow_packets_queues.has_key(key):
            (flow_packets_queues.get(key)).insert(0,event)
          else:
            flow_packets_queues[key] = [event]
          watermark = create_watermark(src_eth_addr)
          log.debug("*** traffic from tainted host and watermark creation result : %i", watermark)
          add_to_watermarks_received_on_hosts(dest_eth_addr, watermark)
          index = random.randint(0,1000)
          log.debug("index %i", index)
          induced_delay = watermark_samples[watermark][index]
          absolute_delay = 0
          if flow_last_packet_sent_time.has_key(src_eth_addr+dest_eth_addr):
            absolute_delay = flow_last_packet_sent_time[src_eth_addr+dest_eth_addr]
          else:
            flow_last_packet_sent_time[src_eth_addr+dest_eth_addr] = induced_delay
          absolute_delay = absolute_delay + induced_delay
          #log.debug("****inserting  "+str(absolute_delay)+" seconds delay here - src Protected***")
          log.debug("****inserting  "+str(watermark_samples[watermark][index])+" seconds delay here - src Protected***")
          #log.debug("***** absolute packet release time after delay addition since t0 : " + str(absolute_delay))
          #Timer(watermark_samples[0][index], delay_and_flood, event)
          #core.callDelayed(absolute_delay, delay_and_flood, event)
          core.callDelayed(induced_delay, release_packets, key)
          flow_last_packet_sent_time[src_eth_addr+dest_eth_addr] = absolute_delay
          skip_add_to_dict_src = 1
          #flood_packet(event, of.OFPP_ALL)
          #delete_flow_entries(event, packet, packet.dst)

    if (skip_add_to_dict_dest == 0) and (skip_add_to_dict_src == 0):
      log.debug("  adding to dictionary skip_add_to_dict_src is %i and skip_add_to_dict_dest is %i", skip_add_to_dict_src, skip_add_to_dict_dest)
      mac_port_dict[packet.src] = event.port
      if packet.dst not in mac_port_dict:
        log.debug("flooding to all ports as no entry in dictionary")
        flood_packet(event, of.OFPP_ALL)
      else:
        port = mac_port_dict[packet.dst]
        log.debug("setting a flow table entry as matching entry found in dict - " + src_eth_addr + "    " + dest_eth_addr)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.priority = 1009
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp
        event.connection.send(msg)
    elif (skip_add_to_dict_dest == 1) and (skip_add_to_dict_src == 0):
      log.debug("  ready to flood. skip_add_to_dict_src is %i and skip_add_to_dict_dest is %i", skip_add_to_dict_src, skip_add_to_dict_dest)
      flood_packet(event, of.OFPP_ALL)


def _handle_ConnectionUp (event):
  log.debug("[!] HubACLs v0.0.1 Running %s", dpidToStr(event.dpid))

def launch ():
  Timer(120, prune_tainted_list, recurring = True)
  Timer(300, delete_flows_for_watermark_detection, recurring = True)
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("PacketIn",_handle_PacketIn)

