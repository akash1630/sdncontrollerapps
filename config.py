#Configuration file for SDN Taint-manager

#############################################################################
#define internal network here - ****IMPORTANT****
#############################################################################
internal_ips = "10.4.4.0/24"
protected_resources = ["10.4.4.4"]       #list of protected resources
hosts_without_agent = "10.4.4.5/32"
isolate_if_pivot_ips = "10.4.10.2/32"
restrict_if_pivot_ips = "10.4.4.0/24"
throttle_outbound_if_pivot_ips = "10.4.4.0/24"
redirect_to_honeynet_ips = "10.4.10.1/32"


############################################################################
#    **** FOR TESTING PURPOSES ****
############################################################################

temp_map = {}                           
temp_map['10.4.4.2']='192.168.158.192'
temp_map['10.4.4.3']='192.168.158.193'
temp_map['10.4.4.4'] ='192.168.158.194'

temp_inverse_map = {}
temp_inverse_map['192.168.158.192']='10.4.4.2'
temp_inverse_map['192.168.158.193']='10.4.4.3'
temp_inverse_map['192.168.158.194']='10.4.4.4'

