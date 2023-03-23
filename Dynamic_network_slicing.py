
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet

from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import udp
from ryu.lib.packet import tcp
from ryu.lib.packet import icmp
from ryu.lib.ovs import vsctl
from ryu.lib.ovs import bridge
from ryu.lib import hub
from ryu.base import app_manager
from ryu.topology.api import get_switch, get_link, get_host
from ryu.topology import event
import copy
import subprocess
import time
import threading
import json



class TrafficSLicing(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TrafficSLicing, self).__init__(*args, **kwargs)
        # Used for learning switch functioning
        self.mac_to_port = {}

        fast_link = 2000
        slow_link = 1000

        # dict link_number : bw
        self.links = {1: slow_link, 2: fast_link}

        #  dict(switch, dict(port, link_num))
        self.switch_link_ports = {
            1: {1: 1},
            2: {1: 1, 2: 2},
            3: {1: 2},
        }

        self.hosts = {
            'h1': "00:00:00:00:00:01",
            'h2': "00:00:00:00:00:02",
            'h3': "00:00:00:00:00:03",
        }

        # Dict(switch : (port : number))
        # Restricting meters restrict other than slice traffic.
        # Every port between switches has its individual meter for restricting traffic
        self.restr_meters = {}

        # Dict("mac1mac2" : dict('slice_meters':dict(switch : dict(port:meter_id), 'bw':bw))
        # Stores all the essential info about slices:
        # - the mac_addresses of the two slice hosts,
        # - the meters that are created for restricting the slice traffic
        # - bw = slice bandwidth
        self.slice_data = {}

        # to avoid meter number overlapping
        # firs 4 numbers reserved for restr_meters
        self.meter_count = 4

        # Start network slicer function used for slicing.
        hub.spawn(self.network_slicer)



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)


    """
    This is called when Ryu receives an OpenFlow packet_in message. The trick is set_ev_cls decorator. This decorator
    tells Ryu when the decorated function should be called.
    """

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    ###################################################################################
    """
    The event EventSwitchEnter will trigger the activation of get_topology_data().
    """

    """
    This event is fired when a switch leaves the topo. i.e. fails.
    """
    # @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    # def handler_switch_leave(self, ev):
    #     #  self.logger.info("Not tracking Switches, switch leaved.")

    def get_switch_and_link(self):
        # The Function get_switch(self, None) outputs the list of switches.
        self.topo_raw_switches = copy.copy(get_switch(self, None))
        # The Function get_link(self, None) outputs the list of links.
        self.topo_raw_links = copy.copy(get_link(self, None))

        """
        Now you have saved the links and switches of the topo. So you could do all sort of stuf with them. 
        """

        print(" \t" + "Current Links:")
        for l in self.topo_raw_links:
            print (" \t\t" + str(l))

        print(" \t" + "Current Switches:")
        for s in self.topo_raw_switches:
            print (" \t\t" + str(s))

    def network_slicer(self):
        hub.sleep(5)
        self.create_restr_meters()  # Create restricting meters for other than slice data
        hub.sleep(4)

        # Loop that takes input parameters for slicing / deleting a slice,
        # checks that the parameters are proper and after that calls the slicing/deleting function.
        while True:
            self.print_slices()
            # Ask what
            a = input("Do you want to add slice[1] or delete slice[2]?: ")

            # Add a slice
            if a == "1":
                self.logger.info("This network has hosts:  %s", self.hosts)
                slice_host_1 = input("Slice between host: ")
                while slice_host_1 not in self.hosts:
                    slice_host_1 = input("Host not in network: ")
                mac1 = self.hosts[slice_host_1]
                slice_host_2 = input("and host: ")
                while slice_host_2 not in self.hosts:
                    slice_host_2 = input("Host not in network: ")
                mac2 = self.hosts[slice_host_2]
                # Slice between hosts already exists
                if mac1 + '/' + mac2 in self.slice_data or mac2 + mac1 in self.slice_data:
                    self.logger.info("Slice between hosts already exists")
                    continue

                # Everything ok --> add slice
                ret = self.add_slice(mac1, mac2)

                if ret == 0:
                    self.logger.info("Slicing is not possible")
                else:
                    self.logger.info("Slicing done :) ")
                hub.sleep(1)

            # Deleting slice
            elif a == "2":
                self.logger.info("This network has hosts:  %s", self.hosts)
                slice_host_1 = input("Delete slice between: ")
                while slice_host_1 not in self.hosts:
                    slice_host_1 = input("Host not in network: ")
                mac1 = self.hosts[slice_host_1]
                slice_host_2 = input("and host: ")
                while slice_host_2 not in self.hosts:
                    slice_host_2 = input("Host not in network: ")
                mac2 = self.hosts[slice_host_2]
                if mac1 + '/' + mac2 in self.slice_data:
                    self.delete_slice(mac1, mac2)
                elif mac2 + mac1 in self.slice_data:
                    self.delete_slice(mac2, mac1)
                else:
                    self.logger.info("Slice between hosts %s and %s doesn't exist", slice_host_1, slice_host_2)

            else:
                hub.sleep(10)

    def add_slice(self, mac1, mac2):
        # Store all the ports where the traffic needs to be restricted
        slice_ports = {}   # dict(switch, dict(port, link))
        # Store all the links that are used in the slice
        slice_links = set()   # set(link1, link2,...)
        hub.sleep(6)

        # Find the path(= slice_links and slice_ports) between the slice hosts
        for switch in self.mac_to_port:
            # Look switch flow table for flows between slice hosts
            port1 = self.get_flow_in_port(mac1, mac2, switch)
            # Look if the flow is for a port that is connected to another switch
            link1 = self.get_link(switch, port1)
            # If flow and link found, store them to slice_ports and slice_links
            if port1 != 0 and link1 != 0:
                slice_ports.setdefault(switch, {})
                slice_ports[switch][port1] = link1
                slice_links.add(link1)
            # The same thing that above but for the other direction
            port2 = self.get_flow_in_port(mac2, mac1, switch)
            link2 = self.get_link(switch, port2)
            if port2 != 0 and link2 != 0:
                slice_ports.setdefault(switch, {})
                slice_ports[switch][port2] = link2
                slice_links.add(link2)
        self.logger.info(" slice ports:  %s", slice_ports)

        # See maximum available bandwidth
        bw_max = 123456
        for link in slice_links:
            bw = self.links[link]
            if bw_max > bw:
                bw_max = bw

        # If slicing is not possible, return
        if bw_max <= 0:
            return 0

        # Ask for slice bw
        self.logger.info("Max bw between %s and %s is %s kbps", mac1, mac2, str(bw_max))
        slice_bw = int(input("How much bandwidth do you want?: "))
        while slice_bw > bw_max:
            slice_bw = int(input("That's too big of a slice: "))

        ### Slicing ###
        # Keep track of slices
        slice_meters = {}
        hub.sleep(4)

        # Go through all the slice_ports and do everything needed for slicing
        for switch in slice_ports:
            # New meter for slice_traffic (only one per switch needed)
            slice_meter_id = self.meter_count
            self.add_meter(switch, slice_bw, slice_meter_id)
            for port in slice_ports[switch]:
                link = slice_ports[switch][port]
                link_bw = self.links[link]
                meter_bw = link_bw - slice_bw                # Meter bandwidth is link_bw - slice_bw
                if meter_bw <= 0:
                    self.logger.info("Should NOT happen")
                    return 0

                # Adjust the restr_meter bandwidth
                restr_meter_id = self.restr_meters[switch][port]
                self.modify_meter(switch, restr_meter_id, meter_bw)

                # If no other slices in port, all flows with outport=port through meter
                # except flows between slice hosts
                if not self.port_has_other_slices(switch, port):
                    flows = self.get_flows_with_outport(switch, port)   # Get all flows with outport
                    for f in flows:     # remove slice flows
                        if f['dl_src'] == mac1 and f['dl_dst'] == mac2:
                            flows.remove(f)
                        if f['dl_src'] == mac2 and f['dl_dst'] == mac1:
                            flows.remove(f)
                    # self.logger.info("Matches in switch %s port %s:   %s", switch, port, flows)
                    for f in flows:
                        self.flow_to_meter(switch, restr_meter_id, f, port)

                # Add flows with slice hosts to slice meter
                slice_meters.setdefault(switch, {})
                slice_meters[switch][port] = slice_meter_id  # store slice meter (= meter for restricting slice traffic)
                flows = self.get_flows_with_outport(switch, port)
                for f in flows:
                    if f['dl_src'] == mac1 and f['dl_dst'] == mac2:
                        self.flow_to_meter(switch, slice_meter_id, f, port)
                    if f['dl_src'] == mac2 and f['dl_dst'] == mac1:
                        self.flow_to_meter(switch, slice_meter_id, f, port)

        self.meter_count = self.meter_count + 1  # to avoid meter number overlap
        # Store slice data
        self.slice_data.setdefault((mac1 + '/' + mac2), {})
        self.slice_data[mac1 + '/' + mac2]['meters'] = slice_meters
        self.slice_data[mac1 + '/' + mac2]['bw'] = slice_bw
        # Update link capacities
        for link in slice_links:
            self.links[link] = self.links[link] - slice_bw
        return 1

    def delete_slice(self, mac1, mac2):

        self.logger.info("Deleting slice between host: %s and host: %s", mac1, mac2)

        # Get data needed for deleting the slices
        slice_bw = self.slice_data[mac1 + '/' + mac2]['bw']
        slice_meters = self.slice_data[mac1 + '/' + mac2]['meters']
        slice_links = set()  # keep track of slice links to update the capacity
        hub.sleep(4)

        # Go through all slice_ports and do everything needed for deleting the slice
        for switch in slice_meters:
            for port in slice_meters[switch]:
                link = self.get_link(switch, port)
                slice_links.add(link)
                link_bw = self.links[link]
                meter_bw = link_bw + slice_bw  # Meter bandwidth is link_bw + slice_bw
                if meter_bw < 0:
                    self.logger.info("Should NOT happen")
                    return 0

                # Adjust the restr_meter bandwidth
                restr_meter_id = self.restr_meters[switch][port]
                self.modify_meter(switch, restr_meter_id, meter_bw)

                # If no other slices in port, delete flows from restr_meter
                hosts = mac1 + '/' + mac2
                if not self.port_has_other_slices_than(switch, port, hosts):
                    self.logger.info("No slices anymore in switch %s port %s :(", switch, port)
                    flows = self.get_flows_with_outport(switch, port)
                    # self.logger.info("Matches in switch %s port %s:   %s", switch, port, flows)
                    for f in flows:
                        self.remove_flow_from_meter(switch, f, port)

                # If other slices in port add hosts from slice to restr_meter
                else:
                    flows = self.get_flows_with_outport(switch, port)  # Get all flows with outport
                    for f in flows:  # remove slice flows
                        if f['dl_src'] == mac1 and f['dl_dst'] == mac2:
                            self.flow_to_meter(switch, restr_meter_id, f, port)
                        if f['dl_src'] == mac2 and f['dl_dst'] == mac1:
                            self.flow_to_meter(switch, restr_meter_id, f, port)

        # Delete slice from self.slice_data
        del self.slice_data[mac1 + '/' + mac2]
        # update link capacities
        for link in slice_links:
            self.links[link] = self.links[link] + slice_bw

        self.logger.info("Link capacities: %s", self.links)
        return 1

    def port_has_other_slices(self, switch, port):
        for hosts in self.slice_data:
            if switch in self.slice_data[hosts]['meters']:
                if port in self.slice_data[hosts]['meters'][switch]:
                    return True
        return False

    def port_has_other_slices_than(self, switch, port, slice_hosts):
        for hosts in self.slice_data:
            if hosts == slice_hosts:
                continue
            if switch in self.slice_data[hosts]['meters']:
                if port in self.slice_data[hosts]['meters'][switch]:
                    return True
        return False

    # returns the in_port of flow src:mac1 to dst:mac2 in a switch
    def get_flow_in_port(self, mac1, mac2, switch):
        port = 0
        match = {
            "match": {
            "dl_src": mac1,
            "dl_dst": mac2
            }
        }
        message = "curl -X POST -d '" + json.dumps(match) + "' http://localhost:8080/stats/flow/" + str(switch)
        # ask for flows with match
        hub.sleep(1)
        process = subprocess.run(message, shell=True, capture_output=True)
        if process.returncode != 0:
            self.logger.info("sorry could not get all the flows")
            return port
        flows = json.loads(process.stdout)
        for s in flows:
            for f in flows[s]:
                m = f['match']
                port = m['in_port']
        return port

    # Get all the flows (src, dst) with out_port
    def get_flows_with_outport(self, switch, out_port):
        restr_flows = []
        match = {}
        message = "curl -X POST -d '" + json.dumps(match) + "' http://localhost:8080/stats/flow/" + str(switch)
        # ask for flows with match
        process = subprocess.run(message, shell=True, capture_output=True)
        if process.returncode != 0:
            self.logger.info("sorry could not get all the flows")
            return restr_flows

        flows = json.loads(process.stdout)
        #self.logger.info(" flows: %s", flows)
        for s in flows:
            for f in flows[s]:
                for a in f['actions']:
                    if a == 'OUTPUT:' + str(out_port) and f['match']:
                        #self.logger.info(" actions: %s match:  %s", a, f['match'])
                        restr_flows.append(f['match'])

        return restr_flows

    def get_link(self, switch, port):
        link = 0
        if switch in self.switch_link_ports:
            if port in self.switch_link_ports[switch]:
                #  dict(switch, dict(port, link_num))
                link = self.switch_link_ports[switch][port]
        return link

    # adding an openFlow meter to a switch
    # meter defines a maximum data rate for a flow
    # if data rate goes over maximum, openFlow switch drop packages
    # max_rate: kbps
    def add_meter(self, switch_id, max_rate, meter_id):

        self.logger.info("creating a new meter:  switch = %s,  bw = %s, meter_id = %s", switch_id, max_rate, meter_id)
        meter = {
                    "dpid": switch_id,
                    "flags": "KBPS",
                    "meter_id": meter_id,
                    "bands": [
                        {
                            "type": "DROP",
                            "rate": max_rate
                        }
                    ]
                }
        message = "curl -X POST -d '" + json.dumps(meter) + "' http://localhost:8080/stats/meterentry/add"
        subprocess.run(message, shell=True)

    def modify_meter(self, switch, meter, bw):
        self.logger.info("modifying a meter:  switch = %s,  bw = %s, meter_id = %s", switch, bw, meter)
        meter = {
            "dpid": switch,
            "flags": "KBPS",
            "meter_id": meter,
            "bands": [
                {
                    "type": "DROP",
                    "rate": bw
                }
            ]
        }
        hub.sleep(1)
        message = "curl -X POST -d '" + json.dumps(meter) + "' http://localhost:8080/stats/meterentry/modify"
        subprocess.run(message, shell=True)


    # modify all flows that match dst to go through meter: meter_id
    def flow_to_meter(self, switch_id, meter_id, match, out_port):

        self.logger.info("flow to meter: switch = %s,  out_port = %s, meter_id = %s, match = %s", switch_id, out_port, meter_id, match)
        meter_flow = {
            "dpid": switch_id,
            "table_id": 0,
            "idle_timeout": 0,
            "hard_timeout": 0,
            "priority": 100,
            "match": match,
            "actions": [
                {
                    "type": "METER",
                    "meter_id": meter_id
                },
                {
                    "type": "OUTPUT",
                    "port": out_port
                }

            ]
        }
        hub.sleep(1)
        message = "curl -X POST -d " + "'" + json.dumps(meter_flow) + "'" + " http://localhost:8080/stats/flowentry/modify"
        subprocess.run(message, shell=True)

    def remove_flow_from_meter(self, switch_id, match, out_port):
        flow = {
            "dpid": switch_id,
            "table_id": 0,
            "idle_timeout": 0,
            "hard_timeout": 0,
            "priority": 100,
            "match": match,
            "actions": [
                {
                    "type": "OUTPUT",
                    "port": out_port
                }

            ]
        }
        #
        hub.sleep(1)
        message = "curl -X POST -d " + "'" + json.dumps(flow) + "'" + " http://localhost:8080/stats/flowentry/modify"
        subprocess.run(message, shell=True)

    # Create restr_meters for all but slice traffic
    # One meter for each port attached to link between switches
    def create_restr_meters(self):
        for switch in self.switch_link_ports:
            meter_id = 1
            self.restr_meters.setdefault(switch, {})
            for port in self.switch_link_ports[switch]:
                link = self.get_link(switch, port)
                bw = self.links[link]
                self.add_meter(switch, bw, meter_id)
                self.restr_meters[switch][port] = meter_id
                meter_id = meter_id + 1

    def print_slices(self):
        self.logger.info("Slices: ")
        for hosts in self.slice_data:
            self.logger.info("hosts:  %s", (hosts.split('/')))
            self.logger.info("Bandwidth: %s", self.slice_data[hosts]['bw'])

