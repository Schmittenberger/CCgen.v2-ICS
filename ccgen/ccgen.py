#!/usr/bin/env python

from scapy.utils import PcapWriter, PcapReader
from scapy.layers.inet import IP, TCP, ICMP, UDP
from os import system

import util.config
import util.helper
import util.iptables

abort = False

def abortGeneration():
    global abort
    abort = True

def _process_online(config, callback):
    import socket
    import fnfqueue

    iprule = util.iptables.get_iprule(config)

    #REMOVE iptables rule just in case
    system('iptables -w -F ' + config.iptables_chain)
    print('iptables -w -F ' + config.iptables_chain)
    #APPLY iptables rule
    system(iprule)
    print(iprule)

    socket.SO_RCVBUFFORCE = 2*1024*1024

    conn = fnfqueue.Connection()
    
    try:
        q = conn.bind(config.iptables_queue)
        q.set_mode(0xffff, fnfqueue.COPY_PACKET)
    except PermissionError:
        print("Access denied; Do I have root rights or the needed capabilities?")
        return

    try:
        for packet in conn:
            scapypkt = IP(packet.payload)
            if callback(scapypkt): break
            packet.payload = bytes(scapypkt)
            packet.mangle()
    finally:
        system('iptables -w -F ' + config.iptables_chain)
        print('iptables -w -F ' + config.iptables_chain)
        conn.close()

def process_online_send(config):
    global modified_frames, params
    modified_frames = 0
    params = config.mapping.getparams()

    def callback(pkt):
        datagram = config.message.getdatagram()
        if not datagram: return True
        mappedvalue = config.mapping.getmapping(datagram)
        if mappedvalue:
            config.technique.modify(pkt, mappedvalue, params)

            del pkt[IP].chksum  #recalculate checksum
            if pkt.haslayer(TCP):
                del pkt[TCP].chksum
            if pkt.haslayer(ICMP):
                del pkt[ICMP].chksum

            global modified_frames
            modified_frames += 1
        else:
            pass
        if abort: return True
        return False

    _process_online(config, callback)
    return modified_frames

def process_online_receive(config):
    global checked_frames, params
    checked_frames = 0
    params = config.mapping.getparams()
    outputfile = open(config.output_file, 'w')

    def callback(pkt):
        received = config.technique.extract(pkt, params)
        data = config.mapping.getdata(str(received))
        if data:
            global checked_frames
            try:
                outputfile.write(data)
                outputfile.flush()
                checked_frames += 1
            except:
                pass
        if abort: return True
        return False

    _process_online(config, callback)
    return checked_frames

def process_offline_send(config):
    print("[process_offline_send]: offline inject started")
    modified_frames = 0
    params = config.mapping.getparams()
    with PcapWriter(config.output_file) as outfile:
        for frame in PcapReader(config.input_file):
            if not util.should_filter_frame(config, frame):
                print("[process_offline_send]: frame fit filter criteria")
                # Add covert channel
                datagram = config.message.getdatagram()
                mappedvalue = config.mapping.getmapping(datagram)
                
                if mappedvalue:
                    modified_frames += 1
                    if config.layer == 'IP' and not 'pIAT' in params:
                        config.technique.modify(frame[IP], mappedvalue, params)
                    else:
                        frame = config.technique.modify(frame, mappedvalue, params)

                    # Recalculate checksums
                    if not frame: continue

                    if frame.haslayer(TCP):
                        del frame[TCP].chksum
                    if frame.haslayer(UDP):
                        del frame[UDP].chksum
                    if frame.haslayer(ICMP):
                        del frame[ICMP].chksum
                    del frame[IP].chksum
            else:
                print("[process_offline_send]: frame did not match the filter criteria", util.should_filter_frame(config, frame))
            outfile.write(frame)
            if abort: break
    return modified_frames

def process_offline_receive(config):
    checked_frames = 0
    params = config.mapping.getparams()
    print("[process_offline_receive]: Params", params)

    with open(config.output_file, 'w') as outfile:
        for frame in PcapReader(config.input_file):
            #print("[process_offline_receive]: Frame details", frame.show())
            #print("[process_offline_receive]: Frame IP details", frame.summary(protocols=["IP"]))
            if not util.should_filter_frame(config, frame):
                checked_frames = checked_frames + 1
                if config.layer == 'IP' and not 'pIAT' in params:
                    mappedvalue = config.technique.extract(frame[IP], params)
                    print("[process_offline_receive]: (IP and not pIAT) extracting stuff", mappedvalue)
                else:
                    mappedvalue = config.technique.extract(frame, params)
                    print("[process_offline_receive]: (else) extracting stuff", mappedvalue)
                if mappedvalue is None:
                    print("[process_offline_receive]: mappedvalue is None", mappedvalue)
                    print("[process_offline_receive]: --> jumping out of loop for this iteration")
                    #jump out of loop for this iteration as mappedvalue is None (undefined)
                    continue
                try:
                    data = ""
                    if 'pIAT' in params and isinstance(mappedvalue, str):
                        for value in mappedvalue: 
                            data += config.mapping.getdata(str(value))
                    else: data = config.mapping.getdata(str(mappedvalue))
                    print("[process_offline_receive]: data", data)
                    outfile.write(data)
                except Exception as e:
                    print("[process_offline_receive]: try except block reached", e)
                    pass
            if abort: 
                print("[Process_offline_receive]: aborted somehow")
                break
    print("[process_offline_receive]: checked_frames: ", checked_frames)
    return checked_frames

#print information about how the inject/extraction went
def process_summary(modus, config, frames_count):
    print("\n[Modus]", modus[1])
    print(config)
    print("frames",frames_count)
    #print("get datagram",config.message.getdatagram())
    #print("necassary packets",config.message.necessary_packets())
    result = "failed"
    if modus[0] == 1: # ONLINE INJECTION
        required_pkts = config.message.necessary_packets()   
        if required_pkts == frames_count:
            print("  SUCCEEDED!!")
            result = "succeeded"
            comment = "SUCCEEDED!!<br>"
        else:
            print("  FAILED!!")
            comment = "FAILED!!<br>"
        comment += "Required packets: " + str(required_pkts) + "<br>Modified packets: " + str(frames_count) 
        print("  Required packets: ", required_pkts)    
        print("  Modified packets: ", frames_count)
    elif modus[0] == 2: #ONLINE EXTRACTION
        output = util.helper.getOutputFile(config.output_file, config.outfile_type)
        if not output or len(output.strip()) == 0: 
            result = "failed"
            comment = "FAILED!!<br>Configured covert channel could not be found!"
            print("  FAILED!!")
        else:
            result = "succeeded"
            comment = "SUCCEEDED!!<br>Inscpected packets: " + str(frames_count) + "<br>Check obtained message in " + config.output_file.replace('.txt', config.outfile_type) + " file."
            print("  SUCCEEDED!!")
            print("  Inspected packets: ", frames_count)
            print("  Check obtained message in " + config.output_file.replace('.txt', "." + config.outfile_type) + " file.")
    elif modus[0] == 3: #OFFLINE INJECTION...
        required_pkts = config.message.necessary_packets()    
        if required_pkts == frames_count:
            print("  SUCCEEDED!!")
            result = "succeeded"
            comment = "SUCCEEDED!!<br>"
        else:
            print("  FAILED!!")
            comment = "FAILED!!<br>"
        comment += "Required packets: " + str(required_pkts) + "<br>Modified packets: " + str(frames_count)
        print("  Required packets: ", required_pkts)    
        print("  Modified packets: ", frames_count)   
    elif modus[0] == 4: #OFFLINE EXTRACTION...
        output = util.helper.getOutputFile(config.output_file, config.outfile_type)
        print("[process_summary]:",config.output_file,config.outfile_type,"Output file contents:",output)
        if not output or len(output.strip()) == 0: 
            result = "failed"
            comment = "FAILED!!<br>Configured covert channel could not be found!"
            print("[process_summary]:  FAILED! Configured covert channel could not be found!")
        else:
            result = "succeeded"
            comment = "SUCCEEDED!!<br>Inscpected packets: " + str(frames_count) + "<br>Check obtained message in " + config.output_file.replace('.txt', config.outfile_type) + " file."
            print("[process_summary]:  SUCCEEDED!!")
            print("[process_summary]:  Inspected packets: ", frames_count)
            print("[process_summary]:  Check obtained message in " + config.output_file.replace('.txt', "." + config.outfile_type) + " file.") 

    if abort: 
        result = "aborted"
        comment = comment.replace("FAILED", "ABORTED") 
        comment = comment.replace("SUCCEEDED", "ABORTED")
    return [result, comment]    

#this function starts the inject/extract process even if is called generateCovertChannel
def generateCovertChannel(user_config, message, direction, network):
    global abort
    abort = False
    #print the config specified for this task
    config = util.config.parse_config(user_config, message, direction, network)
    print("[Scheduling]: Starting chosen steganographic process")
    #frames is a counter how many frames (packets?) have been modified
    frames = 0
    if network == util.config.NETWORK_ONLINE:
        if direction == util.config.DIRECTION_SEND:
            frames = process_online_send(config)
            # modus is just information for the process summary in the end
            modus = (1,'ONLINE INJECTION...')
        elif direction == util.config.DIRECTION_RECEIVE:
            frames = process_online_receive(config)
            modus = (2,'ONLINE EXTRACTION...')
    elif network == util.config.NETWORK_OFFLINE:
        if direction == util.config.DIRECTION_SEND:
            frames = process_offline_send(config)
            modus = (3,'OFFLINE INJECTION...')
        elif direction == util.config.DIRECTION_RECEIVE:
            frames = process_offline_receive(config)
            modus = (4,'OFFLINE EXTRACTION...')

    util.helper.makeFileAccessible(network, config.output_file)
    return process_summary(modus, config, frames)