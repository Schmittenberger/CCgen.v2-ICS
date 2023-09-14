from scapy.layers.inet import IP, TCP, UDP
from scapy.all import load_layer
#import scapy.all as scapy


def find_transport(ip):
	if ip.haslayer(TCP):
		return TCP
	elif ip.haslayer(UDP):
		return UDP
	else:
		return None


def should_filter_frame(config, frame):
	print()
	print("[UTIL should_filter_frame]: <-- Begin -- >")

	if frame.haslayer(IP) == 0:
		print("[UTIL should_filter_frame]: frame does not have IP Layer --> FILTER", frame.show())
		return True

	ip = frame[IP]
	# filter protocol

	# filter ip
	if config.src_ip and ip.src != config.src_ip:
		print("[UTIL should_filter_frame]: src ip doesnt match --> FILTER", config.src_ip, ip.src)
		return True
	else:
		print("[UTIL should_filter_frame]: src ip matches!", config.src_ip, ip.src)
	if config.dst_ip and ip.dst != config.dst_ip:
		print("[UTIL should_filter_frame]: dest ip doesnt match --> FILTER", config.dst_ip, ip.dst)
		return True
	else:
		print("[UTIL should_filter_frame]: dest ip matches!", config.dst_ip, ip.dst)

	# filter protocol
	if config.proto and ip.proto != config.proto:
		print("[UTIL should_filter_frame]: protocols dont match --> FILTER", config.proto, ip.proto)
		print("Tip: 6 = TCP | 17 = UDP ")
		return True

	transport = find_transport(ip)
	print( "[UTIL should_filter_frame]: transport 2",transport)
	if transport:
		# filter ports
		if config.src_port and ip[transport].sport != config.src_port:
			print("[UTIL should_filter_frame]: TCP or UDP src ports dont match --> FILTER")
			return True
		if config.dst_port and ip[transport].dport != config.dst_port:
			print("[UTIL should_filter_frame]: TCP or UDP dest ports dont match --> FILTER")
			return True

	if config.layer == 'TLS':
		load_layer("tls") 
		if frame.haslayer(TLS) == 0 or frame[TLS][0].type != 23:
			print("[UTIL should_filter_frame]: some issue with TLS")
			return True
	print("[UTIL should_filter_frame]: This frame is all good")
	print()
	return False
