import subprocess

pcap_file = "/home/ash/github/packet_analysis/pcap_store/wifi_customer/RoamingIQRadiusfiltered.pcapng"
command = f"tshark -r {pcap_file} -T fields -e udp.port"
res = subprocess.run(command, shell=True, capture_output=True, text=True)
x = res.stdout.split("\n")


