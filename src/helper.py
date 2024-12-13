import os
import pandas as pd
import subprocess
import streamlit as st
import re
import boto3
import anthropic
import json
import numpy as np
from botocore.exceptions import ClientError
from openai import OpenAI
from mac_vendor_lookup import MacLookup
from dotenv import load_dotenv
from groq import Groq
load_dotenv()

client_groq = Groq(api_key=os.getenv("GROQ_API_KEY"))

# Load OpenAI API key
client_openai = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
bedrock = boto3.client(
    service_name="bedrock-runtime",
    region_name="us-west-2",
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID_USER"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY_USER"),
)
network_information_prompt = """
            - 🌐 **HTTP**: `tcp.port == 80`
            - 🔐 **HTTPS**: `tcp.port == 443`
            - 🛠 **SNMP**: `udp.port == 161` or `udp.port == 162`
            - ⏲ **NTP**: `udp.port == 123`
            - 📁 **FTP**: `tcp.port == 21`
            - 🔒 **SSH**: `tcp.port == 22`
            - 🔄 **BGP**: `tcp.port == 179`
            - 🌐 **OSPF**: IP protocol 89 (works directly on IP, no TCP/UDP)
            - 🔍 **DNS**: `udp.port == 53` (or `tcp.port == 53` for larger queries/zone transfers)
            - 💻 **DHCP**: `udp.port == 67` (server), `udp.port == 68` (client)
            - 📧 **SMTP**: `tcp.port == 25` (email sending)
            - 📬 **POP3**: `tcp.port == 110` (email retrieval)
            - 📥 **IMAP**: `tcp.port == 143` (advanced email retrieval)
            - 🔒 **LDAPS**: `tcp.port == 636` (secure LDAP)
            - 📞 **SIP**: `tcp.port == 5060` or `udp.port == 5060` (for multimedia sessions)
            - 🎥 **RTP**: No fixed port, commonly used with SIP for multimedia streams.
            - 🖥 **Telnet**: `tcp.port == 23`
            - 📂 **TFTP**: `udp.port == 69`
            - 💾 **SMB**: `tcp.port == 445` (Server Message Block)
            - 🌍 **RDP**: `tcp.port == 3389` (Remote Desktop Protocol)
            - 📡 **SNTP**: `udp.port == 123` (Simple Network Time Protocol)
            - 🔄 **RIP**: `udp.port == 520` (Routing Information Protocol)
            - 🌉 **MPLS**: IP protocol 137 (Multi-Protocol Label Switching)
            - 🔗 **EIGRP**: IP protocol 88 (Enhanced Interior Gateway Routing Protocol)
            - 🖧 **L2TP**: `udp.port == 1701` (Layer 2 Tunneling Protocol)
            - 💼 **PPTP**: `tcp.port == 1723` (Point-to-Point Tunneling Protocol)
            - 🔌 **Telnet**: `tcp.port == 23` (Unencrypted remote access)
            - 🛡 **Kerberos**: `tcp.port == 88` (Authentication protocol)
            - 🖥 **VNC**: `tcp.port == 5900` (Virtual Network Computing)
            - 🌐 **LDAP**: `tcp.port == 389` (Lightweight Directory Access Protocol)
            - 📡 **NNTP**: `tcp.port == 119` (Network News Transfer Protocol)
            - 📠 **RSYNC**: `tcp.port == 873` (Remote file sync)
            - 📡 **ICMP**: IP protocol 1 (Internet Control Message Protocol, no port)
            - 🌐 **GRE**: IP protocol 47 (Generic Routing Encapsulation, no port)
            - 📶 **IKE**: `udp.port == 500` (Internet Key Exchange for VPNs)
            - 🔐 **ISAKMP**: `udp.port == 4500` (for VPN traversal)
            - 🛠 **Syslog**: `udp.port == 514`
            - 🖨 **IPP**: `tcp.port == 631` (Internet Printing Protocol)
            - 📡 **RADIUS**: `udp.port == 1812` (Authentication), `udp.port == 1813` (Accounting)
            - 💬 **XMPP**: `tcp.port == 5222` (Extensible Messaging and Presence Protocol)
            - 🖧 **Bittorrent**: `tcp.port == 6881-6889` (File-sharing protocol)
            - 🔑 **OpenVPN**: `udp.port == 1194`
            - 🖧 **NFS**: `tcp.port == 2049` (Network File System)
            - 🔗 **Quic**: `udp.port == 443` (UDP-based transport protocol)
            - 🌉 **STUN**: `udp.port == 3478` (Session Traversal Utilities for NAT)
            - 🛡 **ESP**: IP protocol 50 (Encapsulating Security Payload for VPNs)
            - 🛠 **LDP**: `tcp.port == 646` (Label Distribution Protocol for MPLS)
            - 🌐 **HTTP/2**: `tcp.port == 8080` (Alternate HTTP port)
            - 📁 **SCP**: `tcp.port == 22` (Secure file transfer over SSH)
            - 🔗 **GTP-C**: `udp.port == 2123` (GPRS Tunneling Protocol Control)
            - 📶 **GTP-U**: `udp.port == 2152` (GPRS Tunneling Protocol User)
            - 🔄 **BGP**: `tcp.port == 179` (Border Gateway Protocol)
            - 🌐 **OSPF**: IP protocol 89 (Open Shortest Path First)
            - 🔄 **RIP**: `udp.port == 520` (Routing Information Protocol)
            - 🔄 **EIGRP**: IP protocol 88 (Enhanced Interior Gateway Routing Protocol)
            - 🌉 **LDP**: `tcp.port == 646` (Label Distribution Protocol)
            - 🛰 **IS-IS**: ISO protocol 134 (Intermediate System to Intermediate System, works directly on IP)
            - 🔄 **IGMP**: IP protocol 2 (Internet Group Management Protocol, for multicast)
            - 🔄 **PIM**: IP protocol 103 (Protocol Independent Multicast)
            - 📡 **RSVP**: IP protocol 46 (Resource Reservation Protocol)
            - 🔄 **Babel**: `udp.port == 6696` (Babel routing protocol)
            - 🔄 **DVMRP**: IP protocol 2 (Distance Vector Multicast Routing Protocol)
            - 🛠 **VRRP**: `ip.protocol == 112` (Virtual Router Redundancy Protocol)
            - 📡 **HSRP**: `udp.port == 1985` (Hot Standby Router Protocol)
            - 🔄 **LISP**: `udp.port == 4341` (Locator/ID Separation Protocol)
            - 🛰 **BFD**: `udp.port == 3784` (Bidirectional Forwarding Detection)
            - 🌍 **HTTP/3**: `udp.port == 443` (Modern web traffic)
            - 🛡 **IPSec**: IP protocol 50 (ESP), IP protocol 51 (AH)
            - 📡 **L2TPv3**: `udp.port == 1701` (Layer 2 Tunneling Protocol)
            - 🛰 **MPLS**: IP protocol 137 (Multi-Protocol Label Switching)
            - 🔑 **IKEv2**: `udp.port == 500`, `udp.port == 4500` (Internet Key Exchange Version 2 for VPNs)
            - 🛠 **NetFlow**: `udp.port == 2055` (Flow monitoring)
            - 🌐 **CARP**: `ip.protocol == 112` (Common Address Redundancy Protocol)
            - 🌐 **SCTP**: `tcp.port == 9899` (Stream Control Transmission Protocol)
            - 🖥 **VNC**: `tcp.port == 5900-5901` (Virtual Network Computing)
            - 🌐 **WebSocket**: `tcp.port == 80` (ws), `tcp.port == 443` (wss)
            - 🔗 **NTPv4**: `udp.port == 123` (Network Time Protocol version 4)
            - 📞 **MGCP**: `udp.port == 2427` (Media Gateway Control Protocol)
            - 🔐 **FTPS**: `tcp.port == 990` (File Transfer Protocol Secure)
            - 📡 **SNMPv3**: `udp.port == 162` (Simple Network Management Protocol version 3)
            - 🔄 **VXLAN**: `udp.port == 4789` (Virtual Extensible LAN)
            - 📞 **H.323**: `tcp.port == 1720` (Multimedia communications protocol)
            - 🔄 **Zebra**: `tcp.port == 2601` (Zebra routing daemon control)
            - 🔄 **LACP**: `udp.port == 646` (Link Aggregation Control Protocol)
            - 📡 **SFlow**: `udp.port == 6343` (SFlow traffic monitoring)
            - 🔒 **OCSP**: `tcp.port == 80` (Online Certificate Status Protocol)
            - 🌐 **RTSP**: `tcp.port == 554` (Real-Time Streaming Protocol)
            - 🔄 **RIPv2**: `udp.port == 521` (Routing Information Protocol version 2)
            - 🌐 **GRE**: IP protocol 47 (Generic Routing Encapsulation)
            - 🌐 **L2F**: `tcp.port == 1701` (Layer 2 Forwarding Protocol)
            - 🌐 **RSTP**: No port (Rapid Spanning Tree Protocol, L2 protocol)
            - 📞 **RTCP**: Dynamic ports (Real-time Transport Control Protocol)
        """

system_prompt = """You are a network engineer capable of understanding network traffic through info 

                        provided by packets captured\n. You hae been given a csv file to analyze, 
                        where each row represents a packet and the columns represent the packet's attributes."""

class PcapToDf:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.row = []
        self.df = pd.DataFrame()
        self.json_path = self.create_json()
        self.pcap_to_json()

    def create_json(self):
        return self.pcap_file.replace(".pcap", ".json")

    def pcap_to_json(self):
        command = f"tshark -nlr {self.pcap_file} -T json > {self.json_path}"
        subprocess.run(command, shell=True)

    def extract_vals_from_dict(self, my_dict):
        if my_dict is not None:
            s = my_dict.items()
            for k, v in s:
                if isinstance(v, dict):
                    my_dict = v
                    self.extract_vals_from_dict(my_dict)
                else:
                    self.columns[k] = v
                    my_dict = None

    def add_row_with_missing_cols(self, df, new_row_dict):
        # Identify existing and new columns
        existing_cols = set(df.columns)
        new_cols = set(new_row_dict.keys()) - existing_cols

        # Add missing columns with NaN
        # df[list(new_cols)] = np.nan
        df = df.reindex(columns=list(df.columns) + list(new_cols), fill_value=np.nan)
        # Add the new row
        df.loc[len(df)] = new_row_dict
        return df

    def create_df(self):
        with open(self.json_path, "r") as file:
            data_dict = json.load(file)
        for d in data_dict:
            self.columns = {}
            self.extract_vals_from_dict(d)
            self.df = self.add_row_with_missing_cols(self.df, self.columns)
        return self.df


def query_openai(prompt):
    """
    Query the OpenAI GPT model with a prompt using the updated client.
    """
    try:
        chat_completion = client_openai.chat.completions.create(
            model="gpt-4o",  # Specify the model
            temperature=0.0,  # Set the temperature to 0 for deterministic outputs
            messages=[{"role": "user", "content": prompt}]
        )
        return chat_completion.choices[0].message.content
    except Exception as e:
        raise RuntimeError(f"Error querying OpenAI API: {e}")


def query_bedrock(prompt,model_id="meta.llama3-1-70b-instruct-v1:0"):
    max_tokens = 8192
    formatted_prompt = f"""
        <|begin_of_text|>
        <|start_header_id|>system<|end_header_id|>
        {system_prompt}
        <|start_header_id|>user<|end_header_id|>
        {prompt}
        <|eot_id|>
        <|start_header_id|>assistant<|end_header_id|>
        """
            
    native_request = {
        "prompt": formatted_prompt,
        "max_gen_len": max_tokens,
        "temperature": 0.0,
        }
    request = json.dumps(native_request)

    try:
        # Invoke the model with the request.
        response = bedrock.invoke_model(
        modelId=model_id,
        body=request,
        contentType="application/json"
        )

        # Decode the response body.
        model_response = json.loads(response["body"].read())
        response_text = model_response["generation"]
        return response_text

    except (ClientError, Exception) as e:
        st.error(f"ERROR: Can't invoke '{model_id}'. Reason: {e}")

def query_groq(query, model_id="llama-3.3-70b-versatile"):
    try:
        chat_completion = client_groq.chat.completions.create(
        messages=[
        {
            "role": "system",
            "content": system_prompt,
        },
        {
            "role": "user",
            "content": query,
        }
    ],

        # The language model which will generate the completion.
        model=model_id,
        temperature=0.0,
        max_tokens=8192,
        top_p=1,
        stop=None,
        stream=False,
    )
        return chat_completion.choices[0].message.content
    except Exception as e:
        raise RuntimeError(f"Error querying Groq API: {e}")








"""
r = PcapToDf("./temp/bgp.pcap")
df = r.create_df()
df.to_csv("bgp.csv", index=False)

df2 = df.describe(include='all')
df2.to_csv("bgp_describe.csv", index=False)
"""