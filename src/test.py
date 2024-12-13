import os
import pandas as pd
import subprocess
import streamlit as st
import re
import boto3
import anthropic
import json
from botocore.exceptions import ClientError
from openai import OpenAI
from mac_vendor_lookup import MacLookup
from dotenv import load_dotenv
from groq import Groq
load_dotenv()

MAX_FILE_SIZE_MB = 1
uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap", "pcapng"])

if uploaded_file:
    if uploaded_file.size > MAX_FILE_SIZE_MB * 1024 * 1024:
        st.error(f"The file exceeds the maximum size of {MAX_FILE_SIZE_MB} MB.")

    temp_dir = "temp"
    os.makedirs(temp_dir, exist_ok=True)

    pcap_path = os.path.join(temp_dir, uploaded_file.name)
    csv_path = pcap_path.replace(".pcap", ".csv")

    with open(pcap_path, "wb") as f:
        f.write(uploaded_file.getvalue())
