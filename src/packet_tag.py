import os
import pandas as pd
import subprocess
import streamlit as st
import re
import boto3
import anthropic
import json
import helper as hp
from botocore.exceptions import ClientError
from openai import OpenAI
from mac_vendor_lookup import MacLookup
from dotenv import load_dotenv
from groq import Groq

load_dotenv()


# client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
# Load environment variables
# Configure Streamlit
st.set_page_config(page_title="Packet TAG", page_icon="📄")


# Function to convert .pcap to CSV using a subset of fields
def pcap_to_csv_with_subset(pcap_path, csv_path):
    fields = [
        "frame.number",
        "frame.time",
        "frame.len",
        "frame.ignored",
        "frame.protocols",
        "ip.version",
        "ip.len",
        "ip.src",
        "ip.dst",
        "ip.proto",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.time_relative",
        "tcp.time_delta",
        "tcp.analysis.acks_frame",
        "tcp.analysis.ack_rtt",
        "udp.srcport",
        "udp.dstport",
        "eth.src",
        "eth.src.oui",
        "eth.addr",
        "eth.addr.oui",
        "eth.src.lg",
        "eth.lg",
        "eth.src.ig",
        "eth.ig",
        "eth.dst",
        "eth.dst.oui",
        "eth.addr",
        "eth.addr.oui",
        "eth.dst.lg",
        "eth.dst.ig",
        "dns.qry.name",
        "dns.a",
        "_ws.expert.message",
    ]
    pcap_to_df = hp.PcapToDf(pcap_path)
    df = pcap_to_df.create_df()
    curated_df = df[[col for col in df.columns if col in fields]]
    curated_df.to_csv(csv_path, index=False)
    return curated_df


def load_csv_as_dataframe(csv_path):
    return pd.read_csv(csv_path)


def generate_query_prompt(schema, query):
    """
    Generate a prompt to translate a user question into a structured query.
    """
    return f"""
    The table schema is as follows:
    {schema}

    The table is stored in a variable named `df`.

    Convert the following question into a Pandas DataFrame query:
    Question: {query}

    Provide the query code only. Do not include explanations.
    """


def clean_query(query):
    if "```" in query:
        cleaned_text = re.sub(r"^```\w*\s*|\s*```$", "", query).strip()
    else:
        cleaned_text = query.strip()
    return cleaned_text.split("\n")[0]


def upload_and_process_pcap():
    MAX_FILE_SIZE_MB = 1
    uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap", "pcapng"])

    if uploaded_file:
        if uploaded_file.size > MAX_FILE_SIZE_MB * 1024 * 1024:
            st.error(f"The file exceeds the maximum size of {MAX_FILE_SIZE_MB} MB.")
            return

        temp_dir = "temp"
        os.makedirs(temp_dir, exist_ok=True)

        pcap_path = os.path.join(temp_dir, uploaded_file.name)
        csv_path = pcap_path.replace(".pcap", ".csv")

        with open(pcap_path, "wb") as f:
            f.write(uploaded_file.getvalue())

        try:
            full_df = pcap_to_csv_with_subset(pcap_path, csv_path)
            st.success("PCAP file successfully processed and converted to CSV.")
            st.session_state["pcap_dataframe"] = full_df
        except Exception as e:
            st.error(f"Error processing PCAP: {e}")
        finally:
            if os.path.exists(pcap_path):
                os.remove(pcap_path)
            if os.path.exists(csv_path):
                os.remove(csv_path)


class Tools:
    def agent_prompt(prompt):
        """
        Prompt the agent with a question and return the response.
        """
        response = hp.query_groq(prompt)
        return response

    def filter_json(str_data):
        if "```" in str_data:
            code_blocks = re.findall(r"```(?:.*?\n)?(.*?)```", str_data, re.DOTALL)
            code_blocks = code_blocks[0]
        else:
            code_blocks = re.findall(r"{(.*?)}", str_data, re.DOTALL)
            code_blocks = "{" + code_blocks[0] + "}"
        print("STR", str_data)
        print("Code Blocks1:", code_blocks)
        return json.loads(code_blocks)

    def mac_vendor_lookup(json_data):
        """
        Lookup the vendor information for a given MAC address.
        """
        dict_lookup = {}
        for key, val in json_data.items():
            vendor = MacLookup().lookup(val)
            dict_lookup[val] = vendor
        return dict_lookup

    def run_mac(result_preview):
        try:
            prompt = f"""
                    From these query results:{result_preview}
                    identify the MAC address of the source and destination IP addresses and return all mac addresses as json
                    IMPORTANT: respond in the format ``` {{"column_name_1": "mac_address", "column_name_2": "mac_address"}} ```
                    """
            response = Tools.agent_prompt(prompt)
            json_data = Tools.filter_json(response)
            lookup = Tools.mac_vendor_lookup(json_data)
            return str(lookup), str(response)
        except Exception as e:
            return str(e), str(e)

    def run_network_matching(result_preview):
        prompt = f"""
                From these query results:{result_preview}
                and these network information hints:{hp.network_information_prompt}, identify the protocols used with source and destination IP addresses.
                DO NOT include specific packet details or repeat the network information hints
                """
        response = Tools.agent_prompt(prompt)
        return response


def tag_query_interface():
    """
    Provide an interface to query the processed PCAP table using OpenAI LLM and generate conversational responses.
    """
    if "pcap_dataframe" not in st.session_state:
        st.error("Please upload and process a PCAP file first.")
        return

    df_full = st.session_state["pcap_dataframe"].dropna(axis=1, how="all")
    # df.to_csv("packet_capture_info.csv", index=False)
    user_query = st.text_input("Ask a question about the PCAP data:")

    if st.button("Send Query"):
        if not user_query.strip():
            st.warning("Please enter a question.")
            return

        # Generate schema and prompt for query generation
        schema = "\n".join(f"- {col}" for col in df_full.columns)
        # prompt = generate_query_prompt(schema, user_query)

        try:
            # Query OpenAI to generate DataFrame query
            with st.spinner("Generating DataFrame query..."):
                query_code = 'df.describe(include="all")'

            # Execute the query on the DataFrame
            result = eval(query_code, {"df": df_full})
            #st.markdown("### Query Results:")
            #st.dataframe(result)

            # Convert results to markdown for LLM
            # result_preview = str(result)
            result_preview = result.to_markdown(index=False)
            #full_df_md = df_full.to_markdown(index=False)
            full_df_md = str(df_full)
            print("colmns in df_full", len(df_full.columns))
            print("here1")

            # MAC ID agent
            mac_mapping, mac_response = Tools.run_mac(result_preview)
            print("MAC resp", mac_response)
            print("MAC mapping", mac_mapping)
            # Traffic details
            result_traffic = Tools.run_network_matching(result_preview)
            st.markdown(f"### Traffic Details:{result_traffic}")

            conversational_prompt_with_hints = f"""
            
            This is the user's query: {user_query}
            Here are the query results based on the user's question:{result_preview}

            You are an expert assistant specialized in analyzing packet captures (PCAPs) for troubleshooting and technical analysis. Use the data in the provided packet_capture_info to answer user questions accurately. When a specific application layer protocol is referenced, inspect the packet_capture_info according to these hints. Format your responses in markdown with line breaks, bullet points, and appropriate emojis to enhance readability
            **Network Information Hints:**
            {hp.network_information_prompt}
            use this to identify the traffic details including specific protocols used. Do not include specific packet details, only high-level traffic information.

            **Main Info to be provided:**
            - General Overview of the packet capture data
            - Key observations from the packet capture data
            - Traffic details including specific protocols use this info and be detailed: {result_traffic}
            - Notable events: anomalies, potential issues, and performance metrics
            - Perform MAC OUI lookup and provide the manufacturer of the NIC, using this info from MAC lookup:{mac_mapping}
                and this {mac_response} from the model regarding the MAC address present in packet_capture_info
    
            Your goal is to provide a clear, concise, and accurate analysis of the packet capture data, leveraging the protocol hints and packet details.
            """

            conversational_prompt_without_hints = f"""
            This is the user's query: {user_query}
            Here are the query results based on the user's question:{full_df_md}

            You are an expert assistant specialized in analyzing packet captures (PCAPs) for troubleshooting and technical analysis. Use the data in the provided packet_capture_info to answer user questions accurately. When a specific application layer protocol is referenced, inspect the packet_capture_info according to these hints. Format your responses in markdown with line breaks, bullet points, and appropriate emojis to enhance readability
            **Network Information Hints:**
            use this to identify the traffic details including specific protocols used. Do not include specific packet details, only high-level traffic information.

            **Main Info to be provided:**
            - General Overview of the packet capture data
            - Key observations from the packet capture data
            - Notable events: anomalies, potential issues, and performance metrics including latency and RTT
            - Perform MAC OUI lookup and provide the manufacturer of the NIC, using this info from MAC lookup:{mac_mapping}
            and this {mac_response} from the model regarding the MAC address present in packet_capture_info
    
            Your goal is to provide a clear, concise, and accurate analysis of the packet capture data, leveraging the protocol hints and packet details.
            """

            with st.spinner("Generating conversational response..."):
                conversational_response = hp.query_bedrock(
                    conversational_prompt_without_hints
                )

            st.markdown("### Conversational Response:")
            st.markdown(conversational_response)

        except Exception as e:
            st.error(f"Error: {e}")


def display_sample_pcaps():
    """
    Display a section for downloading sample PCAP files.
    """
    st.subheader("Sample PCAP Files")
    sample_files = {
        "BGP Example": "pcap/bgp.pcap",
        "Single Packet Example": "pcap/capture.pcap",
        "DHCP Example": "pcap/dhcp.pcap",
        "EIGRP Example": "pcap/eigrp.pcap",
        "Slammer Worm Example": "pcap/slammer.pcap",
        "Teardrop Attack Example": "pcap/teardrop.pcap",
        "VXLAN Example": "pcap/vxlan.pcapng",
    }

    for name, path in sample_files.items():
        try:
            with open(path, "rb") as file:
                st.download_button(
                    label=f"Download {name}",
                    data=file,
                    file_name=os.path.basename(path),
                    mime="application/vnd.tcpdump.pcap",
                )
        except FileNotFoundError:
            st.error(f"Sample file '{name}' not found. Please check the file path.")


# Main Application Logic
def main():
    st.title("Packet TAG: Table-Augmented Generation for PCAP Analysis")
    st.markdown("---")
    st.subheader("Step 1: Upload and Convert PCAP")
    upload_and_process_pcap()
    st.markdown("---")
    st.subheader("Step 2: Query the Table with LLM Assistance")
    tag_query_interface()


if __name__ == "__main__":
    main()
