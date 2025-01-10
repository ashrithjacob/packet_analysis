import os
import pandas as pd
import subprocess
import streamlit as st
import re
import boto3
import anthropic
import json
import dspy
import helper as hp
from botocore.exceptions import ClientError
from openai import OpenAI
from mac_vendor_lookup import MacLookup
from dotenv import load_dotenv
from groq import Groq
from pydantic import BaseModel

load_dotenv()


class Article(BaseModel):
    title: str
    body: str

# client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
st.set_page_config(page_title="Nanites AI PCAP Copilot", page_icon="images/black.png")
st.session_state["models"]=("GPT-4o", "Llama-3.3-70b")
st.session_state["dataframe_json_multifile"] = {}

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
        "eth.dst_resolved",
        "eth.src_resolved",
        "eth.src.oui_resolved",
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
    #curated_df = df[[col for col in df.columns if col in fields]]
    curated_df = df
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

def process_multifile_pcap():
    uploaded_files = st.file_uploader("Upload a PCAP file(s)", type=["pcap", "pcapng"], accept_multiple_files=True)
    for uploaded_file in uploaded_files:
        full_df = upload_and_process_pcap(uploaded_file)
        if full_df is not None:
            file_name=uploaded_file.name.split(".")[0]
            #st.session_state["dataframe_json_multifile"][file_name] = full_df.dropna(axis=1, how="any")
            st.session_state["dataframe_json_multifile"][file_name] = full_df
        st.session_state["pcap_dataframe_status"] = True

def upload_and_process_pcap(uploaded_file):
    MAX_FILE_SIZE_MB = 1
    if uploaded_file:
        st.write(f"Processing uploaded PCAP file...{uploaded_file.name}")
        if uploaded_file.size > MAX_FILE_SIZE_MB * 1024 * 1024:
            st.error(f"The file exceeds the maximum size of {MAX_FILE_SIZE_MB} MB.")
            return

        temp_dir = "temp"
        os.makedirs(temp_dir, exist_ok=True)

        pcap_path = os.path.join(temp_dir, uploaded_file.name)
        pcap_extention = uploaded_file.name.split(".")[-1]
        csv_path = pcap_path.replace(pcap_extention, "csv")

        with open(pcap_path, "wb") as f:
            f.write(uploaded_file.getvalue())

        try:
            full_df = pcap_to_csv_with_subset(pcap_path, csv_path)
            st.success("PCAP file successfully uploaded!")
        except Exception as e:
            st.error(f"Error processing PCAP: {e}")
        finally:
            if os.path.exists(pcap_path):
                os.remove(pcap_path)
            if os.path.exists(csv_path):
                os.remove(csv_path)
            return full_df


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


def view_csv_file():
    dataframe_list = list(st.session_state["dataframe_json_multifile"].values())
    dataframe_list_keys = list(st.session_state["dataframe_json_multifile"].keys())
    for i, df in enumerate(dataframe_list):
        st.markdown(f"*{dataframe_list_keys[i]}.csv*")
        st.dataframe(df)


def reasoning_logic(lm, context, user_query):
    dspy.configure(lm=lm)
    respond = dspy.ChainOfThought('context, question -> answer')
    result = respond(context=context, question=user_query)
    # Print the history of prompts
    #dspy.inspect_history(n=5)
    return result


def query_interface(user_query, llm):
    """
    Provide an interface to query the processed PCAP table using OpenAI LLM and generate conversational responses.
    """
    if "pcap_dataframe_status" not in st.session_state:
        st.error("Please upload and process PCAP file(s) first.")
        return
    dataframe_list = list(st.session_state["dataframe_json_multifile"].values())

    if len(dataframe_list) == 1:
        df_full = dataframe_list[0]
        context = df_full.to_markdown(index=False)
    else:
        context = ""
        for key, value in st.session_state["dataframe_json_multifile"].items():
            df_in_markdown = value.to_markdown(index=False)
            context += f"{key} : {df_in_markdown}\n\n"

    if not user_query.strip():
        st.warning("Please enter a question.")
        return
    try:
        with st.spinner(f"Generating conversational response with {llm}..."):
            if llm==st.session_state["models"][1]:
                lm = dspy.LM('openai/llama-3.3-70b-versatile', api_key=os.getenv("GROQ_API_KEY"), api_base='https://api.groq.com/openai/v1')
            elif llm==st.session_state["models"][0]:
                lm = dspy.LM('openai/gpt-4o', api_key=os.getenv("OPENAI_API_KEY"))
            result =reasoning_logic(lm=lm, context=context, user_query=user_query)
        return result.reasoning, result.answer
    except Exception as e:
        st.error(f"Error: {e}")



# Main Application Logic
def main():
    logo = "images/Nanites.svg"
    # st.logo(logo, size="large")
    st.image(logo, width=150)
    st.title("Nanites AI PCAP Copilot!!")
    st.markdown("---")
    st.subheader(
        """Welcome to Nanites AI PCAP Copilot! 🚀 Simply upload one or multiple PCAP files and ask a question about the data."""
    )
    st.caption(
        "Note: All information, including PCAPs, JSON files, and vector stores are neither stored nor retained. Data is deleted during or immediately after each session. Please adhere to your organization’s AI policies and governance protocols before uploading any sensitive materials.",
        unsafe_allow_html=False,
        help=None,
    )
    st.subheader("Step 1:  Upload and convert one or multiple PCAPs")
    process_multifile_pcap()
    st.markdown("---")
    st.subheader("Step 2: View uploaded CSV files")
    view_csv_file()
    st.markdown("---")
    st.subheader("Step 3: Choose the model of choice for the querying")
    llm = st.selectbox("Choose the model",st.session_state["models"])
    st.markdown("---")
    st.subheader("Step 4: Query the file with AI Assistance")

    # Initialize chat history
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Display chat messages from history on app rerun
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # React to user input
    if prompt := st.chat_input("Ask a question about the PCAP data"):
        # Display user message in chat message container
        st.chat_message("user").markdown(prompt)
        # Add user message to chat history
        st.session_state.messages.append({"role": "user", "content": prompt})

        #with st.spinner("AI is Processing and compiling a detailed response..."):
        #    questions, files_description = answer_processing(prompt, llm)
        #    response_final=compile_answer(questions, files_description, llm)
        response_reasoning, response_answer = query_interface(prompt, llm)
        # Display assistant response in chat message container
        with st.chat_message("assistant"):
            st.subheader("Reasoning:")
            st.markdown(response_reasoning)
            st.subheader("Answer:")
            st.markdown(response_answer)
        # Add assistant response to chat history
        st.session_state.messages.append({"role": "assistant", "content": response_answer})


if __name__ == "__main__":
    main()
