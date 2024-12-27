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
            st.session_state["dataframe_json_multifile"][file_name] = full_df.dropna(axis=1, how="any")
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
        csv_path = pcap_path.replace(".pcap", ".csv")

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


def tag_query_interface(user_query, llm):
    """
    Provide an interface to query the processed PCAP table using OpenAI LLM and generate conversational responses.
    """
    if "pcap_dataframe_status" not in st.session_state:
        st.error("Please upload and process PCAP file(s) first.")
        return
    dataframe_list = list(st.session_state["dataframe_json_multifile"].values())

    if len(dataframe_list) == 1:
        df_full = dataframe_list[0]
    else:
        files_description = ""
        for key, value in st.session_state["dataframe_json_multifile"].items():
            df_in_markdown = value.to_markdown(index=False)
            files_description += f"{key} : {df_in_markdown}\n\n"


    if not user_query.strip():
        st.warning("Please enter a question.")
        return

    try:
        if len(list(st.session_state["dataframe_json_multifile"].values())) == 1:
            query_code = 'df.describe(include="all")'
            result = eval(query_code, {"df": df_full})
            result_preview = result.to_markdown(index=False)
            # MAC ID agent
            mac_mapping, mac_response = Tools.run_mac(result_preview)
            # Traffic details
            result_traffic = Tools.run_network_matching(result_preview)
            #st.markdown(f"### Traffic Details:{result_traffic}")
            conversational_prompt_with_hints = f"""
            This is the user's query: {user_query}
            Here are the query results based on the user's question:{result_preview}

            You are an expert assistant specialized in analyzing packet captures (PCAPs) for troubleshooting and technical analysis. Use the data in the provided packet_capture_info to answer user questions accurately. When a specific application layer protocol is referenced, inspect the packet_capture_info according to these hints. Format your responses in markdown with line breaks, bullet points, and appropriate emojis to enhance readability
            **Network Information Hints:**
            {hp.network_information_prompt}
            use this to identify the traffic details including specific protocols used. Do not include specific packet details, only high-level traffic information.

            **Provide deeep insight regarding the following points:**
            - General Overview of the packet capture data
            - Key observations from the packet capture data
            - Traffic details including specific protocols use this info and be detailed: {result_traffic}
            - Notable events: anomalies, potential issues, and performance metrics
            - Perform MAC OUI lookup and provide the manufacturer of the NIC, using this info from MAC lookup:{mac_mapping}
                and this {mac_response} from the model regarding the MAC address present in packet_capture_info
    
            Your goal is to provide a clear, concise, and accurate analysis of the packet capture data, leveraging the protocol hints and packet details.
            """
            with st.spinner(f"Generating conversational response with {llm}..."):
                if llm==st.session_state["models"][1]:
                    conversational_response = hp.query_groq(conversational_prompt_with_hints)
                elif llm==st.session_state["models"][0]:
                    conversational_response = hp.query_openai(conversational_prompt_with_hints)
            return_info = result_preview
        else:
            conversational_prompt_multifile = f"""{user_query}

            {files_description}

            """
            with st.spinner(f"Generating conversational response with {llm}..."):
                if llm==st.session_state["models"][1]:
                    conversational_response = hp.query_groq(conversational_prompt_multifile)
                elif llm==st.session_state["models"][0]:
                    conversational_response = hp.query_openai(conversational_prompt_multifile)
            return_info = files_description

        st.session_state["dataframe_json_multifile"] = {}
        user_query = None
        return conversational_response, return_info
    except Exception as e:
        st.error(f"Error: {e}")


def answer_processing(prompt, llm):

    dataframe_list = list(st.session_state["dataframe_json_multifile"].values())

    if len(dataframe_list) == 1:
        query_code = 'df.describe(include="all")'
        file_name = list(st.session_state["dataframe_json_multifile"].keys())[0]
        files_description = f"{file_name} : {dataframe_list[0].head().to_markdown(index=False)}"
        files_description_2 = eval(query_code, {"df":dataframe_list[0]}).to_markdown(index=False)
        columns = dataframe_list[0].columns

    else:
        files_description = ""
        for key, value in st.session_state["dataframe_json_multifile"].items():
            df_in_markdown = value.to_markdown(index=False)
            files_description += f"{key} : {df_in_markdown}\n\n"

    query_expansion_prompt = f"""
                            given the user query: {prompt} and the pcap file:{files_description}
                            generate questions that can be asked off that further verbalise the user prompt?

                            ## Simply list a biref set of questions without any explanation or code. Ensure the question is fully framed and clear.
                            """
    
    if llm==st.session_state["models"][1]:
        query_expansion_response = hp.query_groq(query_expansion_prompt)
    elif llm==st.session_state["models"][0]:
        query_expansion_response = hp.query_openai(query_expansion_prompt)

    # Cleaning the questions
    query_list = query_expansion_response.split("\n")
    query_list = [q.lstrip("'[]0123456789. ") for q in query_list]
    question_list = hp.filter_keywords(query_list)
    print(question_list)
    embeddings = [hp.get_embedding(i) for i in question_list]
    #print(cosine_similarity(embeddings))

    # Get top 3 most diverse vectors
    n_vectors = 3
    diverse_vectors, indices = hp.get_diverse_vectors(embeddings, n_vectors)
    question_list = [question_list[i] for i in indices]
    print(question_list)
    return question_list, files_description

def compile_answer(questions, files_description, llm):
    question_answer = ""
    for question in questions:
        prompt = f"""
            This is the user's query: {question}
            Here are the pcap files in a dataframe format, each file name is provided with it's contents:{files_description}

            You are an expert assistant specialized in analyzing packet captures (PCAPs) for troubleshooting and technical analysis. Use the data in the provided packet_capture_info to answer user questions accurately. When a specific application layer protocol is referenced, inspect the packet_capture_info according to these hints. Format your responses in markdown with line breaks, bullet points, and appropriate emojis to enhance readability
            **Network Information Hints:**
            {hp.network_information_prompt}

            ## Keep the response short and to the point. Just answer the query directly based on the information provided and do not provide any introduction, code or explanation.
            """
        if llm==st.session_state["models"][1]:
            query_expansion_response = hp.query_groq(prompt)
        elif llm==st.session_state["models"][0]:
            query_expansion_response = hp.query_openai(prompt)
        question_answer += f"**{question}**:{query_expansion_response}\n\n"
        print(f"{question}:{query_expansion_response}")
        print("**************")
    compiled_prompt = f"""
            This is the user's query: {question}
            Here are the pcap files in a dataframe format, each file name is provided with it's contents:{files_description}

            You are an expert assistant specialized in analyzing packet captures (PCAPs) for troubleshooting and technical analysis. Use the data in the provided packet_capture_info to answer user questions accurately.
            **Network Information Hints:**
            {hp.network_information_prompt}

            Here are some questions and answers that have already been generated based on the user query and pcap file(s):
            {question_answer}

            ## Generate a detailed response to the user query based on the information provided in the pcap file(s) and the question answers generated.
            """
    if llm==st.session_state["models"][1]:
        query_expansion_response = hp.query_groq(compiled_prompt)
    elif llm==st.session_state["models"][0]:
        query_expansion_response = hp.query_openai(compiled_prompt)

    return query_expansion_response

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
        response_final, meta = tag_query_interface(prompt, llm)
        # Display assistant response in chat message container
        with st.chat_message("assistant"):
            st.markdown(response_final)
        # Add assistant response to chat history
        st.session_state.messages.append({"role": "assistant", "content": response_final})


if __name__ == "__main__":
    main()
