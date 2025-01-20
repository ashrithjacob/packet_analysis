import os
import uuid
import json
import requests
import subprocess
import streamlit as st
import dspy
from langchain_community.llms import Ollama
from langchain.chains import ConversationalRetrievalChain
from langchain.memory import ConversationBufferMemory
from langchain_community.vectorstores import Chroma
from langchain_community.document_loaders import JSONLoader
from langchain_experimental.text_splitter import SemanticChunker
from langchain_openai import OpenAIEmbeddings
from dotenv import load_dotenv
from chromadb.config import Settings
from chromadb import Client
from dotenv import load_dotenv

load_dotenv()

import logging

logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")


def pcap_to_json(pcap_path, json_path):
    # Convert pcap to JSON
    command = f"tshark -nlr {pcap_path} -T json > {json_path}"
    subprocess.run(command, shell=True)

    # Remove udp.payload and tcp.payload from the JSON
    try:
        with open(json_path, "r") as file:
            data = json.load(file)  # Load the JSON data

        # Process each packet and remove unwanted fields
        for packet in data:
            layers = packet.get("_source", {}).get("layers", {})
            if "udp" in layers and "udp.payload" in layers["udp"]:
                del layers["udp"]["udp.payload"]
            if "tcp" in layers and "tcp.payload" in layers["tcp"]:
                del layers["tcp"]["tcp.payload"]

        # Save the cleaned JSON back to the file
        with open(json_path, "w") as file:
            json.dump(data, file, indent=4)

    except json.JSONDecodeError as e:
        st.error(f"Error processing JSON file: {e}")
        raise ValueError("Failed to decode JSON file.")
    except Exception as e:
        st.error(f"Unexpected error: {e}")
        raise


# Streamlit UI for uploading and converting pcap file
def upload_and_convert_pcap():
    st.title("Packet KAI8 - Chat with Packet Captures using Multi-AI Consensus")
    uploaded_file = st.file_uploader("Choose a PCAP file", type="pcap")
    if uploaded_file:
        if not os.path.exists("temp"):
            os.makedirs("temp")
        pcap_path = os.path.join("temp", uploaded_file.name)
        json_path = pcap_path + ".json"

        with open(pcap_path, "wb") as f:
            f.write(uploaded_file.getvalue())
        pcap_to_json(pcap_path, json_path)
        st.session_state["json_path"] = json_path
        st.success("PCAP file uploaded and converted to JSON.")
        # Fetch and display the models in a select box
        if st.button("Proceed to Chat"):
            st.session_state.page = 3
            st.rerun()


# Streamlit UI for chat interface
def chat_interface():
    st.title("Packet KAI8 - Chat with Packet Captures using Multi-AI Consensus")
    json_path = st.session_state.get("json_path")
    if not json_path or not os.path.exists(json_path):
        st.error(
            "PCAP file missing or not converted. Please go back and upload a PCAP file."
        )
        return

    if "chat_instance" not in st.session_state:
        st.session_state["chat_instance"] = hp.ChatWithPCAP(json_path=json_path)

    user_input = st.text_input("Ask a question about the PCAP data:")
    if user_input and st.button("Send"):
        with st.spinner("Thinking..."):
            response = st.session_state["chat_instance"].chat(user_input)
            st.markdown("**Synthesized Answer:**")
            if isinstance(response, dict) and "answer" in response:
                st.markdown("REASONING LOGIC:")
                st.markdown(response["answer"].reasoning)
                st.markdown("ANSWER:")
                st.markdown(response["answer"].answer)
            else:
                st.markdown("No specific answer found.")


if __name__ == "__main__":
    if "page" not in st.session_state:
        st.session_state["page"] = 1
    if "selected_models" not in st.session_state:
        st.session_state.selected_models = {
            model: False
            for model in [
                "llama3.1",
                "mistral",
                "qwen",
                "gemma2",
                "phi4",
                "nezahatkorkmaz/deepseek-v3",
            ]
        }

    if st.session_state.page == 1:
        model_selection()
    elif st.session_state.page == 2:
        upload_and_convert_pcap()
    elif st.session_state.page == 3:
        chat_interface()
