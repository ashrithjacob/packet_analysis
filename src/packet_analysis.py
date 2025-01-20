import streamlit as st
import os
import json
import subprocess
import numpy as np
import dspy
import uuid
# import helper as hp
import pandas as pd
from pathlib import Path
from langchain_community.vectorstores import Chroma
from langchain_community.document_loaders import JSONLoader
from langchain_experimental.text_splitter import SemanticChunker
from langchain_openai import OpenAIEmbeddings
from dotenv import load_dotenv

load_dotenv()

class Frontend:
    def page_intro(logo="images/Nanites.svg"):
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

    @classmethod
    def process_multifile_pcap(cls):
        files = []
        uploaded_files = st.file_uploader(
            "Upload a PCAP file(s)", type=["pcap", "pcapng"], accept_multiple_files=True
        )
        for uploaded_file in uploaded_files:
            paths = Backend.upload_and_process_pcap(uploaded_file)
            files.append(paths)
        return files

    def view_csv_file(files):
        for file in files:
            file_name_json = file["json_path"]
            file_name_csv = Path(file_name_json).stem + ".csv"
            df = Parser.json_to_df(file_name_json)
            st.markdown(f"*{file_name_csv}*")
            st.dataframe(df)


class Backend:
    def _check_max_size_limit(uploaded_file, max_pcap_size_mb=1):
        if uploaded_file:
            st.write(f"Processing uploaded PCAP file...{uploaded_file.name}")
            if uploaded_file.size > max_pcap_size_mb * 1024 * 1024:
                st.message(
                    f"The file exceeds the maximum size of {max_pcap_size_mb} MB. System might be very slow."
                )
                return False
            return True

    @classmethod
    def _create_temp_dir(cls, dir_name):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        cls.temp_dir = os.path.join(current_dir, dir_name)
        os.makedirs(cls.temp_dir, exist_ok=True)

    @classmethod
    def _get_json_path(cls, uploaded_file):
        pcap_path = os.path.join(cls.temp_dir, uploaded_file.name)
        pcap_extention = uploaded_file.name.split(".")[-1]
        json_path = pcap_path.replace(pcap_extention, "json")
        print("json_path", json_path)
        return {"pcap_path": pcap_path, "json_path": json_path}

    @classmethod
    def upload_and_process_pcap(cls, uploaded_file):
        if cls._check_max_size_limit(uploaded_file):
            cls._create_temp_dir(dir_name="temp")
            paths = cls._get_json_path(uploaded_file)

            # Write the uploaded pcap file to the temp directory
            with open(paths["pcap_path"], "wb") as f:
                f.write(uploaded_file.getvalue())

            # Convert pcap to JSON
            Parser.pcap_to_json(paths["pcap_path"], paths["json_path"])
            return paths


class Parser(Backend):
    def json_to_df(json_path):
        j_to_df = JsonToDf(json_path)
        df = j_to_df.create_df()
        return df

    def pcap_to_json(pcap_path, json_path):
        # Convert pcap to JSON
        command = f"tshark -nlr '{pcap_path}' -T json > '{json_path}'"
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


class JsonToDf:
    def __init__(self, json_path):
        self.json_path = json_path
        self.row = []
        self.df = pd.DataFrame()

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


@st.cache_resource
def load_model():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        st.error("OpenAI API Key is missing. Please set it in the .env file.")
        return None
    try:
        with st.spinner("Loading OpenAI Embeddings..."):
            embedding_model = OpenAIEmbeddings(api_key=api_key)
        return embedding_model
    except Exception as e:
        st.error(f"Error loading model: {e}")
        return None


# Function to generate priming text based on pcap data


class ChatWithPCAP:
    def __init__(self, json_path, models):
        self.priming_text = st.session_state.get("priming_text", "")
        self.models = models
        self.embedding_model = load_model()
        self.chroma_store = self._make_chroma_store()
        self.pages = None
        self.docs = None
        self.vectordb = None
        self.memory = None
        self.llm_chains = None
        self.conversation_history = []

        # Load and process the JSON file
       # for json_file in json_paths:
        self.json_path = json_path
        self.load_json()
        self.split_into_chunks()
        self.store_in_chroma()
        # self.setup_conversation_memory()
        # self.initialize_llm_chains()

    def _make_chroma_store(self):
        chroma_store = Path(__file__).parent / "chroma_store"
        os.makedirs(chroma_store, exist_ok=True)
        return chroma_store


    def _get_system_text(self, pcap_data: str) -> str:
        PACKET_WHISPERER = f"""
        You are an expert assistant specialized in analyzing packet captures (PCAPs) for troubleshooting and technical analysis. Use the data in the provided to answer user questions accurately.

        Your goal is to provide a clear, concise, and accurate analysis of the packet capture data, leveraging the packet details from the uploaded .pcap JSON.
        """
        return PACKET_WHISPERER

    def load_json(self):
        """Load and split JSON data into pages."""
        with st.spinner("Loading JSON data..."):
            # Use jq schema to exclude specific fields
            self.loader = JSONLoader(
                file_path=self.json_path,
                jq_schema="""
                    .[] 
                    | ._source.layers
                    | del(.data)
                """,
                text_content=False,
            )
            self.pages = self.loader.load_and_split()

        if not self.pages:
            st.error("No data loaded from JSON file. Please check the input file.")
            raise ValueError("No data loaded from JSON file.")

    def split_into_chunks(self):
        """Split loaded pages into smaller, meaningful chunks."""
        with st.spinner("Splitting into chunks..."):
            text_splitter = SemanticChunker(
                embeddings=self.embedding_model, breakpoint_threshold_type="percentile"
            )
            self.docs = text_splitter.split_documents(self.pages)

        if not self.docs:
            st.error(
                "No documents were generated from the PCAP data. Please check the input file."
            )
            raise ValueError("Document splitting resulted in an empty list.")

    def store_in_chroma(self):
        """Store chunks in Chroma for vector search."""
        with st.spinner("Storing in Chroma..."):
            session_id = st.session_state.get("session_id", str(uuid.uuid4()))
            st.session_state["session_id"] = session_id
            persist_directory = os.path.join(self.chroma_store,f"chroma_db_{session_id}")
            self.vectordb = Chroma.from_documents(
                self.docs,
                embedding=self.embedding_model,
                persist_directory=persist_directory,
            )

    def reasoning_logic(self, lm, context, question):
        dspy.configure(lm=lm)
        respond = dspy.ChainOfThought("context, question -> answer")
        result = respond(context=context, question=question)
        # Print the history of prompts
        # dspy.inspect_history(n=5)
        return result

    def chat(self, question, llm):
        all_results = []
        response_placeholders = {}

        # Retrieve relevant documents
        retrieved_docs = self.vectordb.as_retriever(
            search_kwargs={"k": 5}
        ).get_relevant_documents(question)
        retrieved_text = "\n\n".join(doc.page_content for doc in retrieved_docs)

        # Create system text
        system_text = st.session_state.get(
            "priming_text", self._get_system_text(retrieved_text)
        )

        # Prepend system and retrieved context to the question
        full_prompt = f"{system_text}\n\nContext:\n{retrieved_text}"
        print("Retrieved text:\n", retrieved_text)

        if llm == self.models[0]:
            lm = dspy.LM("openai/gpt-4o", api_key=os.getenv("OPENAI_API_KEY"))
        elif llm == self.models[1]:
            lm = dspy.LM(
                "openai/llama-3.3-70b-versatile",
                api_key=os.getenv("GROQ_API_KEY"),
                api_base="https://api.groq.com/openai/v1",
            )

        response_placeholders= self.reasoning_logic(
            lm=lm, context=full_prompt, question=question
        )
        return response_placeholders.reasoning, response_placeholders.answer


# Main Application Logic
def main():
    root_dir = Path(__file__).parent.parent
    image_dir = "images/Nanites.svg"
    # Display the introduction page
    Frontend.page_intro(logo=os.path.join(root_dir, image_dir))

    # Step 1:
    st.subheader("Step 1:  Upload and convert one or multiple PCAPs")
    files = Frontend.process_multifile_pcap()
    st.markdown("---")

    # Step 2:
    if files:
        st.subheader("Step 2: View uploaded CSV files")
        Frontend.view_csv_file(files)
        st.markdown("---")

    # Step 3:
    st.subheader("Step 3: Choose the model of choice for the querying")
    models = ("GPT-4o", "Llama-3.3-70b")
    llm = st.selectbox("Choose the model", models)
    st.markdown("---")

    # Step 4:
    st.subheader("Step 4: Query the file with AI Assistance")
    if "chat_instance" not in st.session_state and files:
        st.session_state["chat_instance"] = ChatWithPCAP(json_path=files[0]["json_path"], models=models)

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

        response_reasoning, response_answer = st.session_state["chat_instance"].chat(prompt, llm)
        # Display assistant response in chat message container
        with st.chat_message("assistant"):
            st.subheader("Reasoning:")
            st.markdown(response_reasoning)
            st.subheader("Answer:")
            st.markdown(response_answer)
        # Add assistant response to chat history
        st.session_state.messages.append(
            {"role": "assistant", "content": response_answer}
        )


if __name__ == "__main__":
    main()
