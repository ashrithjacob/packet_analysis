import streamlit as st
import os
import json
import subprocess
import numpy as np
import dspy
import uuid
import shutil
import ast
# import helper as hp
import pandas as pd
from pathlib import Path
from langchain_community.vectorstores import Chroma
from langchain_community.document_loaders import JSONLoader
from langchain_experimental.text_splitter import SemanticChunker
from langchain_openai import OpenAIEmbeddings
from langchain_core.tools import tool
from dotenv import load_dotenv

load_dotenv()


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
            file_name_csv = Path(file).stem + ".csv"
            df = Parser.json_to_df(file)
            st.markdown(f"*{file_name_csv}*")
            st.dataframe(df)


class Backend:
    @classmethod
    def _get_pcaps_path(cls, base_path, uploaded_file):
        if "run_number" not in st.session_state:
            st.session_state["run_number"] = cls._get_next_run_folder(base_path)
        run_folder = st.session_state["run_number"]
        subfolder = os.path.join(cls.temp_dir, run_folder)
        os.makedirs(
            subfolder, exist_ok=True
        )  # Create the subfolder if it doesn't exist
        pcap_path = os.path.join(cls.temp_dir, subfolder, uploaded_file.name)
        return pcap_path

    def _get_next_run_folder(base_path):
        # Convert to Path object if string is provided
        path = Path(base_path)

        # Initialize max run number
        max_run = 0

        # Check if path exists
        if path.exists():
            # Look through all folders
            for folder in path.iterdir():
                if folder.is_dir() and folder.name.startswith("run_"):
                    try:
                        # Extract number from folder name
                        run_num = int(folder.name.split("_")[1])
                        max_run = max(max_run, run_num)
                    except (ValueError, IndexError):
                        # Skip folders that don't match the pattern
                        continue

        # Return the next run folder name
        return f"run_{max_run + 1}"

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
    def _get_run_path(cls, uploaded_file):
        pcap_path = cls._get_pcaps_path(cls.temp_dir, uploaded_file)
        pcap_extention = uploaded_file.name.split(".")[-1]
        json_path = pcap_path.replace(pcap_extention, "json")
        print("json_path", json_path)
        return {"pcap_path": pcap_path, "json_path": json_path}

    @classmethod
    def upload_and_process_pcap(cls, uploaded_file):
        if cls._check_max_size_limit(uploaded_file):
            cls._create_temp_dir(dir_name="temp")
            paths = cls._get_run_path(uploaded_file)

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


class StorePCAP:
    def __init__(self, json_paths, models):
        self.priming_text = st.session_state.get("priming_text", "")
        self.models = models
        self.embedding_model = load_model()
        self.chroma_store = self._refresh_chroma_store()
        self.json_paths = json_paths
        self.pages = None
        self.docs = None
        self.vectordb = None
        self.memory = None
        self.llm_chains = None
        self.vectordb_dict = {}
        self.conversation_history = []

        # Load and process the JSON file
        # for json_file in json_paths:
        for json_path in self.json_paths:
            file_name = Path(json_path).stem
            self.json_path = json_path
            self.load_json()
            self.split_into_chunks()
            self.store_in_chroma(file_name=file_name)
        # self.setup_conversation_memory()
        # self.initialize_llm_chains()

    def _refresh_chroma_store(self):
        chroma_store = Path(__file__).parent / "chroma_store"
        os.makedirs(chroma_store, exist_ok=True)
        for item in os.listdir(chroma_store):
            item_path = os.path.join(chroma_store, item)
            try:
                if os.path.isfile(item_path) or os.path.islink(item_path):
                    os.unlink(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
            except Exception as e:
                print(f"Failed to delete {item_path}. Reason: {e}")
        return chroma_store

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

    def store_in_chroma(self, file_name):
        """Store chunks in Chroma for vector search."""
        with st.spinner("Storing in Chroma..."):
            # session_id = st.session_state.get("session_id", str(uuid.uuid4()))
            # st.session_state["session_id"] = session_id
            persist_directory = os.path.join(
                self.chroma_store, f"chroma_db_{file_name}"
            )
            self.vectordb = Chroma.from_documents(
                self.docs,
                embedding=self.embedding_model,
                persist_directory=persist_directory,
            )
            self.vectordb_dict[file_name] = self.vectordb


class RetrievePCAP:
    def __init__(self, store_pcap: StorePCAP, llm: str):
        self.store_pcap = store_pcap
        self.llm = llm

    def _get_system_text(self, pcap_data: str) -> str:
        PACKET_WHISPERER = f"""
        You are an expert assistant copilot specialized in analyzing packet captures (PCAPs) for troubleshooting and technical analysis. Use the data in the provided to answer user questions accurately.

        Your goal is to provide a clear, descriptive and accurate analysis of the packet capture data, leveraging the packet details from the uploaded .pcap JSON.
        """
        return PACKET_WHISPERER

    def get_concerned_files(self, question):
        all_files = [f"{Path(file).stem}" for file in self.store_pcap.json_paths]
        st.write(f"Available files: {all_files}")
        context = f""" Provided the following PCAP files: {str(all_files)} and the question: {question}
                    return the relevant files for the question, it can be one or all files but never zero files
                    return as a list of files
                    """
        response = self.reasoning_logic(context, question, llm=self.store_pcap.models[0])
        files = ast.literal_eval(response.answer)
        st.write(f"Concerned files: {files}")
        return files

    def get_multifile_context(self, concerned_files, question):
        expanded_query = self.query_expansion(question, files=concerned_files)
        st.write(f"Expanded query: {expanded_query}")
        if list(expanded_query.keys()) == concerned_files:
            # Retrieve relevant documents
            context = ""
            for file in concerned_files:
                vector_db = self.store_pcap.vectordb_dict[file]
                retrieved_docs = vector_db.as_retriever(
                    search_kwargs={"k": 5}
                ).get_relevant_documents(expanded_query[file])
                #self.save_retrieved_docs(retrieved_docs)
                retrieved_text = "\n\n".join(doc.page_content for doc in retrieved_docs)
                context += f"\n\n #[{file}]#:{retrieved_text}"
            return context, expanded_query
        else:
            st.error("Error in LLM parsing. Please try again.")

    def get_singlefile_context(self, file, question):
        context = ""
        expanded_query = ""
        vector_db = self.store_pcap.vectordb_dict[file]
        retrieved_docs = vector_db.as_retriever(
            search_kwargs={"k": 5}
        ).get_relevant_documents(question)
        #self.save_retrieved_docs(retrieved_docs)
        retrieved_text = "\n\n".join(doc.page_content for doc in retrieved_docs)
        context += f"\n\n #[{file}]#:{retrieved_text}"
        return context, expanded_query


    def reasoning_logic(self, context, question, llm):
        if llm == self.store_pcap.models[0]:
            lm = dspy.LM("openai/gpt-4o", api_key=os.getenv("OPENAI_API_KEY"))
        elif llm == self.store_pcap.models[1]:
            lm = dspy.LM(
                "openai/llama-3.3-70b-versatile",
                api_key=os.getenv("GROQ_API_KEY"),
                api_base="https://api.groq.com/openai/v1",
            )
        dspy.configure(lm=lm)
        respond = dspy.ChainOfThought("context, question -> answer")
        result = respond(context=context, question=question)
        # Print the history of prompts
        # dspy.inspect_history(n=5)
        return result
    
    def query_expansion(self, question, files):
        # Retrieve relevant documents
        context = f""" Provided the following PCAP files: {str(files)} and the origin question: {question};
                   Ask best question to ask each file such that it helps in answering the original question
                   return as a json object with file name as key and question as value.
                    """
        response = self.reasoning_logic(context, question, llm=self.store_pcap.models[0])
        expanded_query = json.loads(response.answer)
        return expanded_query

    def chat(self, question):
        response_placeholders = {}

        concerned_files = self.get_concerned_files(question)

        if len(concerned_files) > 1:
            context, expanded_query = self.get_multifile_context(concerned_files, question)
        elif len(concerned_files) == 1:
            context, expanded_query = self.get_singlefile_context(concerned_files[0], question)
        else:
            st.error("Error in file parsing. Please try again.")
        # Create system text
        system_text = st.session_state.get(
            "priming_text", self._get_system_text(context)
        )

        # Prepend system and retrieved context to the question
        #TODO: find a better way to parse the context
        full_prompt = f"{system_text}\n\n Questions asked from the files:{expanded_query} \n\nContext from respective files:\n{context}"
        #print("Retrieved text:\n", context)

        response_placeholders = self.reasoning_logic(
            context=full_prompt, question=question, llm=self.llm
        )
        return response_placeholders.reasoning, response_placeholders.answer


# Main Application Logic
def main():
    root_dir = Path(__file__).parent.parent
    image_dir = "images/Nanites.svg"
    # Display the introduction page
    Frontend.page_intro(logo=os.path.join(root_dir, image_dir))

    # Step 1:
    st.subheader("Step 1:  Upload and convert one or multiple PCAPs upto 1MB each")
    files = Frontend.process_multifile_pcap()
    st.markdown("---")

    json_files = [file["json_path"] for file in files]
    pcap_files = [file["pcap_path"] for file in files]

    # Step 2:
    if files:
        st.subheader("Step 2: View uploaded CSV files")
        Frontend.view_csv_file(json_files)
        st.markdown("---")

    # Step 3:
    st.subheader("Step 3: Choose the model of choice for the querying")
    models = ("GPT-4o", "Llama-3.3-70b")
    llm = st.selectbox("Choose the model", models)
    st.markdown("---")

    # Step 4:
    st.subheader("Step 4: Query the file with AI Assistance")
    if "chat_instance" not in st.session_state and files:
        st.session_state["chat_instance"] = StorePCAP(
            json_paths=json_files, models=models
        )

    # Initialize chat history
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Display chat messages from history on app rerun
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # React to user input
    if prompt := st.chat_input("Ask a question about the PCAP data"):
        chatbot = RetrievePCAP(store_pcap=st.session_state["chat_instance"], llm=llm)
        # Display user message in chat message container
        st.chat_message("user").markdown(prompt)
        # Add user message to chat history
        st.session_state.messages.append({"role": "user", "content": prompt})

        response_reasoning, response_answer = chatbot.chat(prompt)
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
