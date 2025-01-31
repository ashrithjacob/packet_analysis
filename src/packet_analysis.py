import streamlit as st
import os
import json
import subprocess
import numpy as np
import dspy
import uuid
import shutil
import ast
import re
import pandas as pd
from groq import Groq
from pydantic import BaseModel
from openai import OpenAI
from pathlib import Path
from langchain_community.vectorstores import Chroma
from langchain_community.document_loaders import JSONLoader
from langchain_experimental.text_splitter import SemanticChunker
from langchain_openai import OpenAIEmbeddings
from langchain_core.tools import tool
from dotenv import load_dotenv

load_dotenv()

groq = Groq(api_key = os.getenv("GROQ_API_KEY"))
gpt = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

lm_gpt4o = dspy.LM("openai/gpt-4o", temperature=0.9, api_key=os.getenv("OPENAI_API_KEY"))
lm_llama70b_r1 = dspy.LM(
                "openai/deepseek-r1-distill-llama-70b",
                api_key=os.getenv("GROQ_API_KEY"),
                api_base="https://api.groq.com/openai/v1",
            )
dspy.configure(lm=lm_gpt4o)

class ColumnSelectorQA(dspy.Signature):
    """Answer questions with short factoid answers."""
    context = dspy.InputField(desc="a paragraph of text")
    question = dspy.InputField()
    answer = dspy.OutputField(desc="list of column names")

class RouterQA(dspy.Signature):
    """Answer questions with short factoid answers."""
    question = dspy.InputField(desc=" task description")
    answer = dspy.OutputField(desc="`more_context` or `dataframe_operation`")

class CodingQA(dspy.Signature):
    """Answer questions with short factoid answers."""
    question = dspy.InputField()
    answer = dspy.OutputField(desc="code snippet list")

class DescriptionQA(dspy.Signature):
    """Answer in descriptive format"""
    context = dspy.InputField(desc="a paragraph of text with pcap in csv format")
    question = dspy.InputField()
    answer = dspy.OutputField(desc="concise and non generic answer rendered with a heading and in markdown format")

class GotAnswerJudge(dspy.Signature):
    """Judge if the answer is factually correct based on the context."""
    question = dspy.InputField(desc="Question to be answered")
    answer = dspy.InputField(desc="Answer for the question")
    factually_correct = dspy.OutputField(desc="Is the question addressed completely by the answer?", prefix="Factual[Yes/No]:")

class LongOrShortJudge(dspy.Signature):
    """Judge if the answer is to be descriptive or can be done in one step."""
    question = dspy.InputField(desc="Question to be answered")
    long_or_short = dspy.OutputField(desc="Will a precise answer satisfy the user(i.e are they asking a specific question) or a long descriptive one (i.e are they generally exploring ther pcap)? If in doubt go with `short`", prefix="Long or Short")

class Task:
    def __init__(self, df, user_query):
        self.df = df
        self.user_query = user_query
        self.columns = df.columns.tolist()[1:]
        self.column_cot = dspy.ChainOfThought(ColumnSelectorQA)
        self.router_cot = dspy.ChainOfThought(RouterQA)
        self.coding_cot = dspy.ChainOfThought(CodingQA)
        self.description_cot = dspy.ChainOfThought(DescriptionQA)
        self.long_or_short_judge = dspy.ChainOfThought(LongOrShortJudge)
        self.steps_eval = []
        self.type = None

    def _get_column_names(self, query):
        try:
            context = f""" You are provided a pcap file in csv format. These are the column names in the csv file:
                            str({self.columns})
                        """
            question = f"Return all possible column names with at most 10 columns to fulfil this task: {query}"
            result_cot = self.column_cot(context=context, question=question)
            try:
                columns = ast.literal_eval(result_cot.answer)
                if isinstance(columns, list):
                    return columns
            except Exception as e:
                print("Could not parse the column names to list-> main")
                print("error", e)
                return []
        except Exception as e:
            print(f"Error in _get_column_names: {str(e)}")
            return []

    def _filter_columns(self, columns, query):
        try:
            context = f""" You are provided a pcap file in csv. These are the column names in the csv file:
                            str({columns})
                        """
            question = f"Return the most important columns from the context that would be required to extract information for this task: {query}"
            result_cot = self.column_cot(context=context, question=question)
            try:
                columns_filtered = ast.literal_eval(result_cot.answer)
                if isinstance(columns_filtered, list):
                    return columns_filtered
            except Exception as e:
                print("Could not parse the column names to list-> filtered")
                return columns[:10]  # Return first 10 columns as fallback
        except Exception as e:
            print(f"Error in _filter_columns: {str(e)}")
            return columns[:10]

    def more_context(self, query):
        limit = 5
        try:
            columns = self._get_column_names(query)
            if not columns:  # If no columns returned, use first 10 columns
                columns = self.columns[:limit]
            if len(columns) > limit:
                columns = self._filter_columns(columns, query)
            
            # Ensure we have valid columns before creating markdown
            valid_columns = [col for col in columns if col in self.df.columns]
            if not valid_columns:
                valid_columns = self.df.columns[:limit]
            print("valid_columns", valid_columns)
            df_in_markdown = self.df.loc[:, valid_columns].to_markdown()
            print("df_in_markdown", df_in_markdown)
            context = f""" You are provided a pcap file with only some of the columns shown below:
                            {df_in_markdown}
                        """
            if self.type == "short":
                question = f"""[Question]:{self.user_query} 
                            [IMPORTANT]: DO NOT MENTION 'CSV' or 'PANDAS' in the answer, only refer to the data as a pcap."""
            elif self.type == "long":
                question = f"""You are tasked on expounding on the following task:{query}, with the main goal to answer the question:{self.user_query} 
                            Based on the new information provided in context, return a detailed answer regarding the technical aspects of the task.
                            [IMPORTANT]: DO NOT MENTION 'CSV' or 'PANDAS' in the answer, only refer to the data as a pcap."""
                
            description = self.description_cot(context=context, question=question)
            return description.answer
        except Exception as e:
            print(f"Error in more_context: {str(e)}")
            return f"Unable to process the query due to an error: {str(e)}"


    def router(self, task: str):
        try:
            method_name = "more_context"
            if hasattr(self, method_name):
                method = getattr(self, method_name)
                try:
                    description = method(task)
                    result = {"task": task, 
                              "answer": description,
                              "error": False
                        }
                    self.steps_eval.append(result)
                except Exception as e:
                    error_result = {
                        "task": task,
                        "answer": f"Error processing task: {str(e)}",
                        "error": True
                    }
                    self.steps_eval.append(error_result)
                    print(f"Error executing {method_name}: {str(e)}")
            else:
                error_result = {
                    "task": task,
                    "answer": f"Method {method_name} does not exist",
                    "error": True
                }
                self.steps_eval.append(error_result)
                print(f"Method {method_name} does not exist")
        except Exception as e:
            error_result = {
                "task": task,
                "answer": f"Fatal error in router: {str(e)}",
                "error": True
            }
            self.steps_eval.append(error_result)
            print(f"Fatal error in router: {str(e)}")

    def execute(self, steps):
        question = self.user_query
        context = "\n\n".join(steps)
        long_or_short = self.long_or_short_judge(question=question, context=context)
        print("user query goal", long_or_short.long_or_short)
        if "long" not in long_or_short.long_or_short.lower():
            context = ["\n\n".join(steps)]
            self.type = "short"
            return context
        else:
            self.type = "long"
            return steps

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
        page_icon = "images/nanites-grey.png"
        st.set_page_config(
            page_title="Nanites AI PCAP Copilot",
            page_icon=page_icon,
            layout="centered",
            initial_sidebar_state="auto",
            menu_items=None,
        )
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
            return df


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

    def get_ports_radius(pcap_path):
        port_radius = []
        command = f"tshark -r {pcap_path} -T fields -e udp.port"
        res = subprocess.run(command, shell=True, capture_output=True, text=True)
        x = res.stdout.split("\n")[:-1]
        for port_pair in x:
            if port_pair:
                ports = list(map(int, port_pair.split(",")))
                port_radius.append(min(ports))
        return port_radius

    def is_radius(pcap_path):
        ports = Parser.get_ports_radius(pcap_path)
        if not ports:
            return False
        command = f"tshark -r {pcap_path} -d udp.port=={ports[0]},radius -Y 'radius'"
        res = subprocess.run(command, shell=True, capture_output=True, text=True)
        print(res.stdout)
        if res.stdout:
            return True
        return False
        
    def extract_radius_payload(pcap_path, json_path):
        unique_ports = list(set(Parser.get_ports_radius(pcap_path)))
        udp_command = ",".join([f"radius -d udp.port=={port}" for port in unique_ports])
        command = f"tshark -r {pcap_path} -Y {udp_command},radius -T json -e frame.time -e eth.src -e eth.dst -e eth.type -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e radius.code -e radius.id -e radius.length -e radius.authenticator -e radius.User_Name -e radius.User_Password_encrypted -e radius.NAS_IP_Address -e radius.NAS_Identifier -e radius.Called_Station_Id -e radius.NAS_Port_Type -e radius.NAS_Port -e radius.Calling_Station_Id -e radius.Connect_Info -e radius.Message_Authenticator -e radius.Tunnel_Password_encrypted -e radius.Tunnel_Private_Group_Id -e radius.Tunnel_Medium_Type -e radius.Tunnel_Type -e radius.Acct_Interim_Interval -e radius.Acct_Status_Type -e radius.Acct_Authentic -e radius.Service_Type -e radius.Acct_Session_Id -e radius.Event_Timestamp -e radius.Acct_Delay_Time -e radius.avp.vendor_id -e radius.Unknown_Attribute > {json_path}"
        return command
        
    def pcap_to_json(pcap_path, json_path):
        # Convert pcap to JSON
        if Parser.is_radius(pcap_path):
            command = Parser.extract_radius_payload(pcap_path, json_path)
        else:
            command = f"tshark -nlr '{pcap_path}' -T json > '{json_path}'"

        subprocess.run(command, shell=True)

        # Remove udp.payload and tcp.payload from the JSON
        try:
            with open(json_path, "r") as file:
                data = json.load(file)  # Load the JSON data

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
                elif isinstance(v, list):
                    self.columns[k] = v[0]
                    my_dict = None
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



def step_outliner(df, user_input):
    total_packets = len(df)
    df_head = df.head(3).to_markdown()
    context = f""" You are provided a pcap file in csv format. There are total of {total_packets} packets (rows of the csv), but only first 3 rows are shown below:
                    {df_head}
                    from the context answer the following question :
                """
    question = f"""
                [user profile]: A network engineer is asking you a question about the pcap file(s).
                [question]: {user_input}
                [Note]: provide a list of steps, (highlighted by `###`), to get the answer. Do not write any code. Just provide the required column names, whose entire context would be needed to answer the question.
                """
    query = f"{context}: \n\n{question}"

    completion = groq.chat.completions.create(
        model="deepseek-r1-distill-llama-70b",
        messages=[
            {
                "role": "user",
                "content": query,
            },
        ],
        temperature=0.6,
        top_p=0.95,
        stream=True,
        stop=None,
    )

    full_response = ""
    for chunk in completion:
        content = chunk.choices[0].delta.content or ""
        full_response += content  # Append each chunk to the full response
    return (full_response)  # Optional: still print while storing

def is_serialized(text):
    # Check if a line contains a number followed by a period"
    return bool(re.match(r'.*\d+(\.|:)', text))

def extract_steps(text):
    # Split the text into sections by numbered items
    split_lines = text.split("\n\n")
    steps = [s for s in split_lines if is_serialized(s)]
    return steps

def store_thoughts_and_steps(full_response):
    store = {}
    store["thoughts"] = full_response.split('</think>')[0].split('<think>')[1:]
    steps = extract_steps(full_response.split('</think>')[-1])
    store["steps"] = steps
    return store

def get_store(df, user_input):
    full_response = step_outliner(df, user_input)
    store = store_thoughts_and_steps(full_response)
    return store


# Main Application Logic
def main():
    root_dir = Path(__file__).parent.parent
    image_dir = "images/Nanites.svg"
    chroma_store = Path(__file__).parent / "chroma_store"

    # Display the introduction page
    Frontend.page_intro(logo=os.path.join(root_dir, image_dir))

    # Step 1:
    st.subheader("Step 1:  Upload and convert a single PCAP[upto 1MB]")
    files = Frontend.process_multifile_pcap()
    st.markdown("---")

    json_files = [file["json_path"] for file in files]
    pcap_files = [file["pcap_path"] for file in files]
    print("json_files", json_files)

    # Step 2:
    if files:
        st.subheader("Step 2: View uploaded CSV files")
        st.session_state["df"] = Frontend.view_csv_file(json_files)
        st.markdown("---")

    # Step 3:
    st.subheader("Step 3: Choose the model of choice for the querying")
    models = ("GPT-4o", "Llama-3.3-70b")
    llm = st.selectbox("Choose the model", models)
    st.markdown("---")

    # Step 4:
    print("Step 4")
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
        with st.spinner("Processing User Question..."):
            df = st.session_state["df"]
            store = get_store(df, prompt)
            runner = Task(df, user_query=prompt)
            steps = runner.execute(store["steps"])
            st.chat_message("user").markdown(prompt)
            # Add user message to chat history
            st.session_state.messages.append({"role": "user", "content": prompt})

        # Display assistant response in chat message container
        with st.chat_message("assistant"):
            with st.spinner("Generating AI Response..."):
                for (idx,step) in enumerate(steps):
                    print(f"step {idx}", step)
                    runner.router(step)
                    response = runner.steps_eval[idx]["answer"]
                    st.markdown(response)
        # Add assistant response to chat history
        st.session_state.messages.append(
            {"role": "assistant", "content": response}
        )


if __name__ == "__main__":
    main()
