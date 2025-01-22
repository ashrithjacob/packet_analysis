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
from langchain_core.documents import Document
import chromadb
chroma_client = chromadb.Client()

load_dotenv()

def load_model():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("OpenAI API Key is missing. Please set it in the .env file.")
        return None
    try:
        embedding_model = OpenAIEmbeddings(api_key=api_key)
        return embedding_model
    except Exception as e:
        print(f"Error loading model: {e}")
        return None

document_1 = Document(
    page_content="I had chocolate chip pancakes and scrambled eggs for breakfast this morning.",
    metadata={"source": "tweet"},
    id=1,
)

persist_directory = os.path.join("/home/ash/github/packet_analysis/src/chroma_store",f"chroma_db_test")
embedding_model = load_model()

persistent_client = chromadb.PersistentClient()
collection = persistent_client.get_or_create_collection("collection_name")
vectordb = Chroma.from_documents(
                documents=[document_1],
                embedding=embedding_model,
                persist_directory=persist_directory,
                collection_name="collection_name",
            )
collection = chroma_client.get_or_create_collection(name="my_collection")
results = collection.query(
    query_texts=["How to make pancakes"], # Chroma will embed this for you
    n_results=2, # how many results to return
    embedding_model=embedding_model
)
print(results)


#d = v.as_retriever(search_kwargs={"k":5}).get_relevant_documents("how to make pancakes")
#a = {}
#a["a"] = vectordb
#d = a["a"].as_retriever(search_kwargs={"k":5}).get_relevant_documents("how to make pancakes")
#print(d)