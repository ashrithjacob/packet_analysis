import pandas as pd
from openai import OpenAI
import os
import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
import matplotlib.pyplot as plt
import seaborn as sns
import dspy
from sklearn.metrics.pairwise import cosine_similarity
from dotenv import load_dotenv

load_dotenv()

def dspy_run():
    lm = dspy.LM('openai/gpt-4o', api_key=os.getenv("OPENAI_API_KEY"))
    dspy.configure(lm=lm)
    math = dspy.ChainOfThought("question -> answer: float")
    out = math(question="How many 'r's in `raspberry`?")
    print(out)


