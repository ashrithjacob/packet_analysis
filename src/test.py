import pandas as pd
from openai import OpenAI
import os
import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics.pairwise import cosine_similarity

def plot_high_dim_data(data, method='tsne', perplexity=30, learning_rate='auto', title=None, labels=None):
    """
    Plot high-dimensional data in 2D using PCA or t-SNE
    
    Parameters:
    data: array-like of shape (n_samples, n_features)
    method: 'pca' or 'tsne'
    perplexity: float, optional (default=30) - only for t-SNE
    learning_rate: float, optional (default='auto') - only for t-SNE
    title: string, optional - plot title
    labels: array-like, optional - labels for coloring points
    """
    
    # Convert embeddings to numpy array if they're in a different format
    if isinstance(data, pd.DataFrame):
        data = np.array(data.tolist())
    elif isinstance(data, list):
        data = np.array(data)
    
    # Create figure
    plt.figure(figsize=(10, 8))
    
    # Perform dimensionality reduction
    if method.lower() == 'pca':
        reducer = PCA(n_components=2)
        reduced_data = reducer.fit_transform(data)
        title_prefix = 'PCA'
    else:  # t-SNE
        reducer = TSNE(n_components=2, perplexity=perplexity, learning_rate=learning_rate, 
                      random_state=42)
        reduced_data = reducer.fit_transform(data)
        title_prefix = 't-SNE'
    
    # Create scatter plot
    if labels is not None:
        scatter = plt.scatter(reduced_data[:, 0], reduced_data[:, 1], 
                            c=labels, cmap='viridis', alpha=0.6)
        plt.colorbar(scatter)
    else:
        plt.scatter(reduced_data[:, 0], reduced_data[:, 1], alpha=0.6)
    
    # Add title and labels
    plt.title(title or f'{title_prefix} Visualization of {data.shape[1]}-dimensional data')
    plt.xlabel(f'{title_prefix} Component 1')
    plt.ylabel(f'{title_prefix} Component 2')
    
    # Add grid and style
    plt.grid(True, alpha=0.3)
    sns.despine()
    
    return plt

def get_embedding(text, model="text-embedding-3-small"):
        return client_openai.embeddings.create(input = [text], model=model).data[0].embedding

def get_diverse_vectors(vectors, n_vectors, lambda_param=0.5):
    """
    Select the most diverse vectors using Maximal Marginal Relevance.
    
    Parameters:
    vectors: List or array of vectors
    n_vectors: Number of vectors to select
    lambda_param: Trade-off parameter between relevance and diversity (0 to 1)
                 Higher values favor diversity
    
    Returns:
    selected_vectors: Array of selected diverse vectors
    selected_indices: Indices of selected vectors in original list
    """
    # Convert to numpy array if not already
    vectors = np.array(vectors)
    
    # Calculate similarities between all vectors
    similarities = cosine_similarity(vectors)
    
    # Initialize selected and remaining indices
    remaining_indices = set(range(len(vectors)))
    selected_indices = []
    
    # Select first vector (highest average similarity to all others)
    avg_sim = np.mean(similarities, axis=1)
    first_idx = np.argmax(avg_sim)
    selected_indices.append(first_idx)
    remaining_indices.remove(first_idx)
    
    # Select remaining vectors using MMR
    while len(selected_indices) < n_vectors and remaining_indices:
        # Calculate MMR scores for remaining vectors
        best_score = float('-inf')
        best_idx = None
        
        for idx in remaining_indices:
            # Calculate relevance (similarity to all vectors)
            relevance = np.mean(similarities[idx])
            
            # Calculate diversity (negative similarity to already selected)
            if selected_indices:
                diversity = -np.max(similarities[idx, selected_indices])
            else:
                diversity = 0
                
            # Calculate MMR score
            score = lambda_param * relevance + (1 - lambda_param) * diversity
            
            if score > best_score:
                best_score = score
                best_idx = idx
        
        selected_indices.append(best_idx)
        remaining_indices.remove(best_idx)
    
    # Get selected vectors
    selected_vectors = vectors[selected_indices]
    
    return selected_vectors, selected_indices


if __name__ == "__main__":
    numbers = ['What are the unique source and destination IP addresses in the data?', 
               'What are the most common source and destination ports used in the data?', 
               'What is the total number of packets in the data?', 
               'What is the average packet length in the data?', 
               'What are the unique protocols used in the data?', 
               'What is the distribution of packet lengths in the data?', 
               'What are the most common source and destination MAC addresses in the data?', 
               'What is the average time delta between packets in the data?', 
               'What are the unique BGP messages in the data?', 
               'What is the distribution of packet protocols in the data?', 
               'What are the unique IP versions used in the data?', 
               'What is the average IP length in the data?', 
               'What are the most common expert messages in the data?', 
               'What is the distribution of TCP analysis ACK RTT in the data?', 
               'What are the unique frame protocols used in the data?']
    
    numbers = ['What are the unique source IP addresses in the data?', 
               'What are the unique destination IP addresses in the data?', 
               'What are the unique source ports in the data?', 
               'What are the unique destination ports in the data?', 
               'What are the different protocols used in the data?', 
               'What are the unique source MAC addresses in the data?', 
               'What are the unique destination MAC addresses in the data?', 
               'What is the total number of packets in the data?', 
               'What is the average packet length in the data?', 
               'What is the maximum packet length in the data?', 
               'What is the minimum packet length in the data?', 
               'What are the different types of expert messages in the data?', 
               'What are the unique OUI values for source MAC addresses in the data?', 
               'What are the unique OUI values for destination MAC addresses in the data?', 
               'What is the earliest timestamp in the data?', 'What is the latest timestamp in the data?', 
               'What is the average time delta between packets in the data?', 
               'What is the maximum time delta between packets in the data?', 
               'What is the minimum time delta between packets in the data?', 
               'What are the unique frame numbers in the data?', 
               'What are the unique frame protocols in the data?', 
               'What are the unique IP versions in the data?', 
               'What are the unique TCP analysis ACK RTT values in the data?', 
               'What are the unique TCP analysis ACKs frame values in the data?', 
               'What are the unique Ethernet IG values in the data?', 
               'What are the unique Ethernet LG values in the data?', 
               'What are the unique Ethernet src IG values in the data?', 
               'What are the unique Ethernet src LG values in the data?', 
               'What are the unique Ethernet dst IG values in the data?', 
               'What are the unique Ethernet dst LG values in the data?']

    client_openai = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    embeddings = [get_embedding(i) for i in numbers]
    #print(cosine_similarity(embeddings))

    # Get top 3 most diverse vectors
    n_vectors = 10
    diverse_vectors, indices = get_diverse_vectors(embeddings, n_vectors)
    print("Diverse Vectors:", indices)