#!/bin/bash

# Start the ChromaDB cleanup script in the background
python3 src/chroma_cleanup.py &

# Run the main Streamlit application
streamlit run src/packet_analysis.py --server.port=8501 --server.address=0.0.0.0