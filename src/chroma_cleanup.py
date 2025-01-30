import os
import shutil
import schedule
import time
import threading
from pathlib import Path


def cleanup_chroma_folder(folder_path):
    """
    Delete all files and subdirectories in the specified ChromaDB folder.

    Args:
        folder_path (str): Path to the ChromaDB folder to be cleaned
    """
    try:
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)

            # Remove files and directories
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)

        print(f"Cleaned up ChromaDB folder: {folder_path}")
    except Exception as e:
        print(f"Error cleaning up ChromaDB folder: {e}")


def start_cleanup_scheduler(folder_path, interval_mins=1):
    """
    Start a background thread to periodically clean up the ChromaDB folder.

    Args:
        folder_path (str): Path to the ChromaDB folder
        interval_hours (int): Cleanup interval in hours (default: 24)
    """
    # Schedule cleanup every specified hours
    schedule.every(interval_mins).minutes.do(cleanup_chroma_folder, folder_path)

    def run_scheduler():
        while True:
            schedule.run_pending()
            time.sleep(1)

    # Start scheduler in a background thread
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()


if __name__ == "__main__":
    # Adjust this path to match your ChromaDB folder location
    CHROMA_FOLDER_PATH = Path(__file__).parent / "chroma_store"
    start_cleanup_scheduler(CHROMA_FOLDER_PATH, interval_mins=30)
