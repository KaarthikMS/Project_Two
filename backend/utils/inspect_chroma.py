import chromadb
from chromadb.config import Settings
import json
import os

def inspect_kb(persist_dir="chroma_db"):
    """
    Utility script to inspect the contents of the Project_Two Knowledge Base.
    """
    if not os.path.exists(persist_dir):
        print(f"❌ Error: Database directory '{persist_dir}' not found.")
        return

    print(f"🔍 Connecting to Knowledge Base at: {os.path.abspath(persist_dir)}")
    client = chromadb.PersistentClient(path=persist_dir)
    
    collections = client.list_collections()
    if not collections:
        print("📭 The database is currently empty (no collections found).")
        return

    print(f"📊 Found {len(collections)} collections:")
    
    for collection in collections:
        count = collection.count()
        print(f"\n📦 Collection: '{collection.name}' ({count} items)")
        
        if count > 0:
            # Peek at the items
            peek = collection.peek(limit=2)
            for i in range(len(peek['ids'])):
                print(f"  🔹 ID: {peek['ids'][i]}")
                print(f"     Metadata: {json.dumps(peek['metadatas'][i], indent=7)}")
                content_snippet = peek['documents'][i][:100].replace('\n', ' ')
                print(f"     Content: {content_snippet}...")
                print("-" * 20)

if __name__ == "__main__":
    inspect_kb()
