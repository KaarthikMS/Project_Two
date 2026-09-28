import chromadb
from chromadb.config import Settings
import os

class ChromaClient:
    def __init__(self, persist_directory="./chroma_db"):
        self.persist_directory = persist_directory
        # Ensure directory exists
        if not os.path.exists(self.persist_directory):
            os.makedirs(self.persist_directory)
            
        self.client = chromadb.PersistentClient(path=self.persist_directory)

    def get_or_create_collection(self, name):
        return self.client.get_or_create_collection(name=name)

    def add_documents(self, collection_name, documents, embeddings, metadatas, ids):
        collection = self.get_or_create_collection(collection_name)
        collection.add(
            documents=documents,
            embeddings=embeddings,
            metadatas=metadatas,
            ids=ids
        )

    def query_collection(self, collection_name, query_embeddings, n_results=3):
        collection = self.get_or_create_collection(collection_name)
        return collection.query(
            query_embeddings=query_embeddings,
            n_results=n_results
        )
