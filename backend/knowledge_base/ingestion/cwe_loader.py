import json
import uuid
from backend.knowledge_base.processing.chunker import Chunker
from backend.knowledge_base.processing.embedder import Embedder
from backend.knowledge_base.vector_store.chroma_client import ChromaClient

class CWELoader:
    def __init__(self):
        self.chunker = Chunker(chunk_size=1000, chunk_overlap=100)
        self.embedder = Embedder()
        self.vector_store = ChromaClient()
        self.collection_name = "security_knowledge"

    def load_cwe(self, cwe_list):
        """
        Ingests a list of CWE definitions.
        Expected format: [{"id": "CWE-79", "name": "Cross-site Scripting", "description": "..."}]
        """
        for weakness in cwe_list:
            text = f"CWE ID: {weakness['id']}\nName: {weakness['name']}\nDescription: {weakness['description']}"
            chunks = self.chunker.split_text(text)
            
            for chunk in chunks:
                embedding = self.embedder.get_embedding(chunk)
                doc_id = str(uuid.uuid4())
                
                self.vector_store.add_documents(
                    collection_name=self.collection_name,
                    documents=[chunk],
                    embeddings=[embedding],
                    metadatas=[{"source": "CWE", "id": weakness['id'], "name": weakness['name']}],
                    ids=[doc_id]
                )
        print(f"Loaded {len(cwe_list)} CWE items into vector store.")
