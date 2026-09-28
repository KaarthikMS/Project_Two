import json
import uuid
from backend.knowledge_base.processing.chunker import Chunker
from backend.knowledge_base.processing.embedder import Embedder
from backend.knowledge_base.vector_store.chroma_client import ChromaClient

class MITRELoader:
    def __init__(self):
        self.chunker = Chunker(chunk_size=1000, chunk_overlap=100)
        self.embedder = Embedder()
        self.vector_store = ChromaClient()
        self.collection_name = "security_knowledge"

    def load_techniques(self, techniques_list):
        """
        Ingests a list of MITRE ATT&CK techniques.
        Expected format: [{"id": "T1059", "name": "Command and Scripting Interpreter", "description": "..."}]
        """
        for tech in techniques_list:
            text = f"MITRE ID: {tech['id']}\nName: {tech['name']}\nDescription: {tech['description']}"
            chunks = self.chunker.split_text(text)
            
            for chunk in chunks:
                embedding = self.embedder.get_embedding(chunk)
                doc_id = str(uuid.uuid4())
                
                self.vector_store.add_documents(
                    collection_name=self.collection_name,
                    documents=[chunk],
                    embeddings=[embedding],
                    metadatas=[{"source": "MITRE", "id": tech['id'], "name": tech['name']}],
                    ids=[doc_id]
                )
        print(f"Loaded {len(techniques_list)} MITRE techniques into vector store.")
