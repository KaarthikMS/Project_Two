import json
import uuid
from backend.knowledge_base.processing.chunker import Chunker
from backend.knowledge_base.processing.embedder import Embedder
from backend.knowledge_base.vector_store.chroma_client import ChromaClient

class CVELoader:
    def __init__(self):
        self.chunker = Chunker(chunk_size=1000, chunk_overlap=100)
        self.embedder = Embedder()
        self.vector_store = ChromaClient()
        self.collection_name = "security_knowledge"

    def load_cve(self, cve_list):
        """
        Ingests a list of CVE findings.
        Expected format: [{"id": "CVE-2023-1234", "description": "...", "severity": "High"}]
        """
        for cve in cve_list:
            text = f"CVE ID: {cve['id']}\nSeverity: {cve['severity']}\nDescription: {cve['description']}"
            chunks = self.chunker.split_text(text)
            
            for chunk in chunks:
                embedding = self.embedder.get_embedding(chunk)
                doc_id = str(uuid.uuid4())
                
                self.vector_store.add_documents(
                    collection_name=self.collection_name,
                    documents=[chunk],
                    embeddings=[embedding],
                    metadatas=[{"source": "CVE", "id": cve['id'], "severity": cve['severity']}],
                    ids=[doc_id]
                )
        print(f"Loaded {len(cve_list)} CVE items into vector store.")
