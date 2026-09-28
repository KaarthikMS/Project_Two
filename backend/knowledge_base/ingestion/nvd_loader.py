import json
import uuid
from backend.knowledge_base.processing.chunker import Chunker
from backend.knowledge_base.processing.embedder import Embedder
from backend.knowledge_base.vector_store.chroma_client import ChromaClient

class NVDLoader:
    def __init__(self):
        self.chunker = Chunker(chunk_size=1000, chunk_overlap=100)
        self.embedder = Embedder()
        self.vector_store = ChromaClient()
        self.collection_name = "security_knowledge"

    def load_nvd(self, nvd_list):
        """
        Ingests a list of NVD entries.
        Expected format: [{"cve_id": "CVE-2023-XYZ", "cvss": 9.8, "summary": "...", "references": [...]}]
        """
        for entry in nvd_list:
            text = f"CVE ID: {entry['cve_id']}\nCVSS Score: {entry['cvss']}\nSummary: {entry['summary']}\nReferences: {', '.join(entry.get('references', []))}"
            chunks = self.chunker.split_text(text)
            
            for chunk in chunks:
                embedding = self.embedder.get_embedding(chunk)
                doc_id = str(uuid.uuid4())
                
                self.vector_store.add_documents(
                    collection_name=self.collection_name,
                    documents=[chunk],
                    embeddings=[embedding],
                    metadatas=[{"source": "NVD", "id": entry['cve_id'], "cvss": entry['cvss']}],
                    ids=[doc_id]
                )
        print(f"Loaded {len(nvd_list)} NVD items into vector store.")
