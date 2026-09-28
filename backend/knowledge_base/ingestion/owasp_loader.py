import json
import uuid
from backend.knowledge_base.processing.chunker import Chunker
from backend.knowledge_base.processing.embedder import Embedder
from backend.knowledge_base.vector_store.chroma_client import ChromaClient

class OWASPLoader:
    def __init__(self):
        self.chunker = Chunker(chunk_size=1000, chunk_overlap=100)
        self.embedder = Embedder()
        self.vector_store = ChromaClient()
        self.collection_name = "security_knowledge"

    def load_data(self, owasp_data_list):
        """
        Ingests a list of OWASP patterns/guidelines.
        Expected format: [{"title": "...", "content": "...", "category": "OWASP Top 10"}]
        """
        for item in owasp_data_list:
            text = f"Title: {item['title']}\nCategory: {item['category']}\nContent: {item['content']}"
            chunks = self.chunker.split_text(text)
            
            for chunk in chunks:
                embedding = self.embedder.get_embedding(chunk)
                doc_id = str(uuid.uuid4())
                
                self.vector_store.add_documents(
                    collection_name=self.collection_name,
                    documents=[chunk],
                    embeddings=[embedding],
                    metadatas=[{"source": "OWASP", "title": item['title'], "category": item['category']}],
                    ids=[doc_id]
                )
        print(f"Loaded {len(owasp_data_list)} OWASP items into vector store.")
