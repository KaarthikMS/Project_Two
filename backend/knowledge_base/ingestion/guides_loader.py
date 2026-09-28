import json
import uuid
from backend.knowledge_base.processing.chunker import Chunker
from backend.knowledge_base.processing.embedder import Embedder
from backend.knowledge_base.vector_store.chroma_client import ChromaClient

class GuidesLoader:
    def __init__(self):
        self.chunker = Chunker(chunk_size=1000, chunk_overlap=100)
        self.embedder = Embedder()
        self.vector_store = ChromaClient()
        self.collection_name = "security_knowledge"

    def load_guides(self, guides_list):
        """
        Ingests secure coding guides.
        Expected format: [{"language": "Python", "category": "Input Validation", "content": "..."}]
        """
        for guide in guides_list:
            text = f"Language: {guide['language']}\nCategory: {guide['category']}\nContent: {guide['content']}"
            chunks = self.chunker.split_text(text)
            
            for chunk in chunks:
                embedding = self.embedder.get_embedding(chunk)
                doc_id = str(uuid.uuid4())
                
                self.vector_store.add_documents(
                    collection_name=self.collection_name,
                    documents=[chunk],
                    embeddings=[embedding],
                    metadatas=[{"source": "SecureCodingGuides", "language": guide['language'], "category": guide['category']}],
                    ids=[doc_id]
                )
        print(f"Loaded {len(guides_list)} Secure Coding Guide items into vector store.")
