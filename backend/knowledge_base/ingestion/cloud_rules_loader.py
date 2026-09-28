import json
import uuid
from backend.knowledge_base.processing.chunker import Chunker
from backend.knowledge_base.processing.embedder import Embedder
from backend.knowledge_base.vector_store.chroma_client import ChromaClient

class CloudRulesLoader:
    def __init__(self):
        self.chunker = Chunker(chunk_size=1000, chunk_overlap=100)
        self.embedder = Embedder()
        self.vector_store = ChromaClient()
        self.collection_name = "security_knowledge"

    def load_rules(self, rules_list):
        """
        Ingests cloud misconfiguration rules.
        Expected format: [{"provider": "AWS", "service": "IAM", "title": "...", "remediation": "..."}]
        """
        for rule in rules_list:
            text = f"Provider: {rule['provider']}\nService: {rule['service']}\nTitle: {rule['title']}\nRemediation: {rule['remediation']}"
            chunks = self.chunker.split_text(text)
            
            for chunk in chunks:
                embedding = self.embedder.get_embedding(chunk)
                doc_id = str(uuid.uuid4())
                
                self.vector_store.add_documents(
                    collection_name=self.collection_name,
                    documents=[chunk],
                    embeddings=[embedding],
                    metadatas=[{"source": "CloudRules", "provider": rule['provider'], "service": rule['service']}],
                    ids=[doc_id]
                )
        print(f"Loaded {len(rules_list)} Cloud Rule items into vector store.")
