from backend.knowledge_base.processing.embedder import Embedder
from backend.knowledge_base.vector_store.chroma_client import ChromaClient

class Retriever:
    def __init__(self):
        self.embedder = Embedder()
        self.vector_store = ChromaClient()
        self.collection_name = "security_knowledge"

    def retrieve_context(self, query, n_results=3):
        """
        Retrieves relevant security context for a given query (e.g., a vulnerability name).
        """
        query_embedding = self.embedder.get_embedding(query)
        results = self.vector_store.query_collection(
            collection_name=self.collection_name,
            query_embeddings=[query_embedding],
            n_results=n_results
        )
        
        # Format results into a string for LLM prompt augmentation
        context_list = []
        if results and 'documents' in results and results['documents']:
            for doc in results['documents'][0]:
                context_list.append(doc)
        
        return "\n---\n".join(context_list)
