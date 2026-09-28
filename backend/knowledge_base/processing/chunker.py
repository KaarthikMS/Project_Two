import re

class Chunker:
    def __init__(self, chunk_size=1000, chunk_overlap=100):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def split_text(self, text):
        """
        Splits text into chunks with overlap. 
        Tries to split by paragraphs first, then sentences, then words.
        """
        if not text:
            return []

        # Simple recursive-ish chunking logic
        chunks = []
        start = 0
        
        while start < len(text):
            end = start + self.chunk_size
            
            # If we are not at the end, try to find a nice break point
            if end < len(text):
                # Look for last newline or period within the chunk to avoid cutting sentences
                search_range = text[start:end]
                last_newline = search_range.rfind('\n')
                if last_newline != -1 and last_newline > self.chunk_size * 0.5:
                    end = start + last_newline + 1
                else:
                    last_period = search_range.rfind('.')
                    if last_period != -1 and last_period > self.chunk_size * 0.5:
                        end = start + last_period + 1
            
            chunk = text[start:end].strip()
            if chunk:
                chunks.append(chunk)
            
            start = end - self.chunk_overlap
            
            # Prevent infinite loop if overlap >= size
            if start >= end:
                start = end
                
        return chunks
