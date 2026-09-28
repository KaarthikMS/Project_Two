import json
import boto3

class Embedder:
    def __init__(self, region_name="us-east-1"):
        self.client = boto3.client("bedrock-runtime", region_name=region_name)
        self.model_id = "amazon.titan-embed-text-v2:0"

    def get_embedding(self, text):
        """
        Generate embedding for the given text using Amazon Titan V2.
        """
        body = json.dumps({
            "inputText": text,
            "dimensions": 1024,
            "normalize": True
        })

        response = self.client.invoke_model(
            modelId=self.model_id,
            body=body
        )

        response_body = json.loads(response.get("body").read())
        return response_body.get("embedding")
