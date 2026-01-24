import os
import json
from google import genai
from google.genai import types
from ...schemas import AiFlatResponse


class GeminiClient:
    def __init__(self):
        self.client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))

    async def generate_analysis(self, prompt_text: str):
        # Wysyłamy prompt wygenerowany przez build_analysis_prompt
        response = self.client.models.generate_content(
            model='gemini-2.0-flash', 
            contents=prompt_text,
            config=types.GenerateContentConfig(
                response_mime_type='application/json',
                response_schema=AiFlatResponse
            )
        )
        return json.loads(response.text)