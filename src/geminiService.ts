import { GoogleGenAI } from "@google/genai";

export async function askGeminiAssistant(prompt: string, packetContext: string, systemRule: string): Promise<string> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error("GEMINI_API_KEY environment variable is not configured.");
  }

  const ai = new GoogleGenAI({
    apiKey: apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build'
      }
    }
  });

  const fullPrompt = `
  Packet / Traffic Session State context:
  ${packetContext}

  User Inquiry:
  ${prompt}
  `;

  try {
    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: fullPrompt,
      config: {
        systemInstruction: systemRule,
        temperature: 0.7,
      }
    });

    return response.text || "No insights could be formulated by the AI model at this moment.";
  } catch (error: any) {
    console.error("Gemini API call failed:", error);
    return `Analysis unavailable due to: ${error.message || error}`;
  }
}
