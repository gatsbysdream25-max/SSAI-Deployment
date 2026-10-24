import requests
import json
import os

OLLAMA_URL = os.environ.get('OLLAMA_URL', 'http://localhost:11434')
MODEL = os.environ.get('OLLAMA_MODEL', 'llama3')


def analyze(prompt: str) -> str:
    response = requests.post(
        f'{OLLAMA_URL}/api/generate',
        json={'model': MODEL, 'prompt': prompt, 'stream': False},
        timeout=120,
    )
    response.raise_for_status()
    return response.json().get('response', '')


def analyze_threat(threat_data: dict) -> str:
    prompt = (
        'You are a cybersecurity analyst. Analyze the following threat data and provide '
        'a brief assessment of severity, likely attack type, and recommended action:\n\n'
        + json.dumps(threat_data, indent=2)
    )
    return analyze(prompt)


def test_connection() -> bool:
    try:
        r = requests.get(f'{OLLAMA_URL}/api/tags', timeout=10)
        return r.status_code == 200
    except requests.RequestException:
        return False


if __name__ == '__main__':
    if test_connection():
        print('Ollama connected at', OLLAMA_URL)
        result = analyze('Say exactly: Ollama is working')
        print('Response:', result)
    else:
        print('Cannot reach Ollama at', OLLAMA_URL)
