import requests
from cryptography.fernet import Fernet
from urllib.parse import urljoin

base_url = 'http://20.91.198.208:8081/"

token = "21cde145"

def fetch_encrypted_payload(token):
     response = requests.get(base_url, params={'token': token})
     key = response.headers["x.secret.key"].encode()
     return response.content, key
    
def decrypt_payload(data, key):
    cipher = Fernet(key)
    return cipher.decrypt(data)

def calculate_answer (encrypted_data):
    return len(encrypted_data) * 2

def submit_answer(answer):
    submit_url = urljoin(base_url, 'submit')
    response = requests.get(submit_url, params={'token': token, 'ansvar': str(answer)})
    return response

def main():
    encrypted, key = fetch_encrypted_payload(token)
    message = decrypt_payload(encrypted, key)
    answer = calculate_answer(encrypted)
    result = submit_answer(answer)

    print (message.decode())
    print("Submission Response:", result)

if __name__ == "__main__":
    main()