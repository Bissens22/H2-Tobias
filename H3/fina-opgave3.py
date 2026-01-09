import requests

server_ip = 'http://20.91.198.208:8081/submit?'

token_value = "adb2fb97"

try:

    response = requests.get(server_ip, params={'token': token_value, 'ansvar' : '1008'}) 
    print("Response headers:")
    print(response.headers)

    print("-"*20)

    print("Response text:")
    print(response.text)

except requests.RequestException as error:

    print("Get request failed:", error)