import requests

try:

    response = requests.get('https://httpbin.org/headers')

    print ('http get response.headers:', response.headers)

except requests.RequestException as e:
    print("HTTP GET request failed:", e)