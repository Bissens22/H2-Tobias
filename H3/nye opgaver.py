import requests

try:

    response = requests.get('https://httpbin.org/get')

    print("HTTP GET request successful. Status Code:", response.status_code)
    print("\nresponse headers:\n", response.headers)
    print("\nresponse body:\n", response.text)

except requests.RequestException as e:
    print("HTTP GET request failed:", e)