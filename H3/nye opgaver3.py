import requests

try:

    response = requests.get('https://httpbin.org/get', params= {'Dit navn : Tobias' : 'Din alder : 20'})
    print("Response headers:")
    print(response.headers)

    print("-"*20)

    print("Response text:")
    print(response.text)

except requests.RequestException as error:

    print("Get request failed:", error)
    