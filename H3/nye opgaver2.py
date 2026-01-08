import requests

try:
    #Sends a "get" request to the website
    response = requests.get('https://httpbin.org/headers')
    #print response headers to terminal
    print("Response headers:")
    print(response.headers)

    print("-"*20)

    #Print response text to terminal
    print("Response text:")
    print(response.text)

#Catch errors and prints a error message to terminal
except requests.RequestException as error:

    print("Get request failed:", error)