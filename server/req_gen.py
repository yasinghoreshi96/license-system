import requests

# The URL for the license generation endpoint
url = "http://127.0.0.1:8000/api/generate_license/"

# Data to send in the POST request
data = {
    "id": "17333"  # Replace with the actual license ID you want to generate
}

try:
    # Send the POST request to generate a license
    response = requests.post(url, json=data)

    # Check if the request was successful
    if response.status_code == 200:
        print("License generated successfully!")
        print("Response data:", response.json())
    else:
        print(f"Failed to generate license. Status code: {response.status_code}")
        print("Error message:", response.json())

except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
