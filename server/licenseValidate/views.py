from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import hashlib
import os
import binascii
from .models import License

# Load private key
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# Load public key
with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

def xor_encrypt(data, key):
    return bytearray(a ^ b for a, b in zip(data, key))

def get_key(password):
    return hashlib.sha256(password.encode()).digest()

@api_view(['POST'])
def generate_license(request):
    data = request.data
    license_id = data.get('id')

    if not license_id:
        return Response({"error": "ID is required"}, status=status.HTTP_400_BAD_REQUEST)

    message = license_id.encode()
    encrypted_message = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    license_file = f"license_{license_id}.bin"
    with open(license_file, "wb") as file:
        file.write(encrypted_message)
    
    #add to table
    License.objects.create(license_id=license_id, encrypted_message=encrypted_message)

    return Response({"message": "License generated", "license_file": license_file}, status=status.HTTP_200_OK)

@api_view(['POST'])
def validate_license(request):
    data = request.data
    encrypted_hash_hex = data.get('encrypted_hash')
    encrypted_mac = base64.b64decode(data.get('encrypted_mac'))

    try:
        decrypted_mac = private_key.decrypt(
            encrypted_mac,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        password_for_XOR = "mysecretpassword"
        key = get_key(password_for_XOR)
        encrypted_mac_xor = xor_encrypt(decrypted_mac, key[:len(decrypted_mac)])
        encrypted_mac_base64 = base64.b64encode(encrypted_mac_xor).decode('utf-8')

        if not encrypted_hash_hex:
            return Response({"status": "invalid"}, status=status.HTTP_400_BAD_REQUEST)

        encrypted_hash = binascii.unhexlify(encrypted_hash_hex)

        # Decrypt the hash using the private key
        decrypted_hash = private_key.decrypt(
            encrypted_hash,
            padding.PKCS1v15()
        )

        octet_string_value = decrypted_hash[19:]

        license_valid = False
        id = ""


        licenses = License.objects.all()
        for license in licenses:
            line = license.license_id
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(line.encode())
            computed_hash = digest.finalize()

            if computed_hash == octet_string_value:
                id = line
                license_valid = True
                # Increment the usage count and save the license
                license.usage_count += 1
                print(license.usage_count)
                license.save()
                break

        # with open("licenses.txt", "r") as file:
        #     lines = file.readlines()
        
        # for line in lines:
        #     line = line.strip()
        #     digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        #     digest.update(line.encode())
        #     computed_hash = digest.finalize()

        #     if computed_hash == octet_string_value:
        #         id = line
        #         license_valid = True
        #         break

        if license_valid:
            return Response({"status": "valid", "encrypted_mac": encrypted_mac_base64}, status=status.HTTP_200_OK)
        else:
            return Response({"status": "invalid"}, status=status.HTTP_400_BAD_REQUEST)
        
    except Exception as e:
        print(f"Decryption error: {e}")
        return Response({"status": "invalid"}, status=status.HTTP_400_BAD_REQUEST)
