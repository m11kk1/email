import os
import threading
import wifi
import pygatt
import socket
import urllib.request
import asyncio
import requests
from bleak import BleakScanner
import json

def print_public_ip():
    try:
        # Method 1: Use api.ipify.org
        response = urllib.request.urlopen("https://api.ipify.org?format=json")
        data = response.read().decode("utf-8")
        ip_address = json.loads(data)["ip"]
        print("Public IP Address:", ip_address)
        return ip_address
    except (urllib.error.URLError, KeyError):
        pass
    
    try:
        # Method 2: Use checkip.dyndns.org
        response = urllib.request.urlopen("http://checkip.dyndns.org")
        html = response.read().decode("utf-8")
        ip_address = html.split(": ")[-1].split("</body>")[0]
        print("Public IP Address:", ip_address)
        return ip_address
    except (urllib.error.URLError, IndexError):
        pass
    
    print("Failed to fetch the public IP address.")
    return None

def print_ip():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    print("IP Address:", ip_address)
    return ip_address

def print_nearby_networks():
    networks = wifi.scan()
    print("Nearby Networks:")
    for network in networks:
        print("  SSID:", network.ssid)
        print("  BSSID:", network.bssid)
        print("  Signal Strength:", network.signal)
        print("  Frequency:", network.frequency)
        print("")

async def print_nearby_bluetooths():
    scanner = BleakScanner()

    devices = await scanner.discover()

    print("Nearby Bluetooth Devices:")
    for device in devices:
        mac_address = device.address
        try:
            response = urllib.request.urlopen(f"https://api.macvendors.com/{mac_address}")
            vendor = response.read().decode("utf-8").strip()
        except urllib.error.URLError:
            vendor = "Unknown Vendor"
        ip_address = print_public_ip()
        if ip_address:
            print(f"Device: {device.name}, Vendor: {vendor}, MAC: {mac_address}, IP: {ip_address}")
        else:
            print(f"Device: {device.name}, Vendor: {vendor}, MAC: {mac_address}")

def send_email(email, ip_address):
    # Implement your email sending logic here
    print(f"Sending email to: {email}")
    print(f"IP Address: {ip_address}")
    # Add your email sending code

def download_file(url, destination):
    try:
        response = requests.get(url, stream=True)
        with open(destination, 'wb') as file:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    file.write(chunk)
        print("File downloaded successfully.")
    except requests.RequestException:
        print("Failed to download file.")

def background_thread():
    while True:
        user_input = input("Enter a command (ip, networks, bluetooth, email, download, or exit): ")
        if user_input == "ip":
            print_ip()
        elif user_input == "networks":
            print_nearby_networks()
        elif user_input == "bluetooth":
            asyncio.run(print_nearby_bluetooths())
        elif user_input == "email":
            email = input("Enter an email address: ")
            ip_address = print_public_ip()
            if ip_address:
                threading.Thread(target=send_email, args=(email, ip_address)).start()
        elif user_input == "download":
            url = input("Enter the URL of the file to download: ")
            destination = input("Enter the destination path to save the file: ")
            threading.Thread(target=download_file, args=(url, destination)).start()
        elif user_input == "exit":
            break
        else:
            print("Invalid command.")

def main():
    threading.Thread(target=background_thread, daemon=True).start()

    while True:
        pass

if __name__ == "__main__":
    main()
