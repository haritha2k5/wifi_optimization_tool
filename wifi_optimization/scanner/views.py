from django.shortcuts import render
import subprocess
import speedtest
import os
import socket
import uuid
import re
import logging
from scapy.all import ARP, Ether, srp, sr, conf  # Single import statement

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def suggest_best_channel(request):
    try:
        # Use netsh on Windows to scan WiFi networks
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=Bssid"],
            capture_output=True, text=True, shell=True
        )
        output = result.stdout

        # Log the raw output for debugging
        logger.debug("Raw netsh output in suggest_best_channel:\n%s", output)

        # Check if no networks are detected
        if "There are 0 networks currently visible" in output:
            logger.debug("No networks detected by netsh.")
            best_channel = "No networks detected"
        else:
            # Parse the output to find channel usage
            channels = {}
            channel_pattern = re.compile(r"Channel\s*:\s*(\d+)", re.IGNORECASE)

            for line in output.splitlines():
                channel_match = channel_pattern.search(line)
                if channel_match:
                    channel = channel_match.group(1)
                    channels[channel] = channels.get(channel, 0) + 1

            # Suggest the least-used channel among 1, 6, 11 (2.4 GHz)
            common_channels = ['1', '6', '11']
            best_channel = min(
                [(ch, channels.get(ch, 0)) for ch in common_channels],
                key=lambda x: x[1], default=('1', 0)
            )[0] if channels else "No Data"

    except Exception as e:
        best_channel = f"Error: {str(e)}"

    return render(request, 'scanner/best_channel.html', {"best_channel": best_channel})

def get_network_info(request):
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2*6, 8)][::-1])
        network_info = {
            "hostname": hostname,
            "ip_address": ip_address,
            "mac_address": mac_address,
        }
    except Exception as e:
        network_info = {"error": str(e)}

    return render(request, 'scanner/network_info.html', {"network_info": network_info})

def ping_test(request):
    try:
        # Use Windows ping command (no -c option, use -n instead)
        response = subprocess.run(["ping", "-n", "4", "8.8.8.8"], capture_output=True, text=True)
        output = response.stdout
    except Exception as e:
        output = f"Error: {str(e)}"
    
    return render(request, 'scanner/ping_test.html', {'ping_output': output})

def scan_wifi(request):
    try:
        # Use netsh on Windows to scan WiFi networks
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=Bssid"],
            capture_output=True, text=True, shell=True
        )
        output = result.stdout

        # Log the raw output for debugging
        logger.debug("Raw netsh output in scan_wifi:\n%s", output)

        # Check if no networks are detected
        if "There are 0 networks currently visible" in output:
            logger.debug("No networks detected by netsh.")
            return render(request, 'scanner/signal.html', {'networks': []})

        # Parse the output with regex
        networks = []
        ssid_pattern = re.compile(r"SSID \d+ : (.+?)(?:\r?\n|$)", re.IGNORECASE)
        signal_pattern = re.compile(r"Signal\s*:\s*(\d+)%", re.IGNORECASE)
        channel_pattern = re.compile(r"Channel\s*:\s*(\d+)", re.IGNORECASE)
        security_pattern = re.compile(r"Authentication\s*:\s*(.+?)(?:\r?\n|$)", re.IGNORECASE)

        current_network = {}
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            ssid_match = ssid_pattern.search(line)
            signal_match = signal_pattern.search(line)
            channel_match = channel_pattern.search(line)
            security_match = security_pattern.search(line)

            if ssid_match:
                if current_network:
                    networks.append(current_network)
                current_network = {'ssid': ssid_match.group(1).strip()}
            if signal_match:
                signal_percent = int(signal_match.group(1))
                signal_dbm = -100 + (signal_percent / 2)  # Rough mapping
                current_network['signal_strength'] = signal_dbm
            if channel_match:
                current_network['channel'] = channel_match.group(1)
            if security_match:
                current_network['security'] = security_match.group(1).strip()

        if current_network:
            networks.append(current_network)

        # Sort by signal strength
        networks.sort(key=lambda x: x.get('signal_strength', -100), reverse=True)
        return render(request, 'scanner/signal.html', {'networks': networks})
    except Exception as e:
        logger.error("Error in scan_wifi: %s", str(e))
        h = {"ssid": "Error", "signal_strength": "N/A", "channel": "N/A", "frequency": "N/A", "security": str(e)}
        return render(request, 'scanner/signal.html', {'networks': [h]})

def get_speed_test(request):
    try:
        st = speedtest.Speedtest()
        upload = st.upload() / 1_000_000  # Convert to Mbps
        download = st.download() / 1_000_000  # Convert to Mbps
        speed = {"download": round(download, 2), "upload": round(upload, 2)}
        logger.debug("Speed test successful: %s", speed)
        return render(request, 'scanner/speed.html', {"speed": speed})
    except Exception as e:
        logger.error("Speed test failed: %s", str(e))
        speed = {"download": "N/A", "upload": "N/A", "error": str(e)}
        return render(request, 'scanner/speed.html', {'speed': speed})

def dashboard(request):
    try:
        return render(request, 'scanner/dashboard.html')
    except (BrokenPipeError, ConnectionResetError):
        pass

# def connected_devices(request):
#     try:
#         ip_range = "192.168.1.1/24"  # Adjust to your network
#         arp = ARP(pdst=ip_range)
#         ether = Ether(dst="ff:ff:ff:ff:ff:ff")
#         packet = ether/arp
#         result = srp(packet, timeout=3, verbose=0)[0]
#         devices = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]
#         logger.debug("Connected devices: %s", devices)
#     except Exception as e:
#         logger.error("Error in connected_devices: %s", str(e))
#         devices = [{'ip': 'Error', 'mac': str(e)}]
#     return render(request, 'scanner/devices.html', {'devices': devices})

def connected_devices(request):
    try:
        ip_range = "192.168.1.0/24"  # Matches your network from ipconfig
        logger.debug(f"Starting ARP scan for IP range: {ip_range}")

        # Set the correct interface (replace 'Wi-Fi' with your interface name from conf.ifaces)
        conf.iface = 'Intel(R) Wi-Fi 6 AX201 160MHz' # Adjust this based on your interface name
        logger.debug(f"Using interface: {conf.iface}")

        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        logger.debug("Packet constructed: %s", packet.summary())

        result = srp(packet, timeout=10, verbose=0)  # Increased timeout to 10 seconds
        answered = result[0]  # Extract answered packets
        unanswered = result[1]  # Extract unanswered packets
        logger.debug(f"ARP scan completed. Answered: {len(answered)}, Unanswered: {len(unanswered)}")

        devices = []
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            device_name = "Unknown"  # Default if resolution fails

            # Try NetBIOS name resolution using nbtstat
            try:
                logger.debug(f"Attempting NetBIOS resolution for IP: {ip}")
                nbt_result = subprocess.run(
                    ["nbtstat", "-A", ip],
                    capture_output=True, text=True, timeout=2
                )
                nbt_output = nbt_result.stdout
                name_match = re.search(r"^\s+<00>\s+UNIQUE\s+(.+?)\s+", nbt_output, re.MULTILINE)
                if name_match:
                    device_name = name_match.group(1).strip()
                    logger.debug(f"NetBIOS resolved {ip} to {device_name}")
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, Exception) as e:
                logger.debug(f"NetBIOS resolution failed for {ip}: {str(e)}")

            # Try reverse DNS lookup as a fallback
            if device_name == "Unknown":
                try:
                    logger.debug(f"Attempting DNS resolution for IP: {ip}")
                    device_name = socket.gethostbyaddr(ip)[0]
                    logger.debug(f"DNS resolved {ip} to {device_name}")
                except (socket.herror, socket.gaierror, Exception) as e:
                    logger.debug(f"DNS resolution failed for {ip}: {str(e)}")

            devices.append({'ip': ip, 'mac': mac, 'name': device_name})
            logger.debug(f"Added device: {ip}, {mac}, {device_name}")

        logger.debug("Final device list: %s", devices)
        if not devices:
            logger.warning("No devices found after scan.")
            devices = [{'ip': 'No devices found', 'mac': 'N/A', 'name': 'N/A'}]

    except Exception as e:
        logger.error("Error in connected_devices: %s", str(e))
        devices = [{'ip': 'Error', 'mac': str(e), 'name': 'N/A'}]
    return render(request, 'scanner/devices.html', {'devices': devices})