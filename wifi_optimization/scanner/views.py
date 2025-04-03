from django.shortcuts import render
import subprocess
import re
import speedtest
import logging
# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
def scan_wifi(request):
    try:
        # Use netsh on Windows to scan WiFi networks
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=Bssid"],
            capture_output=True, text=True, shell=True
        )
        output = result.stdout

        # Log the raw output for debugging
        logger.debug("Raw netsh output:\n%s", output)

        # If no networks are found, netsh might say "There are 0 networks currently visible"
        if "There are 0 networks currently visible" in output:
            logger.debug("No networks detected by netsh.")
            return render(request, 'scanner/signal.html', {'networks': []})

        # Parse the output with more flexible regex
        networks = []
        ssid_pattern = re.compile(r"SSID \d+ : (.+?)(?:\r?\n|$)")
        signal_pattern = re.compile(r"Signal\s*:\s*(\d+)%")
        channel_pattern = re.compile(r"Channel\s*:\s*(\d+)")
        security_pattern = re.compile(r"Authentication\s*:\s*(.+?)(?:\r?\n|$)")

        current_network = {}
        for line in output.splitlines():
            line = line.strip()  # Remove leading/trailing whitespace
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

        # Log the parsed networks
        logger.debug("Parsed networks: %s", networks)

        # Sort by signal strength
        networks.sort(key=lambda x: x.get('signal_strength', -100), reverse=True)

        # Channel interference recommendation
        channel_usage = {}
        for net in networks:
            ch = net.get('channel')
            if ch:
                channel_usage[ch] = channel_usage.get(ch, 0) + 1
        common_channels = ['1', '6', '11']
        channel_recommendation = min(
            [(ch, channel_usage.get(ch, 0)) for ch in common_channels if ch in channel_usage],
            key=lambda x: x[1], default=('1', 0)
        )[0]

        return render(request, 'scanner/signal.html', {
            'networks': networks,
            'recommended_channel': channel_recommendation
        })
    except Exception as e:
        logger.error("Error in scan_wifi: %s", str(e))
        h = {"ssid": "Error", "signal_strength": "N/A", "channel": "N/A", "security": str(e)}
        return render(request, 'scanner/signal.html', {'networks': [h]})
def get_speed_test(request):
    try:
        st = speedtest.Speedtest()
        upload = st.upload() / 1_000_000  # Convert to Mbps
        download = st.download() / 1_000_000  # Convert to Mbps
        speed = {"download": round(download, 2), "upload": round(upload, 2)}
        return render(request, 'scanner/speed.html', {"speed": speed})
    except Exception as e:
        speed = {"download": "N/A", "upload": "N/A", "error": str(e)}
        return render(request, 'scanner/speed.html', {'speed': speed})

def dashboard(request):
    return render(request, 'scanner/dashboard.html')