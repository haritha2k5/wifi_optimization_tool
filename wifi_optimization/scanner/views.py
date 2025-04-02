from django.shortcuts import render
import subprocess
import speedtest

def scan_wifi(request):
    try:
        result = subprocess.run(
            ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"],
            capture_output=True, text=True
        )
        lines = result.stdout.strip().split("\n")[1:]
        networks = []

        for line in lines:
            parts = line.split()
            if len(parts) < 5:
                continue

            ssid = " ".join(parts[:-5])
            signal_strength = int(parts[-5])
            channel = parts[-4]
            frequency = parts[-3]
            security = parts[-1]

            networks.append({
                'ssid': ssid,
                'signal_strength': signal_strength,
                'channel': channel,
                'frequency': frequency,
                'security': security
            })

        networks.sort(key=lambda x: x['signal_strength'], reverse=True)
        return render(request,'scanner/signal.html',{'networks':networks})
    except Exception as e:
        h={"ssid": "Error", "signal_strength": "N/A", "channel": "N/A", "frequency": "N/A", "security": str(e)}
        return render(request,'scanner/signal.html',{'networks':h})
    
def get_speed_test(request):
    try:
        st=speedtest.Speedtest()
        upload=st.upload()
        download=st.download()
        speed={"download":download,"upload":upload}
        return render(request,'scanner/speed.html',{"speed":speed})
    except Exception as e:
        speed={"download":"N/A","upload":"N/A","error":str(e)}
        return render(request,'scanner/speed.html',{'speed':speed})
def dashboard(request):
    
    try:
        return render(request,'scanner/dashboard.html')
    except (BrokenPipeError, ConnectionResetError):
        pass  