from django.db import models

class wiFiNetwork(models.Model):
    ssid=models.CharField(max_length=10)
    signal_strength = models.IntegerField()
    channel = models.CharField(max_length=10)
    frequency = models.CharField(max_length=10)
    security = models.CharField(max_length=50)
    scanned_at = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return self.ssid
class SpeedTestResult(models.Model):
    download_speed = models.FloatField()
    upload_speed = models.FloatField()
    tested_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.download_speed} Mbps / {self.upload_speed} Mbps"
