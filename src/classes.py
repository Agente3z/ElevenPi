class AccessPoint:
    ssid: str
    bssid: str
    channel: int

    def __init__(self, ssid: str, bssid: str, channel: int):
        self.ssid = ssid
        self.bssid = bssid
        self.channel = channel

    def __str__(self):
        return f"SSID: {self.ssid}, BSSID: {self.bssid}, Channel: {self.channel}"
    
    def __repr__(self):
        return self.bssid

    def __eq__(self, other) -> bool:
        if isinstance(other, AccessPoint):
            return self.bssid == other.bssid
        return False