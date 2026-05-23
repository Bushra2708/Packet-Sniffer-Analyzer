import requests

# Cache for IP lookups to avoid rate limiting and blockages
_location_cache = {}

def get_ip_location(ip):
    # Check cache first to avoid hitting external API repeatedly
    if ip in _location_cache:
        return _location_cache[ip]

    try:
        # Add a strict timeout to prevent the sniffer thread from hanging
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=0.8
        )

        data = response.json()

        if data["status"] == "success":
            result = {
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown")
            }
            # Cache the successful result
            _location_cache[ip] = result
            return result

    except Exception as e:
        print("GeoIP error:", e)

    # Don't cache failures permanently, but return placeholder
    return {
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown"
    }