from django.utils.timezone import now
from django.core.cache import cache
from ip_tracking.models import RequestLog, BlockedIP
from django.http import HttpResponseForbidden
import requests

class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)

        # Block blacklisted IPs
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Access denied: IP is blacklisted.")

        # Check cache for geolocation
        geo_key = f"geo:{ip}"
        geo_data = cache.get(geo_key)

        if not geo_data:
            geo_data = self.get_geolocation(ip)
            cache.set(geo_key, geo_data, timeout=86400)  # Cache for 24 hours

        # Log request with geolocation
        RequestLog.objects.create(
            ip_address=ip,
            timestamp=now(),
            path=request.path,
            country=geo_data.get("country"),
            city=geo_data.get("city")
        )

        return self.get_response(request)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        return x_forwarded_for.split(",")[0] if x_forwarded_for else request.META.get("REMOTE_ADDR")

    def get_geolocation(self, ip):
        try:
            response = requests.get(f"https://ipgeolocationapi.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    "country": data.get("country", {}).get("name", ""),
                    "city": data.get("city", "")
                }
        except Exception as e:
            pass
        return {"country": "", "city": ""}
