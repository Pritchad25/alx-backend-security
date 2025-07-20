from django.http import HttpResponseForbidden
from ip_tracking.models import BlockedIP, RequestLog
from django.utils.timezone import now

class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)

        # Block if IP is blacklisted
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Access denied: IP is blacklisted.")

        # Log request
        RequestLog.objects.create(ip_address=ip, timestamp=now(), path=request.path)

        return self.get_response(request)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        return x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')
