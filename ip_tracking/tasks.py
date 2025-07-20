from celery import shared_task
from django.utils.timezone import now, timedelta
from ip_tracking.models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ['/admin', '/login']

@shared_task
def detect_suspicious_ips():
    one_hour_ago = now() - timedelta(hours=1)
    logs = RequestLog.objects.filter(timestamp__gte=one_hour_ago)

    ip_counts = {}
    flagged_ips = set()

    for log in logs:
        ip = log.ip_address
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

        if log.path in SENSITIVE_PATHS:
            flagged_ips.add((ip, f"Accessed sensitive path: {log.path}"))

    for ip, count in ip_counts.items():
        if count > 100:
            flagged_ips.add((ip, f"Exceeded 100 requests in 1 hour: {count}"))

    for ip, reason in flagged_ips:
        SuspiciousIP.objects.update_or_create(ip_address=ip, defaults={"reason": reason})
