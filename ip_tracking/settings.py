INSTALLED_APPS = [
    ...
    'ratelimit',
]


MIDDLEWARE = [
    ...
    'ip_tracking.middleware.IPTrackingMiddleware',
]
