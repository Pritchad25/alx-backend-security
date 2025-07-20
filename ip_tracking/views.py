from django.http import JsonResponse
from ratelimit.decorators import ratelimit

@ratelimit(key='user_or_ip', rate='10/m', method='POST', block=True)
@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def login_view(request):
    if getattr(request, 'limited', False):
        return JsonResponse({"error": "Too many requests"}, status=429)

    # Simulated login logic
    return JsonResponse({"message": "Login successful"})
