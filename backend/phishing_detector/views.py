import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from ml_model.predict import detect_phishing
from django.http import HttpResponse

def home(request):
    return HttpResponse("<h1>Welcome to the PhishGuard API!</h1>")

@csrf_exempt
def check_email_phishing(request):
    if request.method == 'POST':
        try:
            # Parse the incoming JSON data
            data = json.loads(request.body)
            email_text = data.get('email_text', '')
            
            # Validate email_text field
            if not email_text:
                return JsonResponse({'error': 'email_text is required'}, status=400)

            # Log the received email text
            print("Received email text:", email_text)

            # Detect phishing
            is_phishing = detect_phishing(email_text)

            # Log the result
            print("Prediction:", is_phishing)

            # Return the result as JSON
            return JsonResponse({'is_phishing': is_phishing})

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)

    return JsonResponse({'error': 'POST method required'}, status=405)