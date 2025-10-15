import os
from django.core.wsgi import get_wsgi_application

# ✅ Must set the Django settings module before anything else
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "profile_scoring.settings")

app = get_wsgi_application()
