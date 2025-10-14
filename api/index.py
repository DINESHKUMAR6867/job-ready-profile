# Vercel Python Function entrypoint for Django via vercel-wsgi
# Docs: https://github.com/juancarlospaco/vercel-wsgi (community)
import os
from vercel_wsgi import handle


# Ensure Django can find settings
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "profile_scoring.settings")

try:
    # Prefer ASGI if present, else WSGI
    django_app = None
    try:
        if "profile_scoring.asgi":
            from profile_scoring.asgi import application as django_asgi_app  # type: ignore
            # vercel-wsgi handles WSGI; for ASGI we can fallback to daphne-like wrapper if needed.
            # To keep it simple, we import WSGI below if available.
    except Exception:
        pass
    if "profile_scoring.wsgi":
        from profile_scoring.wsgi import application as django_wsgi_app  # type: ignore
        django_app = django_wsgi_app
    assert django_app is not None, "Could not import Django application. Check wsgi.py and settings."
except Exception as e:
    # Fail fast with a clear error for Vercel logs
    def handler(event, context):
        return {"statusCode": 500, "headers": {}, "body": f"Import error: {e}"}
else:
    def handler(event, context):
        # Delegate to vercel-wsgi adapter
        return handle(event, context, django_app)
