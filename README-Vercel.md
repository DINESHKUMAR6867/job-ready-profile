# Deploying this Django app to Vercel

## What we added
- `api/index.py`: Python serverless function that wraps Django via **vercel-wsgi**.
- `vercel.json`: Vercel config to route **all requests** to `api/index.py` and serve `/static/*` directly.
- Updated/created `requirements.txt` with:
  - `Django`
  - `vercel-wsgi`
  - `whitenoise` (for static files)
  - `psycopg2-binary` (if you use Postgres)

## Before deploying
1. Make sure your settings enable static files for production, e.g. in your Django `settings.py`:

```python
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

# Optional but recommended for serverless:
MIDDLEWARE = [
    "whitenoise.middleware.WhiteNoiseMiddleware",
    # ... the rest
]

# Enable compressed manifest storage (optional)
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"
```

2. Collect static locally and commit:
```bash
python manage.py collectstatic --noinput
```

3. Configure environment variables on Vercel:
   - `DJANGO_SETTINGS_MODULE=profile_scoring.settings`
   - `SECRET_KEY=...`
   - `DEBUG=false`
   - Database vars (if any): `DATABASE_URL` or individual settings

## Deploy
```bash
vercel
# or
vercel --prod
```

## Notes
- Long-lived DB connections and migrations are better handled on a traditional host (Render/Fly/Heroku).
- For small/mid projects and APIs, Vercel serverless works well.
