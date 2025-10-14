#!/bin/bash
echo "Installing Python dependencies..."
pip install -r requirements.txt
echo "Running collectstatic..."
python manage.py collectstatic --noinput
echo "Creating public directory for Vercel..."
mkdir -p public
cp -r staticfiles/* public/ 2>/dev/null || echo "No static files to copy"
echo "Build completed!"
