#!/bin/bash
echo "Installing Python dependencies..."
pip install -r requirements.txt
echo "Running collectstatic..."
python manage.py collectstatic --noinput
echo "Build completed!"
