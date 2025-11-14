#!/bin/bash

# Start gunicorn server
poetry run gunicorn --workers 1 --bind 0.0.0.0:5000 app:app
