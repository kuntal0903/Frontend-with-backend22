import os
import sys

# Ensure Backend directory is in Python path for Vercel Serverless Function
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "Backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app import app  # noqa: E402, F401
