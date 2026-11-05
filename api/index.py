"""Vercel Serverless Function entry point."""

from app.main import app

# Export ASGI app for Vercel
app = app
