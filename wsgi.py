import sys
import os

# Add your project directory to the path
path = os.path.dirname(__file__)
if path not in sys.path:
    sys.path.append(path)

from app import create_app

application = create_app()