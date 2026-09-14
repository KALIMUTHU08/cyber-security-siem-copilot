"""
Main entrypoint for running the controlled dummy target application.
Binds STRICTLY to localhost (127.0.0.1).
"""

import uvicorn
from config import DUMMY_APP_HOST, DUMMY_APP_PORT

if __name__ == "__main__":
    print("=" * 65)
    print(f"  Controlled SIEM Demo Target App")
    print(f"  Running safely on http://{DUMMY_APP_HOST}:{DUMMY_APP_PORT}")
    print(f"  SIEM Ingestion Target: http://127.0.0.1:8000/api/logs/upload")
    print("=" * 65)
    uvicorn.run(
        "app:app",
        host=DUMMY_APP_HOST,  # Strictly 127.0.0.1
        port=DUMMY_APP_PORT,
        reload=False,
    )
