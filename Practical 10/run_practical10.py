"""
Practical 10 - SentinelSOC Platform Launcher
============================================
Launches the FastAPI ML Backend and Next.js SOC Frontend.

Architecture:
  - Backend: FastAPI, scikit-learn models (P5 Isolation Forest + P9 Champion Multi-Class Classifier), SQLite DB
    URL: http://127.0.0.1:8000
    Docs: http://127.0.0.1:8000/docs
  - Frontend: Next.js 16 + Tailwind CSS + Lucide (Zero emojis, minimalist SOC dashboard)
    URL: http://localhost:3000
"""

import sys
import os
import subprocess
import time
import argparse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

def run_backend(port=8000):
    print(f"[*] Starting SentinelSOC FastAPI ML Backend on http://127.0.0.1:{port}...")
    backend_cmd = [
        sys.executable, "-m", "uvicorn",
        "backend.main:app",
        "--host", "127.0.0.1",
        "--port", str(port),
        "--reload"
    ]
    return subprocess.Popen(backend_cmd, cwd=str(BASE_DIR))

def run_frontend(port=3000):
    frontend_dir = BASE_DIR / "frontend"
    print(f"[*] Starting SentinelSOC Next.js Frontend on http://localhost:{port}...")
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    frontend_cmd = [npm_cmd, "run", "dev"]
    return subprocess.Popen(frontend_cmd, cwd=str(frontend_dir))

def main():
    parser = argparse.ArgumentParser(description="SentinelSOC Threat Platform Launcher")
    parser.add_argument("--backend-only", action="store_true", help="Launch only the FastAPI backend")
    parser.add_argument("--frontend-only", action="store_true", help="Launch only the Next.js frontend")
    parser.add_argument("--backend-port", type=int, default=8000, help="Backend port (default: 8000)")
    parser.add_argument("--frontend-port", type=int, default=3000, help="Frontend port (default: 3000)")
    args = parser.parse_args()

    processes = []
    try:
        if not args.frontend_only:
            proc_back = run_backend(args.backend_port)
            processes.append(proc_back)
            time.sleep(1.5)

        if not args.backend_only:
            proc_front = run_frontend(args.frontend_port)
            processes.append(proc_front)

        print("\n" + "=" * 65)
        print("  SENTINELSOC PLATFORM IS LIVE")
        print(f"  - Web UI:      http://localhost:{args.frontend_port}")
        print(f"  - API Server:  http://127.0.0.1:{args.backend_port}")
        print(f"  - API Docs:    http://127.0.0.1:{args.backend_port}/docs")
        print("  Press Ctrl+C to terminate all services.")
        print("=" * 65 + "\n")

        # Keep alive
        for proc in processes:
            proc.wait()

    except KeyboardInterrupt:
        print("\n[*] Shutting down SentinelSOC services...")
        for proc in processes:
            proc.terminate()
        sys.exit(0)

if __name__ == "__main__":
    main()
