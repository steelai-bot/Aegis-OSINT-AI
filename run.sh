#!/bin/bash
# Aegis OSINT AI - Linux Run Script
# Starts the backend server and opens the browser

echo ""
echo "========================================"
echo "  Aegis OSINT AI - Starting (Linux)"
echo "========================================"
echo ""

# Check if .venv exists
if [ ! -d ".venv" ]; then
    echo "ERROR: Virtual environment not found."
    echo "Please run ./setup.sh first."
    exit 1
fi

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "WARNING: .env not found. Using default configuration."
fi

# Start backend server in the background
echo ""
echo "[1/2] Starting backend server..."
# We use nohup and redirect output to a log file so it doesn't block the terminal
nohup ./.venv/bin/python -m backend.main > server.log 2>&1 &
SERVER_PID=$!

# Wait for server to start
echo "[2/2] Waiting for server to be ready..."
sleep 3

# Check if server is running
while true; do
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        echo "      Server is running!"
        break
    fi
    
    # Check if the process is still alive
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo "ERROR: Backend server failed to start. Check server.log for details."
        exit 1
    fi
    
    echo "      Waiting for server..."
    sleep 2
done

# Open browser
echo ""
echo "Opening browser..."
if command -v xdg-open > /dev/null; then
    xdg-open http://localhost:8000
elif command -v open > /dev/null; then
    open http://localhost:8000
else
    echo "Could not open browser automatically. Please visit: http://localhost:8000"
fi

echo ""
echo "========================================"
echo "  Aegis OSINT AI is running!"
echo "========================================"
echo ""
echo "Backend: http://localhost:8000"
echo "API Docs: http://localhost:8000/docs"
echo ""
echo "Log file: server.log"
echo "Press Ctrl+C to stop the server (or run: kill $SERVER_PID)"
echo ""

# Keep the script running to maintain the process and allow Ctrl+C to kill it
trap "kill $SERVER_PID; echo -e '\nServer stopped.'; exit" SIGINT SIGTERM
wait $SERVER_PID