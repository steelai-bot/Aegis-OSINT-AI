# Aegis-OSINT-AI Installation Guide

## Automated Installation (Kali Linux / Debian / Ubuntu)

The main installer script automates dependency setup, virtual environments, PostgreSQL, Redis, and more.
It is primarily designed for Kali Linux, but you can bypass the strict OS check if you are on another Debian-based system.

### Option 1: Kali Linux

```bash
sudo python3 install.py
```

### Option 2: Generic Debian/Ubuntu (Skip Kali check)

```bash
sudo python3 install.py --skip-kali-check
```

*Note: You may be prompted to run as `root` for system package installation (`apt`).*

---

## Manual Installation

If you prefer to install things manually, follow these steps:

### 1. System Dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip \
    postgresql postgresql-contrib pgvector redis-server \
    git tesseract-ocr holehe nodejs npm build-essential cmake
```

### 2. Services (PostgreSQL & Redis)

Ensure they are running and start them on boot:

```bash
sudo systemctl enable --now postgresql redis-server
```

Setup the database and vector extension:

```bash
sudo su - postgres -c 'psql -c "CREATE DATABASE aegis;"'
sudo su - postgres -c 'psql -d aegis -c "CREATE EXTENSION IF NOT EXISTS vector;"'
```

### 3. Backend Setup

Create a virtual environment and install packages:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -r backend/requirements.txt
```

### 4. Frontend Setup

```bash
cd frontend
npm install
cd ..
```

### 5. Environment Variables

Create a `.env` file in the root of the project:

```bash
cp .env.example .env
```

*(If `.env.example` doesn't exist, the installer provides a template you can paste).*

---

## Running the Application

### Backend (FastAPI)

Run the backend in your virtual environment:

```bash
source .venv/bin/activate
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

Check health: [http://localhost:8000/health](http://localhost:8000/health)

### Frontend (Next.js)

In a new terminal window:

```bash
cd frontend
npm run dev
```

Open your browser to: [http://localhost:3000](http://localhost:3000)

---

## Troubleshooting

- **Database Errors**: Ensure PostgreSQL is running (`systemctl status postgresql`) and the `aegis` database exists.
- **pgvector Missing**: If `CREATE EXTENSION vector` fails, you might need to build `pgvector` from source or install `postgresql-<version>-pgvector` manually.
- **Port Conflicts**: Ensure ports `8000` (Backend) and `3000` (Frontend) are not being used by other services.
- **Node/NPM Version**: Aegis' frontend works best with modern Node versions (v18+). If your `apt` provides an older one, consider using `nvm` or the NodeSource repository.
