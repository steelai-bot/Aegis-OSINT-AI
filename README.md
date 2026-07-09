# Aegis OSINT AI

A lightweight, modular, and extensible OSINT (Open Source Intelligence) investigation framework designed for rapid intelligence gathering and entity relationship mapping.

## 🚀 Key Features

- **Modular Plugin Architecture**: Easily add new intelligence sources by implementing the `BasePlugin` interface.
- **Entity Graph Backend**: Automatically extracts and maps relationships between discovered entities (domains, emails, IPs, etc.) using a SQLite-based relational graph.
- **Automatic Investigation Timeline**: Every step of the investigation is logged, providing a clear audit trail of discovery.
- **Professional Reporting**: Generate structured reports in Markdown, JSON, and HTML formats.
- **AI-Powered Planning**: Uses LLMs to dynamically determine the most effective sequence of plugins for any given target.
- **Centralized Management**: Manage all API keys and configuration through a unified web interface.

## 🛠️ Tech Stack

- **Backend**: FastAPI (Python)
- **Database**: SQLite (Relational Graph Implementation)
- **Frontend**: Vanilla JavaScript, HTML5, CSS3 (SPA Architecture)
- **AI Integration**: Support for OpenRouter, OpenAI, Anthropic, Gemini, and Nvidia.

## 📂 Project Structure

```text
.
├── backend/
│   ├── engine.py          # Orchestration logic
│   ├── main.py            # FastAPI application & endpoints
│   ├── models.py          # Pydantic data models
│   ├── planner.py         # AI-driven investigation planning
│   ├── plugin_manager.py  # Plugin discovery and execution
│   ├── report.py          # Modular report generation
│   ├── storage.py         # Database abstraction layer
│   └── plugins/           # OSINT plugin implementations
├── config/
│   └── .env.example       # API key templates
├── data/                  # SQLite database storage
├── frontend/
│   ├── app.js             # Frontend logic
│   ├── index.html         # Main application shell
│   └── style.css          # Application styling
├── reports/               # Generated report storage
└── requirements.txt       # Python dependencies
```

## ⚙️ Setup & Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/steelai-bot/Aegis-OSINT-AI.git
   cd Aegis-OSINT-AI
   ```

2. **Set up a virtual environment**:
   ```bash
   python -m venv .venv
   # Windows
   .venv\Scripts\activate
   # Linux/macOS
   source .venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure API Keys**:
   Copy the example configuration to a `.env` file and add your keys:
   ```bash
   cp config/.env.example .env
   ```

5. **Run the application**:
   ```bash
   python -m backend.main
   ```
   The application will be available at `http://localhost:8000`.

## 🧩 Developing Plugins

To add a new plugin, create a new file in `backend/plugins/` that inherits from `BasePlugin`.

```python
from backend.plugins.base import BasePlugin
from backend.models import PluginMetadata, PluginResponse, TargetType

class MyNewPlugin(BasePlugin):
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="my_plugin",
            description="Does something cool",
            supported_entity_types=[TargetType.DOMAIN],
            tags=["new"]
        )

    async def execute(self, query: str, target_type: TargetType) -> List[PluginResponse]:
        # Your logic here
        return []
```

## 📄 License

This project is licensed under the MIT License.