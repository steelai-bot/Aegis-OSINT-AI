"""
ai_modules.py — AU-OSINT-RECON
HuggingFace AI integration with hardware auto-detection.
Recommends uncensored models based on available RAM/CPU.
Runs fully local — no data leaves the machine.
"""

import os
import sys
import json
import platform
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

try:
    import cpuinfo
    CPUINFO_OK = True
except ImportError:
    CPUINFO_OK = False

try:
    import GPUtil
    GPUTIL_OK = True
except ImportError:
    GPUTIL_OK = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, IntPrompt
    from rich.text import Text
    from rich import box
    RICH_OK = True
    console = Console()
except ImportError:
    RICH_OK = False
    console = None


# ─────────────────────────────────────────────
#  Uncensored Model Registry
#  Priority: RAM/CPU fit, uncensored, red-team friendly
# ─────────────────────────────────────────────

UNCENSORED_MODELS = [
    # ── GGUF models (llama-cpp-python, CPU-first) ──────────────
    {
        "id":          "TheBloke/dolphin-2.9-llama3-70b-GGUF",
        "file":        "dolphin-2.9-llama3-70b.Q4_K_M.gguf",
        "name":        "Dolphin 2.9 LLaMA3 70B (Q4)",
        "family":      "dolphin",
        "ram_gb":      38,
        "backend":     "gguf",
        "uncensored":  True,
        "description": "Best uncensored model. Dolphin fine-tune on LLaMA3-70B. No restrictions.",
        "tags":        ["uncensored", "red-team", "analysis", "70b"],
    },
    {
        "id":          "TheBloke/dolphin-2.9-mistral-7b-v2-GGUF",
        "file":        "dolphin-2.9-mistral-7b-v2.Q4_K_M.gguf",
        "name":        "Dolphin 2.9 Mistral 7B (Q4)",
        "family":      "dolphin",
        "ram_gb":      5,
        "backend":     "gguf",
        "uncensored":  True,
        "description": "Fast uncensored 7B. Excellent for credential analysis and report generation.",
        "tags":        ["uncensored", "fast", "7b", "red-team"],
    },
    {
        "id":          "TheBloke/WizardLM-2-7B-GGUF",
        "file":        "WizardLM-2-7B.Q4_K_M.gguf",
        "name":        "WizardLM 2 7B (Q4)",
        "family":      "wizardlm",
        "ram_gb":      5,
        "backend":     "gguf",
        "uncensored":  True,
        "description": "Strong instruction following, minimal refusals. Good for threat analysis.",
        "tags":        ["uncensored", "instruction", "7b"],
    },
    {
        "id":          "TheBloke/OpenHermes-2.5-Mistral-7B-GGUF",
        "file":        "openhermes-2.5-mistral-7b.Q4_K_M.gguf",
        "name":        "OpenHermes 2.5 Mistral 7B (Q4)",
        "family":      "openhermes",
        "ram_gb":      5,
        "backend":     "gguf",
        "uncensored":  True,
        "description": "Highly capable uncensored Mistral fine-tune. Fast and reliable.",
        "tags":        ["uncensored", "fast", "mistral", "7b"],
    },
    {
        "id":          "TheBloke/Mixtral-8x7B-Instruct-v0.1-GGUF",
        "file":        "mixtral-8x7b-instruct-v0.1.Q4_K_M.gguf",
        "name":        "Mixtral 8x7B Instruct (Q4)",
        "family":      "mixtral",
        "ram_gb":      26,
        "backend":     "gguf",
        "uncensored":  False,
        "description": "High quality MoE model. Lightly restricted but very capable.",
        "tags":        ["instruction", "moe", "8x7b"],
    },
    {
        "id":          "TheBloke/dolphin-2.9-mixtral-8x7b-GGUF",
        "file":        "dolphin-2.9-mixtral-8x7b.Q4_K_M.gguf",
        "name":        "Dolphin 2.9 Mixtral 8x7B (Q4)",
        "family":      "dolphin",
        "ram_gb":      26,
        "backend":     "gguf",
        "uncensored":  True,
        "description": "Uncensored Mixtral MoE. Best balance of capability and unrestricted output.",
        "tags":        ["uncensored", "moe", "8x7b", "red-team"],
    },
    {
        "id":          "TheBloke/Llama-3-70B-Instruct-GGUF",
        "file":        "Meta-Llama-3-70B-Instruct.Q4_K_M.gguf",
        "name":        "LLaMA 3 70B Instruct (Q4)",
        "family":      "llama3",
        "ram_gb":      40,
        "backend":     "gguf",
        "uncensored":  False,
        "description": "Meta's flagship 70B. Strong reasoning, some restrictions.",
        "tags":        ["instruction", "70b", "reasoning"],
    },
    {
        "id":          "TheBloke/Llama-3-8B-Instruct-GGUF",
        "file":        "Meta-Llama-3-8B-Instruct.Q4_K_M.gguf",
        "name":        "LLaMA 3 8B Instruct (Q4)",
        "family":      "llama3",
        "ram_gb":      6,
        "backend":     "gguf",
        "uncensored":  False,
        "description": "Fast LLaMA3 8B. Good for quick analysis on low-RAM systems.",
        "tags":        ["instruction", "8b", "fast"],
    },
    {
        "id":          "microsoft/Phi-3-mini-4k-instruct-gguf",
        "file":        "Phi-3-mini-4k-instruct-q4.gguf",
        "name":        "Phi-3 Mini 4K (Q4)",
        "family":      "phi3",
        "ram_gb":      3,
        "backend":     "gguf",
        "uncensored":  False,
        "description": "Tiny but capable. For very low RAM systems (VPS with 4GB).",
        "tags":        ["small", "fast", "low-ram"],
    },
    {
        "id":          "TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF",
        "file":        "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
        "name":        "TinyLlama 1.1B (Q4)",
        "family":      "tinyllama",
        "ram_gb":      1,
        "backend":     "gguf",
        "uncensored":  False,
        "description": "Minimal footprint. Use only when RAM < 3GB.",
        "tags":        ["minimal", "1b", "low-ram"],
    },
    # ── HuggingFace transformers (higher RAM, GPU optional) ────
    {
        "id":          "cognitivecomputations/dolphin-2.9-llama3-8b",
        "file":        None,
        "name":        "Dolphin 2.9 LLaMA3 8B (HF)",
        "family":      "dolphin",
        "ram_gb":      16,
        "backend":     "transformers",
        "uncensored":  True,
        "description": "HuggingFace transformers version. Requires more RAM but no GGUF download.",
        "tags":        ["uncensored", "transformers", "8b"],
    },
    {
        "id":          "teknium/OpenHermes-2.5-Mistral-7B",
        "file":        None,
        "name":        "OpenHermes 2.5 Mistral 7B (HF)",
        "family":      "openhermes",
        "ram_gb":      14,
        "backend":     "transformers",
        "uncensored":  True,
        "description": "HuggingFace transformers. Good for systems with 16GB+ RAM.",
        "tags":        ["uncensored", "transformers", "mistral"],
    },
]

# RAM tier thresholds (GB)
RAM_TIERS = [
    (64,  "EXTREME",   "64 GB+  — Full precision 70B models"),
    (32,  "VERY_HIGH", "32–64 GB — Quantised 70B, Mixtral 8x7B"),
    (16,  "HIGH",      "16–32 GB — 13B models, Dolphin 13B"),
    (8,   "MEDIUM",    "8–16 GB  — 7B/8B Q8, Dolphin 7B"),
    (4,   "LOW",       "4–8 GB   — 7B Q4, OpenHermes 7B"),
    (0,   "MINIMAL",   "< 4 GB   — Phi-3 mini, TinyLlama"),
]


# ─────────────────────────────────────────────
#  Hardware Detection
# ─────────────────────────────────────────────

class HardwareProfile:
    """Snapshot of the current machine's hardware capabilities."""

    def __init__(self):
        self.cpu_name      = "Unknown"
        self.cpu_cores     = 1
        self.cpu_threads   = 1
        self.cpu_freq_mhz  = 0
        self.ram_total_gb  = 0.0
        self.ram_avail_gb  = 0.0
        self.disk_free_gb  = 0.0
        self.gpu_name      = None
        self.gpu_vram_gb   = 0.0
        self.os_name       = platform.system()
        self.os_version    = platform.version()
        self.arch          = platform.machine()
        self.ram_tier      = "MINIMAL"
        self._detect()

    def _detect(self):
        # CPU
        if CPUINFO_OK:
            try:
                info = cpuinfo.get_cpu_info()
                self.cpu_name    = info.get("brand_raw", "Unknown")
                self.cpu_cores   = info.get("count", 1)
                self.cpu_freq_mhz = int(info.get("hz_advertised_friendly", "0 GHz").split()[0].replace(".", "")) // 10
            except Exception:
                pass

        if PSUTIL_OK:
            try:
                cpu_count = psutil.cpu_count(logical=False) or 1
                cpu_logical = psutil.cpu_count(logical=True) or 1
                self.cpu_cores   = cpu_count
                self.cpu_threads = cpu_logical
                freq = psutil.cpu_freq()
                if freq:
                    self.cpu_freq_mhz = int(freq.max or freq.current or 0)
            except Exception:
                pass

            # RAM
            try:
                mem = psutil.virtual_memory()
                self.ram_total_gb = round(mem.total / (1024**3), 1)
                self.ram_avail_gb = round(mem.available / (1024**3), 1)
            except Exception:
                pass

            # Disk
            try:
                disk = psutil.disk_usage("/")
                self.disk_free_gb = round(disk.free / (1024**3), 1)
            except Exception:
                pass

        # GPU (optional, graceful fallback)
        if GPUTIL_OK:
            try:
                gpus = GPUtil.getGPUs()
                if gpus:
                    g = gpus[0]
                    self.gpu_name    = g.name
                    self.gpu_vram_gb = round(g.memoryTotal / 1024, 1)
            except Exception:
                pass

        # Determine RAM tier
        for threshold, tier, _ in RAM_TIERS:
            if self.ram_avail_gb >= threshold:
                self.ram_tier = tier
                break

    def to_dict(self) -> dict:
        return {
            "cpu_name":     self.cpu_name,
            "cpu_cores":    self.cpu_cores,
            "cpu_threads":  self.cpu_threads,
            "ram_total_gb": self.ram_total_gb,
            "ram_avail_gb": self.ram_avail_gb,
            "disk_free_gb": self.disk_free_gb,
            "gpu_name":     self.gpu_name,
            "gpu_vram_gb":  self.gpu_vram_gb,
            "os":           f"{self.os_name} {self.os_version}",
            "arch":         self.arch,
            "ram_tier":     self.ram_tier,
        }


# ─────────────────────────────────────────────
#  Model Recommender
# ─────────────────────────────────────────────

def recommend_models(hw: HardwareProfile, top_n: int = 6) -> list[dict]:
    """
    Filter and rank models that fit within available RAM.
    Uncensored models are always ranked first.
    """
    available = hw.ram_avail_gb
    # Leave 1.5GB headroom for OS + Python
    usable = max(0, available - 1.5)

    fitting = [m for m in UNCENSORED_MODELS if m["ram_gb"] <= usable]

    # Sort: uncensored first, then by RAM descending (bigger = better within budget)
    fitting.sort(key=lambda m: (-int(m["uncensored"]), -m["ram_gb"]))

    return fitting[:top_n]


# ─────────────────────────────────────────────
#  Rich Display
# ─────────────────────────────────────────────

def print_hardware_report(hw: HardwareProfile) -> None:
    if not RICH_OK:
        _plain_hardware_report(hw)
        return

    console.print()
    console.rule("[bold red]AU-OSINT-RECON — Hardware Detection[/bold red]")
    console.print()

    # Hardware table
    hw_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    hw_table.add_column("Key",   style="dim", width=14)
    hw_table.add_column("Value", style="bold white")

    hw_table.add_row("CPU",      hw.cpu_name)
    hw_table.add_row("Cores",    f"{hw.cpu_cores} physical / {hw.cpu_threads} logical")
    hw_table.add_row("RAM",      f"{hw.ram_total_gb} GB total / [green]{hw.ram_avail_gb} GB available[/green]")
    hw_table.add_row("Disk",     f"{hw.disk_free_gb} GB free")
    hw_table.add_row("GPU",      hw.gpu_name or "[dim]None detected (CPU inference mode)[/dim]")
    hw_table.add_row("OS",       f"{hw.os_name} {hw.arch}")
    hw_table.add_row("Tier",     f"[bold yellow]{hw.ram_tier}[/bold yellow]")

    console.print(Panel(hw_table, title="[bold]System Profile[/bold]", border_style="dim"))


def print_model_recommendations(models: list[dict], hw: HardwareProfile) -> None:
    if not RICH_OK:
        _plain_model_list(models)
        return

    console.print()
    console.print(f"  [dim]Available RAM for inference:[/dim] [bold green]{hw.ram_avail_gb - 1.5:.1f} GB[/bold green]")
    console.print()

    table = Table(
        title="[bold red]Recommended Uncensored Models[/bold red]",
        box=box.ROUNDED,
        show_lines=True,
        border_style="dim red",
    )
    table.add_column("#",           style="bold dim", width=3,  justify="right")
    table.add_column("Model",       style="bold white", width=34)
    table.add_column("RAM",         style="cyan",       width=7,  justify="right")
    table.add_column("Backend",     style="dim",        width=12)
    table.add_column("Uncensored",  style="bold",       width=11, justify="center")
    table.add_column("Description", style="dim white",  width=48)

    for i, m in enumerate(models, start=1):
        uncensored_str = "[bold green]✓ YES[/bold green]" if m["uncensored"] else "[dim]—[/dim]"
        backend_str    = "[yellow]GGUF[/yellow]" if m["backend"] == "gguf" else "[blue]HF[/blue]"
        table.add_row(
            str(i),
            m["name"],
            f"{m['ram_gb']} GB",
            backend_str,
            uncensored_str,
            m["description"],
        )

    console.print(table)


def _plain_hardware_report(hw: HardwareProfile) -> None:
    print("\n" + "=" * 60)
    print("  AU-OSINT-RECON — Hardware Detection")
    print("=" * 60)
    print(f"  CPU     : {hw.cpu_name}")
    print(f"  Cores   : {hw.cpu_cores} / {hw.cpu_threads} threads")
    print(f"  RAM     : {hw.ram_total_gb} GB total / {hw.ram_avail_gb} GB available")
    print(f"  Disk    : {hw.disk_free_gb} GB free")
    print(f"  GPU     : {hw.gpu_name or 'None (CPU mode)'}")
    print(f"  OS      : {hw.os_name} {hw.arch}")
    print(f"  Tier    : {hw.ram_tier}")
    print("=" * 60)


def _plain_model_list(models: list[dict]) -> None:
    print("\nRecommended models:")
    for i, m in enumerate(models, start=1):
        flag = "[UNCENSORED]" if m["uncensored"] else ""
        print(f"  {i}. {m['name']} ({m['ram_gb']}GB) {flag}")
        print(f"     {m['description']}")


# ─────────────────────────────────────────────
#  Interactive Model Selector
# ─────────────────────────────────────────────

def interactive_model_select(models: list[dict]) -> dict | None:
    """
    Prompt the user to select a model from the recommended list,
    or enter a custom HuggingFace model ID.
    """
    if not models:
        print("No models fit within available RAM.")
        return None

    print_model_recommendations(models, HardwareProfile())

    if RICH_OK:
        console.print()
        console.print(f"  Enter [bold cyan]1–{len(models)}[/bold cyan] to select, "
                      f"[bold cyan]C[/bold cyan] for custom HuggingFace ID, "
                      f"[bold cyan]Q[/bold cyan] to quit")
        choice = Prompt.ask("  Select", default="1")
    else:
        choice = input(f"\n  Select model [1-{len(models)}], C=custom, Q=quit: ").strip()

    if choice.upper() == "Q":
        return None

    if choice.upper() == "C":
        if RICH_OK:
            custom_id = Prompt.ask("  HuggingFace model ID")
        else:
            custom_id = input("  HuggingFace model ID: ").strip()
        return {
            "id":         custom_id,
            "file":       None,
            "name":       custom_id,
            "family":     "custom",
            "ram_gb":     0,
            "backend":    "transformers",
            "uncensored": False,
            "description": "Custom model",
            "tags":       ["custom"],
        }

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(models):
            return models[idx]
    except ValueError:
        pass

    return models[0]


# ─────────────────────────────────────────────
#  Model Loader
# ─────────────────────────────────────────────

class ModelLoader:
    """
    Loads and manages the selected HuggingFace / GGUF model.
    Handles download, caching, and inference.
    """

    def __init__(self, model_info: dict, cache_dir: str = "./models"):
        self.model_info = model_info
        self.cache_dir  = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._model     = None
        self._tokenizer = None
        self._llama     = None

    def load(self) -> bool:
        """Download (if needed) and load the model. Returns True on success."""
        backend = self.model_info.get("backend", "transformers")

        if backend == "gguf":
            return self._load_gguf()
        else:
            return self._load_transformers()

    def _load_gguf(self) -> bool:
        try:
            from llama_cpp import Llama
            from huggingface_hub import hf_hub_download
        except ImportError:
            print("ERROR: llama-cpp-python not installed. Run: pip install llama-cpp-python")
            return False

        model_id   = self.model_info["id"]
        model_file = self.model_info["file"]
        local_path = self.cache_dir / model_file

        if not local_path.exists():
            if RICH_OK:
                console.print(f"  [dim]Downloading[/dim] [bold]{model_file}[/bold] from HuggingFace...")
            else:
                print(f"  Downloading {model_file}...")

            try:
                hf_hub_download(
                    repo_id   = model_id,
                    filename  = model_file,
                    local_dir = str(self.cache_dir),
                    token     = os.getenv("HF_TOKEN"),
                )
            except Exception as e:
                print(f"  Download failed: {e}")
                return False

        if RICH_OK:
            console.print(f"  [dim]Loading[/dim] [bold]{self.model_info['name']}[/bold]...")

        try:
            self._llama = Llama(
                model_path    = str(local_path),
                n_ctx         = 4096,
                n_threads     = os.cpu_count() or 4,
                n_gpu_layers  = 0,          # CPU-first — no GPU required
                verbose       = False,
            )
            return True
        except Exception as e:
            print(f"  Load failed: {e}")
            return False

    def _load_transformers(self) -> bool:
        try:
            from transformers import AutoTokenizer, AutoModelForCausalLM
            import torch
        except ImportError:
            print("ERROR: transformers not installed. Run: pip install transformers torch")
            return False

        model_id = self.model_info["id"]
        hf_token = os.getenv("HF_TOKEN")

        if RICH_OK:
            console.print(f"  [dim]Loading[/dim] [bold]{model_id}[/bold] via transformers...")

        try:
            self._tokenizer = AutoTokenizer.from_pretrained(
                model_id,
                token      = hf_token,
                cache_dir  = str(self.cache_dir),
            )
            self._model = AutoModelForCausalLM.from_pretrained(
                model_id,
                token          = hf_token,
                cache_dir      = str(self.cache_dir),
                device_map     = "cpu",
                torch_dtype    = "auto",
                low_cpu_mem_usage = True,
            )
            return True
        except Exception as e:
            print(f"  Load failed: {e}")
            return False

    def generate(self, prompt: str, max_tokens: int = 512, temperature: float = 0.7) -> str:
        """Run inference. Returns generated text."""
        if self._llama is not None:
            result = self._llama(
                prompt,
                max_tokens  = max_tokens,
                temperature = temperature,
                stop        = ["</s>", "<|im_end|>", "[INST]"],
                echo        = False,
            )
            return result["choices"][0]["text"].strip()

        if self._model is not None and self._tokenizer is not None:
            import torch
            inputs  = self._tokenizer(prompt, return_tensors="pt")
            with torch.no_grad():
                output = self._model.generate(
                    **inputs,
                    max_new_tokens = max_tokens,
                    temperature    = temperature,
                    do_sample      = True,
                    pad_token_id   = self._tokenizer.eos_token_id,
                )
            decoded = self._tokenizer.decode(output[0], skip_special_tokens=True)
            return decoded[len(prompt):].strip()

        return "ERROR: No model loaded."

    def is_loaded(self) -> bool:
        return self._llama is not None or self._model is not None


# ─────────────────────────────────────────────
#  AI Analysis Tasks
# ─────────────────────────────────────────────

TASK_PROMPTS = {
    "summarise": (
        "You are a cybersecurity analyst. Summarise the following OSINT findings "
        "into a concise executive brief. Focus on the most critical risks.\n\n"
        "FINDINGS:\n{data}\n\nEXECUTIVE SUMMARY:"
    ),
    "classify": (
        "You are a MITRE ATT&CK expert. Classify each finding below by ATT&CK technique ID and name.\n\n"
        "FINDINGS:\n{data}\n\nCLASSIFICATION:"
    ),
    "extract_entities": (
        "Extract all named entities from the text below. "
        "Return as JSON with keys: emails, domains, organisations, abns, phone_numbers, ips.\n\n"
        "TEXT:\n{data}\n\nJSON:"
    ),
    "analyse_passwords": (
        "Analyse the following password list. Identify patterns, common bases, "
        "keyboard walks, and weaknesses. Suggest cracking strategies.\n\n"
        "PASSWORDS:\n{data}\n\nANALYSIS:"
    ),
    "threat_narrative": (
        "Write a detailed threat narrative for a red team report based on these findings. "
        "Be specific about attack paths and impact.\n\n"
        "FINDINGS:\n{data}\n\nNARRATIVE:"
    ),
}


class AIAnalyser:
    """
    Runs AI analysis tasks against OSINT findings using the loaded model.

    Usage:
        hw     = HardwareProfile()
        models = recommend_models(hw)
        chosen = interactive_model_select(models)
        loader = ModelLoader(chosen)
        loader.load()
        ai     = AIAnalyser(loader)
        result = ai.run("summarise", findings_json_str)
    """

    def __init__(self, loader: ModelLoader):
        self.loader = loader

    def run(self, task: str, data: str, max_tokens: int = 512) -> str:
        if not self.loader.is_loaded():
            return "ERROR: Model not loaded."

        template = TASK_PROMPTS.get(task)
        if not template:
            return f"ERROR: Unknown task '{task}'. Available: {list(TASK_PROMPTS.keys())}"

        prompt = template.format(data=data[:6000])  # Truncate to context limit
        return self.loader.generate(prompt, max_tokens=max_tokens)

    def analyse_findings(self, findings: list[dict], task: str = "summarise") -> str:
        data = json.dumps(findings, indent=2, default=str)
        return self.run(task, data)

    def analyse_passwords(self, passwords: list[str]) -> str:
        data = "\n".join(passwords[:200])
        return self.run("analyse_passwords", data)

    def extract_entities(self, text: str) -> dict:
        raw = self.run("extract_entities", text, max_tokens=256)
        try:
            start = raw.find("{")
            end   = raw.rfind("}") + 1
            return json.loads(raw[start:end])
        except Exception:
            return {"raw": raw}

    def available_tasks(self) -> list[str]:
        return list(TASK_PROMPTS.keys())


# ─────────────────────────────────────────────
#  Convenience: Full Setup Flow
# ─────────────────────────────────────────────

def setup_ai(cache_dir: str = "./models", auto: bool = False) -> tuple[AIAnalyser | None, dict | None]:
    """
    Full setup flow:
    1. Detect hardware
    2. Recommend models
    3. Interactive selection (or auto-pick best fit)
    4. Load model
    5. Return AIAnalyser

    Returns (analyser, model_info) or (None, None) on failure.
    """
    hw     = HardwareProfile()
    print_hardware_report(hw)
    models = recommend_models(hw)

    if not models:
        print("ERROR: No models fit within available RAM.")
        return None, None

    if auto:
        chosen = models[0]
        if RICH_OK:
            console.print(f"\n  [dim]Auto-selected:[/dim] [bold]{chosen['name']}[/bold]")
        else:
            print(f"\n  Auto-selected: {chosen['name']}")
    else:
        chosen = interactive_model_select(models)
        if chosen is None:
            return None, None

    loader = ModelLoader(chosen, cache_dir=cache_dir)
    ok = loader.load()
    if not ok:
        return None, chosen

    analyser = AIAnalyser(loader)
    return analyser, chosen


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AU-OSINT AI Module — HuggingFace Integration")
    parser.add_argument("--detect-hardware", action="store_true", help="Detect hardware and show model recommendations")
    parser.add_argument("--select-model",    action="store_true", help="Interactively select and load a model")
    parser.add_argument("--model",           default="auto",      help="Model selection: 'auto' or HuggingFace model ID")
    parser.add_argument("--input",           help="JSON findings file to analyse")
    parser.add_argument("--task",            default="summarise", help=f"Analysis task: {list(TASK_PROMPTS.keys())}")
    parser.add_argument("--cache-dir",       default="./models",  help="Local model cache directory")
    parser.add_argument("--output",          help="Save analysis output to file")
    args = parser.parse_args()

    if args.detect_hardware:
        hw     = HardwareProfile()
        print_hardware_report(hw)
        models = recommend_models(hw)
        print_model_recommendations(models, hw)
        sys.exit(0)

    if args.select_model or args.input:
        auto = args.model == "auto" and not args.select_model
        analyser, model_info = setup_ai(cache_dir=args.cache_dir, auto=auto)

        if analyser is None:
            sys.exit(1)

        if args.input:
            with open(args.input, "r") as f:
                raw = json.load(f)
            findings = raw if isinstance(raw, list) else raw.get("findings", [])
            result   = analyser.analyse_findings(findings, task=args.task)

            if RICH_OK:
                console.print(Panel(result, title=f"[bold]{args.task.upper()}[/bold]", border_style="green"))
            else:
                print("\n" + "=" * 60)
                print(result)

            if args.output:
                with open(args.output, "w") as f:
                    f.write(result)
                print(f"\nSaved to: {args.output}")
