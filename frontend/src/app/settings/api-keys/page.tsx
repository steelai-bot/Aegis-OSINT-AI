"use client";

import { useState, useEffect } from "react";
import { Key, Eye, EyeOff, Check, AlertCircle, Loader2, Save } from "lucide-react";
import { PageHeader } from "@/components/page-header";

type ApiKeyEntry = {
  key: string;
  label: string;
  placeholder: string;
  envVar: string;
  link?: string;
};

const API_KEYS: ApiKeyEntry[] = [
  { key: "OPENAI_API_KEY",      label: "OpenAI API Key",      placeholder: "sk-...",                 envVar: "OPENAI_API_KEY",      link: "https://platform.openai.com/api-keys" },
  { key: "OPENROUTER_API_KEY",  label: "OpenRouter API Key",  placeholder: "sk-or-...",              envVar: "OPENROUTER_API_KEY",  link: "https://openrouter.ai/keys" },
  { key: "HF_TOKEN",            label: "HuggingFace Token",   placeholder: "hf_...",                 envVar: "HF_TOKEN",            link: "https://huggingface.co/settings/tokens" },
  { key: "HIBP_API_KEY",        label: "Have I Been Pwned",   placeholder: "hibp_...",               envVar: "HIBP_API_KEY",        link: "https://haveibeenpwned.com/API/Key" },
  { key: "SHODAN_API_KEY",      label: "Shodan",              placeholder: "shodan_...",             envVar: "SHODAN_API_KEY",      link: "https://account.shodan.io" },
  { key: "VIRUSTOTAL_API_KEY",  label: "VirusTotal",          placeholder: "vt_...",                 envVar: "VIRUSTOTAL_API_KEY",  link: "https://www.virustotal.com/gui/my-apikey" },
  { key: "CENSYS_API_ID",       label: "Censys API ID",       placeholder: "censys_id...",           envVar: "CENSYS_API_ID" },
  { key: "CENSYS_API_SECRET",   label: "Censys API Secret",   placeholder: "censys_secret...",       envVar: "CENSYS_API_SECRET" },
  { key: "BRAVE_API_KEY",       label: "Brave Search",        placeholder: "brave_...",              envVar: "BRAVE_API_KEY",       link: "https://brave.com/search/api/" },
  { key: "HUNTER_API_KEY",      label: "Hunter.io",           placeholder: "hunter_...",             envVar: "HUNTER_API_KEY",      link: "https://hunter.io/api-keys" },
];

export default function ApiKeysPage() {
  const [values, setValues] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [visibleKeys, setVisibleKeys] = useState<Record<string, boolean>>({});

  useEffect(() => {
    const loaded: Record<string, string> = {};
    for (const entry of API_KEYS) {
      loaded[entry.key] = localStorage.getItem(`aegis_${entry.key}`) || "";
    }
    setValues(loaded);
  }, []);

  function handleChange(key: string, value: string) {
    setValues((prev) => ({ ...prev, [key]: value }));
    setSaved(false);
    setError(null);
  }

  function handleSave() {
    setSaving(true);
    setError(null);
    try {
      for (const entry of API_KEYS) {
        const val = values[entry.key]?.trim();
        if (val) {
          localStorage.setItem(`aegis_${entry.key}`, val);
        } else {
          localStorage.removeItem(`aegis_${entry.key}`);
        }
      }
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (err) {
      setError("Failed to save API keys to local storage.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <PageHeader
        title="API Keys"
        description="Configure API keys for AI providers and external services. Keys are stored locally in your browser."
        icon={Key}
      />

      <section className="space-y-4">
        {/* AI Provider Keys */}
        <div className="rounded-md border border-zinc-800 bg-zinc-900/70 p-4">
          <h2 className="mb-4 text-sm font-semibold uppercase text-zinc-400">AI Providers</h2>
          <div className="grid gap-4 md:grid-cols-2">
            {API_KEYS.slice(0, 3).map((entry) => (
              <ApiKeyInput
                key={entry.key}
                entry={entry}
                value={values[entry.key] || ""}
                visible={visibleKeys[entry.key] || false}
                onChange={(v) => handleChange(entry.key, v)}
                onToggle={() => setVisibleKeys((p) => ({ ...p, [entry.key]: !p[entry.key] }))}
              />
            ))}
          </div>
        </div>

        {/* Intelligence Provider Keys */}
        <div className="rounded-md border border-zinc-800 bg-zinc-900/70 p-4">
          <h2 className="mb-4 text-sm font-semibold uppercase text-zinc-400">Intelligence Providers</h2>
          <div className="grid gap-4 md:grid-cols-2">
            {API_KEYS.slice(3).map((entry) => (
              <ApiKeyInput
                key={entry.key}
                entry={entry}
                value={values[entry.key] || ""}
                visible={visibleKeys[entry.key] || false}
                onChange={(v) => handleChange(entry.key, v)}
                onToggle={() => setVisibleKeys((p) => ({ ...p, [entry.key]: !p[entry.key] }))}
              />
            ))}
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center justify-between rounded-md border border-zinc-800 bg-zinc-900/70 p-4">
          <div>
            {saved && (
              <span className="flex items-center gap-1 text-sm text-green-400">
                <Check className="size-4" /> Keys saved locally
              </span>
            )}
            {error && (
              <span className="flex items-center gap-1 text-sm text-red-400">
                <AlertCircle className="size-4" /> {error}
              </span>
            )}
          </div>
          <button
            onClick={handleSave}
            disabled={saving}
            className="flex items-center gap-2 rounded-md bg-cyan-300 px-4 py-2 text-sm font-semibold text-zinc-950 transition-colors hover:bg-cyan-200 disabled:opacity-50"
          >
            {saving ? <Loader2 className="size-4 animate-spin" /> : <Save className="size-4" />}
            {saving ? "Saving..." : "Save Keys"}
          </button>
        </div>
      </section>
    </>
  );
}

function ApiKeyInput({
  entry,
  value,
  visible,
  onChange,
  onToggle,
}: {
  entry: ApiKeyEntry;
  value: string;
  visible: boolean;
  onChange: (v: string) => void;
  onToggle: () => void;
}) {
  return (
    <div className="rounded-md border border-zinc-800 bg-zinc-950 p-3">
      <label className="mb-1 block text-xs font-medium text-zinc-400">
        {entry.label}
        {entry.link && (
          <a
            href={entry.link}
            target="_blank"
            rel="noopener noreferrer"
            className="ml-1 text-cyan-400 hover:text-cyan-300"
          >
            (get key)
          </a>
        )}
      </label>
      <div className="relative">
        <input
          type={visible ? "text" : "password"}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={entry.placeholder}
          className="w-full rounded border border-zinc-700 bg-zinc-900 px-2 py-1.5 pr-8 text-sm font-mono text-zinc-200 placeholder-zinc-600 focus:border-cyan-400 focus:outline-none"
        />
        <button
          type="button"
          onClick={onToggle}
          className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
          aria-label={visible ? "Hide" : "Show"}
        >
          {visible ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
        </button>
      </div>
    </div>
  );
}