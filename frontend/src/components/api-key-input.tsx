"use client";

import { Eye, EyeOff } from "lucide-react";

export type ApiKeyEntry = {
  key: string;
  label: string;
  placeholder: string;
  envVar: string;
  link?: string;
};

interface ApiKeyInputProps {
  entry: ApiKeyEntry;
  value: string;
  visible: boolean;
  onChange: (v: string) => void;
  onToggle: () => void;
}

export function ApiKeyInput({
  entry,
  value,
  visible,
  onChange,
  onToggle,
}: ApiKeyInputProps) {
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