"use client";

import { useState, type FormEvent } from "react";
import { ShieldCheck, Eye, EyeOff, AlertCircle, Loader2 } from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import Link from "next/link";

const OAUTH_PROVIDERS = [
  { name: "Google",      icon: "G",  color: "bg-white text-zinc-900 hover:bg-zinc-200",        url: "/api/v1/auth/oauth/google" },
  { name: "GitHub",      icon: "GH", color: "bg-zinc-800 text-zinc-100 hover:bg-zinc-700",     url: "/api/v1/auth/oauth/github" },
  { name: "HuggingFace", icon: "HF", color: "bg-amber-600 text-white hover:bg-amber-500",      url: "/api/v1/auth/oauth/huggingface" },
  { name: "Microsoft",   icon: "MS", color: "bg-blue-600 text-white hover:bg-blue-500",        url: "/api/v1/auth/oauth/microsoft" },
];

export default function LoginPage() {
  const { login, isAuthenticated } = useAuth();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  if (isAuthenticated && typeof window !== "undefined") {
    window.location.href = "/dashboard";
    return null;
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await login(email, password);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Login failed.");
    } finally {
      setLoading(false);
    }
  }

  function handleOAuth(providerUrl: string) {
    const baseUrl = process.env.NEXT_PUBLIC_AEGIS_API_URL?.replace(/\/$/, "") ?? "";
    window.location.href = `${baseUrl}${providerUrl}`;
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-950 px-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 grid size-14 place-items-center rounded-xl bg-cyan-300 text-zinc-950">
            <ShieldCheck className="size-8" />
          </div>
          <h1 className="text-xl font-semibold text-zinc-50">Aegis OSINT</h1>
          <p className="mt-1 text-sm text-zinc-500">Sign in to your workspace</p>
        </div>

        {/* OAuth Buttons */}
        <div className="space-y-2">
          {OAUTH_PROVIDERS.map((p) => (
            <button
              key={p.name}
              type="button"
              onClick={() => handleOAuth(p.url)}
              className={`flex w-full items-center justify-center gap-3 rounded-md px-4 py-2.5 text-sm font-medium transition-colors ${p.color}`}
            >
              <span className="flex size-6 items-center justify-center rounded-full bg-black/10 text-xs font-bold">
                {p.icon}
              </span>
              Sign in with {p.name}
            </button>
          ))}
        </div>

        {/* Divider */}
        <div className="my-6 flex items-center gap-3">
          <div className="h-px flex-1 bg-zinc-800" />
          <span className="text-xs text-zinc-500">or sign in with email</span>
          <div className="h-px flex-1 bg-zinc-800" />
        </div>

        {/* Email form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          {error && (
            <div className="flex items-start gap-2 rounded-md border border-red-800 bg-red-950/50 p-3 text-sm text-red-200">
              <AlertCircle className="mt-0.5 size-4 shrink-0 text-red-400" />
              <span>{error}</span>
            </div>
          )}

          <div>
            <label htmlFor="email" className="mb-1.5 block text-sm font-medium text-zinc-300">
              Email
            </label>
            <input
              id="email"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="operator@example.com"
              autoComplete="email"
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-500 transition-colors focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400"
            />
          </div>

          <div>
            <label htmlFor="password" className="mb-1.5 block text-sm font-medium text-zinc-300">
              Password
            </label>
            <div className="relative">
              <input
                id="password"
                type={showPassword ? "text" : "password"}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                autoComplete="current-password"
                className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 pr-10 text-sm text-zinc-100 placeholder-zinc-500 transition-colors focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
                aria-label={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="flex w-full items-center justify-center gap-2 rounded-md bg-cyan-300 px-4 py-2 text-sm font-semibold text-zinc-950 transition-colors hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? <Loader2 className="size-4 animate-spin" /> : null}
            {loading ? "Signing in..." : "Sign in"}
          </button>
        </form>

        <p className="mt-6 text-center text-xs text-zinc-600">
          Don't have an account?{" "}
          <Link href="/register" className="text-cyan-400 hover:text-cyan-300">
            Create one
          </Link>
        </p>
      </div>
    </div>
  );
}