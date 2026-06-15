"use client";

import { useState, type FormEvent } from "react";
import { ShieldCheck, AlertCircle, Loader2 } from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import Link from "next/link";

export default function RegisterPage() {
  const { register, isAuthenticated } = useAuth();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
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
      await register(email, password, displayName);
      setSuccess(true);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Registration failed.");
    } finally {
      setLoading(false);
    }
  }

  if (success) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-zinc-950 px-4">
        <div className="w-full max-w-sm text-center">
          <div className="mx-auto mb-4 grid size-14 place-items-center rounded-xl bg-emerald-300 text-zinc-950">
            <ShieldCheck className="size-8" />
          </div>
          <h1 className="text-xl font-semibold text-zinc-50">Account created</h1>
          <p className="mt-2 text-sm text-zinc-400">
            You can now sign in with your email and password.
          </p>
          <Link
            href="/login"
            className="mt-6 inline-block rounded-md bg-cyan-300 px-6 py-2 text-sm font-semibold text-zinc-950 hover:bg-cyan-200"
          >
            Sign in
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-950 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 grid size-14 place-items-center rounded-xl bg-cyan-300 text-zinc-950">
            <ShieldCheck className="size-8" />
          </div>
          <h1 className="text-xl font-semibold text-zinc-50">Create an account</h1>
          <p className="mt-1 text-sm text-zinc-500">Register for Aegis OSINT</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {error && (
            <div className="flex items-start gap-2 rounded-md border border-red-800 bg-red-950/50 p-3 text-sm text-red-200">
              <AlertCircle className="mt-0.5 size-4 shrink-0 text-red-400" />
              <span>{error}</span>
            </div>
          )}

          <div>
            <label htmlFor="displayName" className="mb-1.5 block text-sm font-medium text-zinc-300">
              Display name
            </label>
            <input
              id="displayName"
              type="text"
              required
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="Jane Doe"
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-500 transition-colors focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400"
            />
          </div>

          <div>
            <label htmlFor="regEmail" className="mb-1.5 block text-sm font-medium text-zinc-300">
              Email
            </label>
            <input
              id="regEmail"
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
            <label htmlFor="regPassword" className="mb-1.5 block text-sm font-medium text-zinc-300">
              Password
            </label>
            <input
              id="regPassword"
              type="password"
              required
              minLength={8}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="At least 8 characters"
              autoComplete="new-password"
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-500 transition-colors focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="flex w-full items-center justify-center gap-2 rounded-md bg-cyan-300 px-4 py-2 text-sm font-semibold text-zinc-950 transition-colors hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? <Loader2 className="size-4 animate-spin" /> : null}
            {loading ? "Creating account…" : "Create account"}
          </button>
        </form>

        <p className="mt-6 text-center text-xs text-zinc-600">
          Already have an account?{" "}
          <Link href="/login" className="text-cyan-400 hover:text-cyan-300">
            Sign in
          </Link>
        </p>
      </div>
    </div>
  );
}