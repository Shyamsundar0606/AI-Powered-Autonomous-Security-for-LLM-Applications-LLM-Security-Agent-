import { useState } from "react";

import InputForm from "../components/InputForm";
import ResultCard from "../components/ResultCard";
import { analyzePrompt } from "../services/api";

const initialResult = null;

export default function HomePage() {
  const [result, setResult] = useState(initialResult);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleAnalyze = async (input) => {
    setLoading(true);
    setError("");

    try {
      const response = await analyzePrompt(input);
      setResult(response);
    } catch (err) {
      setError(err.message || "Unable to analyze prompt right now.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(204,90,47,0.18),_transparent_35%),linear-gradient(135deg,_#f8f4ec_0%,_#efe4d2_50%,_#e8ddd0_100%)] px-6 py-12 text-slateink">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-8">
        <section className="grid gap-6 rounded-[32px] border border-white/50 bg-white/70 p-8 shadow-card backdrop-blur md:grid-cols-[1.2fr_0.8fr]">
          <div className="space-y-5">
            <span className="inline-flex rounded-full bg-slateink px-4 py-1 text-xs font-semibold uppercase tracking-[0.24em] text-sand">
              LLM Security Gateway
            </span>
            <div className="space-y-3">
              <h1 className="max-w-2xl text-4xl font-semibold leading-tight md:text-5xl">
                Secure AI prompts before they ever reach the model.
              </h1>
              <p className="max-w-2xl text-base leading-7 text-slate-600">
                Inspect prompt injection, jailbreak attempts, and data leakage risks,
                then return a policy-safe response through one guarded workflow.
              </p>
            </div>
            <InputForm onSubmit={handleAnalyze} loading={loading} />
            {error ? (
              <p className="rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
                {error}
              </p>
            ) : null}
          </div>
          <div className="flex items-center justify-center">
            <div className="w-full rounded-[28px] bg-slateink p-6 text-sand">
              <p className="text-sm uppercase tracking-[0.24em] text-sand/70">
                Security Coverage
              </p>
              <div className="mt-6 space-y-4 text-sm leading-6">
                <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                  Prompt injection detection
                </div>
                <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                  Jailbreak pattern analysis
                </div>
                <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                  Data leakage prevention
                </div>
                <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                  Safe output filtering
                </div>
              </div>
            </div>
          </div>
        </section>

        <ResultCard result={result} loading={loading} />
      </div>
    </main>
  );
}
