import { useState } from "react";

export default function InputForm({ onSubmit, loading }) {
  const [input, setInput] = useState("");

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!input.trim()) {
      return;
    }
    await onSubmit(input.trim());
  };

  return (
    <form className="space-y-4" onSubmit={handleSubmit}>
      <label className="block text-sm font-medium text-slate-700" htmlFor="prompt-input">
        Prompt to inspect
      </label>
      <textarea
        id="prompt-input"
        className="min-h-44 w-full rounded-[28px] border border-slate-200 bg-white px-5 py-4 text-base text-slateink outline-none transition focus:border-ember focus:ring-4 focus:ring-ember/15"
        placeholder="Paste a user prompt here to evaluate prompt injection, jailbreak, or leakage risks..."
        value={input}
        onChange={(event) => setInput(event.target.value)}
      />
      <button
        type="submit"
        disabled={loading}
        className="inline-flex items-center justify-center rounded-full bg-ember px-6 py-3 text-sm font-semibold text-white transition hover:bg-[#b84f28] disabled:cursor-not-allowed disabled:opacity-70"
      >
        {loading ? "Analyzing..." : "Analyze Prompt"}
      </button>
    </form>
  );
}
