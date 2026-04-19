const labelStyles = {
  SAFE: "bg-green-100 text-green-700",
  SUSPICIOUS: "bg-yellow-100 text-yellow-800",
  MALICIOUS: "bg-red-100 text-red-700",
};

export default function ResultCard({ result, loading }) {
  return (
    <section className="rounded-[32px] border border-white/60 bg-white/80 p-8 shadow-card backdrop-blur">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm uppercase tracking-[0.24em] text-slate-500">Analysis Result</p>
          <h2 className="mt-2 text-2xl font-semibold text-slateink">Gateway Decision</h2>
        </div>
        {result ? (
          <span
            className={`rounded-full px-4 py-2 text-sm font-semibold ${
              labelStyles[result.label] || "bg-slate-100 text-slate-700"
            }`}
          >
            {result.label}
          </span>
        ) : null}
      </div>

      {loading ? (
        <div className="mt-6 rounded-3xl border border-dashed border-slate-300 bg-slate-50 p-8 text-sm text-slate-500">
          Running detection modules and preparing a safe response...
        </div>
      ) : null}

      {!loading && !result ? (
        <div className="mt-6 rounded-3xl border border-dashed border-slate-300 bg-slate-50 p-8 text-sm text-slate-500">
          Submit a prompt to see the risk score, security classification, explanation, and safe response.
        </div>
      ) : null}

      {result && !loading ? (
        <div className="mt-6 grid gap-4 md:grid-cols-2">
          <article className="rounded-3xl bg-sand p-5">
            <p className="text-sm uppercase tracking-[0.16em] text-slate-500">Risk Score</p>
            <p className="mt-3 text-4xl font-semibold text-slateink">{result.risk_score}</p>
          </article>
          <article className="rounded-3xl bg-sand p-5">
            <p className="text-sm uppercase tracking-[0.16em] text-slate-500">Explanation</p>
            <p className="mt-3 text-base leading-7 text-slate-700">{result.reason}</p>
          </article>
          <article className="rounded-3xl bg-slateink p-5 text-sand md:col-span-2">
            <p className="text-sm uppercase tracking-[0.16em] text-sand/60">Safe LLM Response</p>
            <p className="mt-3 text-base leading-7">{result.safe_response}</p>
          </article>
        </div>
      ) : null}
    </section>
  );
}
