export default function StatsCard({ title, value, accent = "slate", description }) {
  const accentStyles = {
    ember: "from-ember/15 to-orange-100 text-ember",
    sage: "from-green-100 to-green-50 text-green-700",
    slate: "from-slate-100 to-white text-slateink",
    crimson: "from-red-100 to-rose-50 text-red-700",
  };

  return (
    <article className="rounded-[28px] border border-white/60 bg-white/80 p-5 shadow-card backdrop-blur">
      <div
        className={`rounded-[22px] bg-gradient-to-br p-5 ${
          accentStyles[accent] || accentStyles.slate
        }`}
      >
        <p className="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">{title}</p>
        <p className="mt-4 text-4xl font-semibold">{value}</p>
        {description ? (
          <p className="mt-3 max-w-xs text-sm leading-6 text-slate-600">{description}</p>
        ) : null}
      </div>
    </article>
  );
}
