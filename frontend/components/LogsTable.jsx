const labelStyles = {
  SAFE: "bg-green-100 text-green-700",
  SUSPICIOUS: "bg-yellow-100 text-yellow-800",
  MALICIOUS: "bg-red-100 text-red-700",
};

function formatDate(value) {
  if (!value) {
    return "--";
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return parsed.toLocaleString();
}

export default function LogsTable({
  title,
  description,
  logs,
  page,
  pageSize,
  totalPages,
  total,
  loading,
  onPageChange,
}) {
  return (
    <section className="rounded-[32px] border border-white/60 bg-white/80 p-6 shadow-card backdrop-blur">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="text-sm uppercase tracking-[0.24em] text-slate-500">{title}</p>
          <h2 className="mt-2 text-2xl font-semibold text-slateink">Security Event Logs</h2>
          <p className="mt-2 text-sm leading-6 text-slate-600">{description}</p>
        </div>
        <div className="rounded-full bg-slateink px-4 py-2 text-sm font-medium text-sand">
          {total} total records
        </div>
      </div>

      <div className="mt-6 overflow-hidden rounded-[24px] border border-slate-200">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-slate-200">
            <thead className="bg-slate-50">
              <tr className="text-left text-xs uppercase tracking-[0.16em] text-slate-500">
                <th className="px-4 py-4 font-semibold">Prompt</th>
                <th className="px-4 py-4 font-semibold">Risk</th>
                <th className="px-4 py-4 font-semibold">Label</th>
                <th className="px-4 py-4 font-semibold">Reason</th>
                <th className="px-4 py-4 font-semibold">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 bg-white">
              {loading ? (
                <tr>
                  <td className="px-4 py-8 text-sm text-slate-500" colSpan="5">
                    Loading log data...
                  </td>
                </tr>
              ) : null}

              {!loading && logs.length === 0 ? (
                <tr>
                  <td className="px-4 py-8 text-sm text-slate-500" colSpan="5">
                    No log entries available for this view.
                  </td>
                </tr>
              ) : null}

              {!loading
                ? logs.map((log) => (
                    <tr key={log.id} className="align-top">
                      <td className="max-w-sm px-4 py-4 text-sm leading-6 text-slate-700">
                        {log.user_input}
                      </td>
                      <td className="px-4 py-4 text-sm font-semibold text-slateink">
                        {log.risk_score}
                      </td>
                      <td className="px-4 py-4 text-sm">
                        <span
                          className={`rounded-full px-3 py-1 text-xs font-semibold ${
                            labelStyles[log.label] || "bg-slate-100 text-slate-700"
                          }`}
                        >
                          {log.label}
                        </span>
                      </td>
                      <td className="max-w-md px-4 py-4 text-sm leading-6 text-slate-600">
                        {log.reason}
                      </td>
                      <td className="whitespace-nowrap px-4 py-4 text-sm text-slate-500">
                        {formatDate(log.created_at)}
                      </td>
                    </tr>
                  ))
                : null}
            </tbody>
          </table>
        </div>
      </div>

      <div className="mt-6 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <p className="text-sm text-slate-500">
          Page {page} of {Math.max(totalPages, 1)} • {pageSize} rows per page
        </p>
        <div className="flex gap-3">
          <button
            type="button"
            onClick={() => onPageChange(page - 1)}
            disabled={page <= 1 || loading}
            className="rounded-full border border-slate-300 px-4 py-2 text-sm font-semibold text-slate-700 transition hover:border-slateink hover:text-slateink disabled:cursor-not-allowed disabled:opacity-50"
          >
            Previous
          </button>
          <button
            type="button"
            onClick={() => onPageChange(page + 1)}
            disabled={loading || totalPages === 0 || page >= totalPages}
            className="rounded-full bg-slateink px-4 py-2 text-sm font-semibold text-sand transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Next
          </button>
        </div>
      </div>
    </section>
  );
}
