/**
 * reports.js
 * -----------
 * Powers reports.html: GET /api/reports/summary?range=X for the stat
 * cards/charts/table, and GET /api/reports/export?range=X (downloaded
 * via a real navigation, not fetch, since it's a file attachment).
 */

let currentRange = "30d";
let trendChartInstance = null;
let iocChartInstance = null;

const IOC_COLORS = {
  ip: "#0E9F6E", domain: "#0B7A55", url: "#16A34A",
  hash: "#D97706", email: "#5B6B63",
};

function renderTrendChart(trend) {
  const ctx = document.getElementById("repTrendChart");
  if (trendChartInstance) trendChartInstance.destroy();
  trendChartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: trend.map((d) => formatDate(d.date)),
      datasets: [{
        label: "Detections",
        data: trend.map((d) => d.count),
        backgroundColor: "#0E9F6E",
        borderRadius: 4,
        maxBarThickness: 28,
      }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        y: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: "#EEF2EF" } },
        x: { grid: { display: false } },
      },
    },
  });
}

function renderIocChart(iocBreakdown) {
  const ctx = document.getElementById("repIocChart");
  if (iocChartInstance) iocChartInstance.destroy();
  iocChartInstance = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: iocBreakdown.map((r) => r.ioc_type.toUpperCase()),
      datasets: [{
        data: iocBreakdown.map((r) => r.count),
        backgroundColor: iocBreakdown.map((r) => IOC_COLORS[r.ioc_type] || "#8B978F"),
        borderWidth: 0,
      }],
    },
    options: {
      responsive: true,
      cutout: "65%",
      plugins: { legend: { position: "bottom", labels: { boxWidth: 10, padding: 14, font: { size: 12 } } } },
    },
  });
}

function renderTypeBreakdown(typeBreakdown) {
  const body = document.getElementById("typeBreakdownBody");
  if (!typeBreakdown.length) {
    body.innerHTML = `<tr><td colspan="3"><div class="empty-state"><p>No data for this range.</p></div></td></tr>`;
    return;
  }
  body.innerHTML = typeBreakdown.map((row) => `
    <tr>
      <td style="text-transform:capitalize">${escapeHtml(row.type.replace(/_/g, " "))}</td>
      <td>${row.count}</td>
      <td>
        <div class="flex items-center gap-sm">
          <div class="cat-bar" style="width:120px;"><div class="cat-bar-fill" style="width:${row.percentage}%"></div></div>
          <span class="text-muted" style="font-size:13px;">${row.percentage}%</span>
        </div>
      </td>
    </tr>
  `).join("");
}

async function loadReport() {
  try {
    const data = await API.get(`/api/reports/summary?range=${currentRange}`);

    document.getElementById("repTotal").textContent = data.total_threats;
    document.getElementById("repAnalyses").textContent = data.total_analyses;
    document.getElementById("repCritical").textContent = data.severity_counts.critical || 0;
    document.getElementById("repTopSource").textContent =
      data.top_sources && data.top_sources.length ? data.top_sources[0].source : "—";

    renderTrendChart(data.trend);
    renderIocChart(data.ioc_breakdown);
    renderTypeBreakdown(data.type_breakdown);
  } catch (err) {
    showToast(err.message || "Could not load report.", "error");
  }
}

function wireRangePills() {
  document.querySelectorAll(".range-pill").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".range-pill").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      currentRange = btn.getAttribute("data-range");
      loadReport();
    });
  });
}

function wireExport() {
  document.getElementById("exportBtn").addEventListener("click", () => {
    window.location.href = `/api/reports/export?range=${currentRange}`;
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  const me = await initNav();
  if (!me) return;
  wireRangePills();
  wireExport();
  loadReport();
});
