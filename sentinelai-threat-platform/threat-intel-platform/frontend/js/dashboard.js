/**
 * dashboard.js
 * -------------
 * Fetches /api/dashboard/summary and renders the stat cards, the 14-day
 * trend line chart, the severity donut chart, the type distribution bars,
 * and the recent threats table.
 */

const SEVERITY_COLORS = {
  critical: "#DC2626",
  high: "#EA580C",
  medium: "#D97706",
  low: "#16A34A",
};

function severityBadge(sev) {
  return `<span class="badge badge-${sev}">${escapeHtml(sev)}</span>`;
}

function statusBadge(status) {
  return `<span class="badge badge-${status}">${escapeHtml(status)}</span>`;
}

function renderRecentThreatsRows(threats) {
  const body = document.getElementById("recentThreatsBody");
  if (!threats.length) {
    body.innerHTML = `<tr><td colspan="6">
      <div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 8L12 13 3 8"/><path d="M3 8v10a2 2 0 002 2h14a2 2 0 002-2V8"/><path d="M3 8l3.6-5.4A2 2 0 018.2 2h7.6a2 2 0 011.6.8L21 8"/></svg>
        <h3>No threats recorded yet</h3>
        <p>Add your first indicator from the Threats page.</p>
      </div>
    </td></tr>`;
    return;
  }
  body.innerHTML = threats.map((t) => `
    <tr>
      <td class="mono">${escapeHtml(t.ioc_value)}</td>
      <td style="text-transform:capitalize">${escapeHtml(t.threat_type.replace(/_/g, " "))}</td>
      <td>${severityBadge(t.severity)}</td>
      <td>${statusBadge(t.status)}</td>
      <td class="cell-muted">${formatDate(t.detected_at)}</td>
      <td class="cell-muted">${escapeHtml(t.created_by_username || "system")}</td>
    </tr>
  `).join("");
}

function renderTypeDistribution(typeDist, total) {
  const container = document.getElementById("typeDistribution");
  if (!typeDist.length) {
    container.innerHTML = `<p class="text-muted">No data yet.</p>`;
    return;
  }
  container.innerHTML = typeDist.map((row) => {
    const pct = total ? Math.round((row.count / total) * 100) : 0;
    return `
      <div class="category-bar-row">
        <div class="cat-name">${escapeHtml(row.type.replace(/_/g, " "))}</div>
        <div class="cat-bar"><div class="cat-bar-fill" style="width:${pct}%"></div></div>
        <div class="cat-pct">${pct}%</div>
      </div>
    `;
  }).join("");
}

function renderTrendChart(trend) {
  const ctx = document.getElementById("trendChart");
  new Chart(ctx, {
    type: "line",
    data: {
      labels: trend.map((d) => formatDate(d.date)),
      datasets: [{
        label: "Threats detected",
        data: trend.map((d) => d.count),
        borderColor: "#0E9F6E",
        backgroundColor: "rgba(14, 159, 110, 0.10)",
        borderWidth: 2.5,
        pointRadius: 3,
        pointBackgroundColor: "#0E9F6E",
        tension: 0.35,
        fill: true,
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

function renderSeverityChart(severityCounts) {
  const ctx = document.getElementById("severityChart");
  const labels = ["critical", "high", "medium", "low"];
  new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: labels.map((l) => l[0].toUpperCase() + l.slice(1)),
      datasets: [{
        data: labels.map((l) => severityCounts[l] || 0),
        backgroundColor: labels.map((l) => SEVERITY_COLORS[l]),
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

async function loadDashboard() {
  try {
    const data = await API.get("/api/dashboard/summary");

    document.getElementById("statTotalThreats").textContent = data.total_threats;
    document.getElementById("statCriticalHigh").textContent =
      (data.severity_counts.critical || 0) + (data.severity_counts.high || 0);
    document.getElementById("statAnalyses").textContent = data.total_analyses;
    document.getElementById("statAiFlagged").textContent = data.ai_flagged_malicious;

    renderTrendChart(data.trend_14_days);
    renderSeverityChart(data.severity_counts);
    renderTypeDistribution(data.type_distribution, data.total_threats);
    renderRecentThreatsRows(data.recent_threats);
  } catch (err) {
    showToast(err.message || "Could not load dashboard data.", "error");
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  const me = await initNav();
  if (me) loadDashboard();
});
