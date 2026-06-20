/**
 * threats.js
 * -----------
 * Powers threats.html: server-side filtered + paginated threat table,
 * the "Add threat" modal, and delete (admin only - the delete button is
 * only rendered for admins, and the backend independently enforces this
 * with @admin_required, so hiding the button is a UX nicety, not the
 * actual security boundary).
 */

let currentPage = 1;
let currentUser = null;
let searchDebounceTimer = null;

function buildQuery() {
  const params = new URLSearchParams();
  params.set("page", currentPage);
  params.set("per_page", 12);

  const search = document.getElementById("searchInput").value.trim();
  const severity = document.getElementById("severityFilter").value;
  const type = document.getElementById("typeFilter").value;
  const status = document.getElementById("statusFilter").value;

  if (search) params.set("search", search);
  if (severity) params.set("severity", severity);
  if (type) params.set("threat_type", type);
  if (status) params.set("status", status);

  return params.toString();
}

function severityBadge(sev) {
  return `<span class="badge badge-${sev}">${escapeHtml(sev)}</span>`;
}
function statusBadge(status) {
  return `<span class="badge badge-${status}">${escapeHtml(status.replace(/_/g, " "))}</span>`;
}

function renderRows(threats) {
  const body = document.getElementById("threatsBody");
  if (!threats.length) {
    body.innerHTML = `<tr><td colspan="8">
      <div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <h3>No threats match your filters</h3>
        <p>Try adjusting your search or filters above.</p>
      </div>
    </td></tr>`;
    return;
  }

  const isAdmin = currentUser && currentUser.role === "admin";

  body.innerHTML = threats.map((t) => `
    <tr>
      <td class="mono">${escapeHtml(t.ioc_value)}</td>
      <td style="text-transform:capitalize">${escapeHtml(t.threat_type.replace(/_/g, " "))}</td>
      <td>${severityBadge(t.severity)}</td>
      <td>${t.confidence_score}%</td>
      <td>
        <select class="status-select" data-id="${t.id}" style="padding:6px 10px;font-size:12.5px;width:auto;">
          <option value="active" ${t.status === "active" ? "selected" : ""}>Active</option>
          <option value="investigating" ${t.status === "investigating" ? "selected" : ""}>Investigating</option>
          <option value="resolved" ${t.status === "resolved" ? "selected" : ""}>Resolved</option>
        </select>
      </td>
      <td class="cell-muted">${escapeHtml(t.source || "—")}</td>
      <td class="cell-muted">${formatDate(t.detected_at)}</td>
      <td>
        <div class="table-actions">
          ${isAdmin ? `<button class="btn btn-icon btn-danger delete-btn" data-id="${t.id}" title="Delete">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 011-1h4a1 1 0 011 1v2"/></svg>
          </button>` : ""}
        </div>
      </td>
    </tr>
  `).join("");

  body.querySelectorAll(".status-select").forEach((sel) => {
    sel.addEventListener("change", async () => {
      const id = sel.getAttribute("data-id");
      try {
        await API.put(`/api/threats/${id}`, { status: sel.value });
        showToast("Status updated.");
      } catch (err) {
        showToast(err.message || "Could not update status.", "error");
      }
    });
  });

  body.querySelectorAll(".delete-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-id");
      if (!confirm("Delete this threat? This cannot be undone.")) return;
      try {
        await API.del(`/api/threats/${id}`);
        showToast("Threat deleted.");
        loadThreats();
      } catch (err) {
        showToast(err.message || "Could not delete threat.", "error");
      }
    });
  });
}

function renderPagination(data) {
  document.getElementById("paginationInfo").textContent =
    `Showing page ${data.page} of ${data.total_pages || 1} — ${data.total} total threats`;

  const container = document.getElementById("paginationButtons");
  const totalPages = data.total_pages || 1;
  let html = `<button class="page-btn" id="prevPageBtn" ${data.page <= 1 ? "disabled" : ""}>‹</button>`;

  const start = Math.max(1, data.page - 2);
  const end = Math.min(totalPages, start + 4);
  for (let p = start; p <= end; p++) {
    html += `<button class="page-btn ${p === data.page ? "active" : ""}" data-page="${p}">${p}</button>`;
  }
  html += `<button class="page-btn" id="nextPageBtn" ${data.page >= totalPages ? "disabled" : ""}>›</button>`;
  container.innerHTML = html;

  const prevBtn = document.getElementById("prevPageBtn");
  const nextBtn = document.getElementById("nextPageBtn");
  if (prevBtn) prevBtn.addEventListener("click", () => { currentPage--; loadThreats(); });
  if (nextBtn) nextBtn.addEventListener("click", () => { currentPage++; loadThreats(); });
  container.querySelectorAll("[data-page]").forEach((btn) => {
    btn.addEventListener("click", () => {
      currentPage = parseInt(btn.getAttribute("data-page"), 10);
      loadThreats();
    });
  });
}

async function loadThreats() {
  const body = document.getElementById("threatsBody");
  body.innerHTML = `<tr><td colspan="8"><div class="loading-row"><div class="spinner"></div> Loading…</div></td></tr>`;
  try {
    const data = await API.get(`/api/threats?${buildQuery()}`);
    renderRows(data.threats);
    renderPagination(data);
  } catch (err) {
    showToast(err.message || "Could not load threats.", "error");
  }
}

function wireFilters() {
  document.getElementById("searchInput").addEventListener("input", () => {
    clearTimeout(searchDebounceTimer);
    searchDebounceTimer = setTimeout(() => { currentPage = 1; loadThreats(); }, 350);
  });
  ["severityFilter", "typeFilter", "statusFilter"].forEach((id) => {
    document.getElementById(id).addEventListener("change", () => { currentPage = 1; loadThreats(); });
  });
}

function wireAddModal() {
  const overlay = document.getElementById("addModalOverlay");
  const openBtn = document.getElementById("openAddModalBtn");
  const closeBtn = document.getElementById("closeAddModalBtn");
  const cancelBtn = document.getElementById("cancelAddModalBtn");
  const form = document.getElementById("addThreatForm");
  const alertBox = document.getElementById("addThreatAlert");
  const submitBtn = document.getElementById("submitAddThreatBtn");

  const open = () => { overlay.classList.add("open"); alertBox.classList.add("hidden"); };
  const close = () => { overlay.classList.remove("open"); form.reset(); };

  openBtn.addEventListener("click", open);
  closeBtn.addEventListener("click", close);
  cancelBtn.addEventListener("click", close);
  overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      ioc_value: document.getElementById("ioc_value").value.trim(),
      ioc_type: document.getElementById("ioc_type").value,
      threat_type: document.getElementById("threat_type").value,
      severity: document.getElementById("severity").value,
      confidence_score: parseInt(document.getElementById("confidence_score").value, 10) || 50,
      source: document.getElementById("source").value.trim() || "Manual Entry",
      description: document.getElementById("description").value.trim(),
    };
    if (!payload.ioc_value) {
      alertBox.textContent = "IOC value is required.";
      alertBox.classList.remove("hidden");
      return;
    }
    submitBtn.disabled = true;
    submitBtn.textContent = "Adding…";
    try {
      await API.post("/api/threats", payload);
      showToast("Threat added.");
      close();
      currentPage = 1;
      loadThreats();
    } catch (err) {
      alertBox.textContent = err.message || "Could not add threat.";
      alertBox.classList.remove("hidden");
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = "Add threat";
    }
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  currentUser = await initNav();
  if (!currentUser) return;
  wireFilters();
  wireAddModal();
  loadThreats();
});
