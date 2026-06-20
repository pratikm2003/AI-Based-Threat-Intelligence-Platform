/**
 * nav.js
 * -------
 * Shared by every protected page (dashboard/threats/analyzer/reports):
 *  - Confirms the user is logged in (GET /api/auth/me) and redirects to
 *    the login page if not - this is the "auth guard" for the SPA-ish
 *    multi-page frontend.
 *  - Fills in the sidebar user card (avatar initials, name, role).
 *  - Highlights the current page's nav link.
 *  - Wires up the logout button and the mobile sidebar toggle.
 *  - Hides any element marked [data-role="admin"] for non-admin users.
 */

async function initNav() {
  let me;
  try {
    const res = await API.get("/api/auth/me");
    me = res.user;
  } catch (err) {
    window.location.href = "index.html";
    return null;
  }

  // Sidebar user card
  const avatarEl = document.querySelector("[data-user-avatar]");
  const nameEl = document.querySelector("[data-user-name]");
  const roleEl = document.querySelector("[data-user-role]");
  if (avatarEl) avatarEl.textContent = me.username.slice(0, 2).toUpperCase();
  if (nameEl) nameEl.textContent = me.username;
  if (roleEl) roleEl.textContent = me.role;

  // Active nav link
  const currentPage = window.location.pathname.split("/").pop() || "dashboard.html";
  document.querySelectorAll(".nav-link").forEach((link) => {
    const href = link.getAttribute("href");
    if (href === currentPage) {
      link.classList.add("active");
    }
  });

  // Logout
  const logoutBtn = document.querySelector("[data-logout]");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", async () => {
      try {
        await API.post("/api/auth/logout");
      } catch (err) {
        /* ignore - we're leaving anyway */
      }
      window.location.href = "index.html";
    });
  }

  // Mobile sidebar toggle
  const toggleBtn = document.querySelector("[data-sidebar-toggle]");
  const sidebar = document.querySelector(".sidebar");
  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener("click", () => sidebar.classList.toggle("open"));
    document.querySelectorAll(".nav-link").forEach((link) => {
      link.addEventListener("click", () => sidebar.classList.remove("open"));
    });
  }

  // Role-gated elements (e.g. delete buttons, admin-only nav items)
  if (me.role !== "admin") {
    document.querySelectorAll('[data-role="admin"]').forEach((el) => {
      el.style.display = "none";
    });
  }

  return me;
}

function showToast(message, type = "success") {
  let stack = document.querySelector(".toast-stack");
  if (!stack) {
    stack = document.createElement("div");
    stack.className = "toast-stack";
    document.body.appendChild(stack);
  }
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  stack.appendChild(toast);
  setTimeout(() => toast.remove(), 3800);
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatDateTime(isoLike) {
  if (!isoLike) return "—";
  // SQLite returns "YYYY-MM-DD HH:MM:SS" (UTC, no offset marker)
  const iso = isoLike.includes("T") ? isoLike : isoLike.replace(" ", "T") + "Z";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return isoLike;
  return d.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function formatDate(isoLike) {
  if (!isoLike) return "—";
  const iso = isoLike.includes("T") ? isoLike : isoLike.replace(" ", "T") + "Z";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return isoLike;
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

// Note: initNav() is intentionally NOT auto-invoked here. Each page's own
// script (dashboard.js, threats.js, analyzer.js, reports.js) calls it
// explicitly inside its own DOMContentLoaded handler, so it can wait for
// the resolved user object before loading page-specific data.
