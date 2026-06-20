/**
 * analyzer.js
 * ------------
 * Powers analyzer.html: the URL analyzer tab (POST /api/analyze/url),
 * the incident text classifier tab (POST /api/analyze/text), and the
 * shared recent-analyses history table (GET /api/analyze/history).
 */

function wireTabs() {
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(btn.getAttribute("data-tab")).classList.add("active");
    });
  });
}

function verdictMeta(verdict) {
  if (verdict === "malicious") {
    return {
      cls: "malicious",
      title: "Malicious",
      icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
    };
  }
  if (verdict === "suspicious") {
    return {
      cls: "suspicious",
      title: "Suspicious",
      icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>`,
    };
  }
  return {
    cls: "benign",
    title: "Benign",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
  };
}

function renderUrlResult(result) {
  const card = document.getElementById("urlResultCard");
  card.style.display = "block";

  const meta = verdictMeta(result.verdict);
  document.getElementById("urlVerdictBanner").innerHTML = `
    <div class="verdict-banner ${meta.cls}">
      <div class="verdict-icon">${meta.icon}</div>
      <div>
        <div class="verdict-title">${meta.title}</div>
        <div class="verdict-sub">${result.source === "threat_database" ? "Matched an existing record in the threat database" : "Scored by the trained URL classification model"}</div>
      </div>
    </div>
  `;

  const conf = result.confidence || 0;
  const fill = document.getElementById("urlConfidenceFill");
  fill.style.width = `${conf}%`;
  fill.className = `confidence-bar-fill ${meta.cls}`;
  document.getElementById("urlConfidenceLabel").textContent = `${conf.toFixed(1)}% confidence`;
  document.getElementById("urlSourceLabel").textContent =
    result.source === "threat_database" ? "Source: threat database" : "Source: AI model";

  const riskWrap = document.getElementById("urlRiskFactorsWrap");
  const riskList = document.getElementById("urlRiskFactors");
  if (result.risk_factors && result.risk_factors.length) {
    riskWrap.style.display = "block";
    riskList.innerHTML = result.risk_factors.map((rf) => `
      <div class="risk-factor-item">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <span>${escapeHtml(rf)}</span>
      </div>
    `).join("");
  } else {
    riskWrap.style.display = "none";
  }

  const featuresWrap = document.getElementById("urlFeaturesWrap");
  const featuresGrid = document.getElementById("urlFeatures");
  if (result.features) {
    const keyFeatures = ["url_length", "num_dots", "has_https", "num_digits",
                           "suspicious_word_count", "entropy", "has_ip", "is_shortener"];
    featuresWrap.style.display = "block";
    featuresGrid.innerHTML = keyFeatures
      .filter((k) => k in result.features)
      .map((k) => `
        <div class="feature-chip">
          <span class="fc-label">${escapeHtml(k.replace(/_/g, " "))}</span>
          <span class="fc-value">${typeof result.features[k] === "number" ? result.features[k] : (result.features[k] ? "Yes" : "No")}</span>
        </div>
      `).join("");
  } else {
    featuresWrap.style.display = "none";
  }
}

async function handleUrlSubmit(e) {
  e.preventDefault();
  const input = document.getElementById("urlInput");
  const btn = document.getElementById("urlSubmitBtn");
  if (!input.value.trim()) return;

  btn.disabled = true;
  btn.textContent = "Analyzing…";
  try {
    const { result } = await API.post("/api/analyze/url", { url: input.value.trim() });
    renderUrlResult(result);
    loadHistory();
  } catch (err) {
    showToast(err.message || "Analysis failed.", "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Analyze";
  }
}

function renderTextResult(result) {
  const card = document.getElementById("textResultCard");
  card.style.display = "block";

  const badge = document.getElementById("textPredictedBadge");
  badge.textContent = result.predicted_category.replace(/_/g, " ");
  badge.className = "badge badge-high";
  badge.style.textTransform = "capitalize";

  document.getElementById("textConfidenceLabel").textContent = `${result.confidence.toFixed(1)}% confidence`;

  const barsWrap = document.getElementById("textCategoryBars");
  const top = result.top_categories || [];
  barsWrap.innerHTML = top.map((c) => `
    <div class="category-bar-row">
      <div class="cat-name">${escapeHtml(c.category.replace(/_/g, " "))}</div>
      <div class="cat-bar"><div class="cat-bar-fill" style="width:${c.probability}%"></div></div>
      <div class="cat-pct">${c.probability.toFixed(0)}%</div>
    </div>
  `).join("");

  document.getElementById("addAsTextThreatBtn").onclick = async () => {
    try {
      await API.post("/api/threats", {
        ioc_value: result.input.slice(0, 80),
        ioc_type: "domain",
        threat_type: result.predicted_category,
        severity: result.confidence >= 70 ? "high" : "medium",
        confidence_score: Math.round(result.confidence),
        source: "AI Analyzer",
        description: result.input,
      });
      showToast("Added to threat database.");
    } catch (err) {
      showToast(err.message || "Could not add threat.", "error");
    }
  };
}

async function handleTextSubmit(e) {
  e.preventDefault();
  const input = document.getElementById("textInput");
  const btn = document.getElementById("textSubmitBtn");
  if (!input.value.trim()) return;

  btn.disabled = true;
  btn.textContent = "Classifying…";
  try {
    const { result } = await API.post("/api/analyze/text", { description: input.value.trim() });
    renderTextResult(result);
    loadHistory();
  } catch (err) {
    showToast(err.message || "Classification failed.", "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Classify";
  }
}

function predictionBadgeClass(prediction) {
  if (["malicious"].includes(prediction)) return "badge-critical";
  if (["suspicious"].includes(prediction)) return "badge-medium";
  if (prediction === "benign") return "badge-low";
  return "badge-neutral";
}

async function loadHistory() {
  try {
    const { history } = await API.get("/api/analyze/history?limit=10");
    const body = document.getElementById("historyBody");
    if (!history.length) {
      body.innerHTML = `<tr><td colspan="6"><div class="empty-state"><p>No analyses yet — try the analyzer above.</p></div></td></tr>`;
      return;
    }
    body.innerHTML = history.map((h) => `
      <tr>
        <td class="mono" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(h.input_value)}</td>
        <td style="text-transform:capitalize">${escapeHtml(h.input_type)}</td>
        <td><span class="badge ${predictionBadgeClass(h.prediction)}">${escapeHtml(String(h.prediction).replace(/_/g, " "))}</span></td>
        <td>${Number(h.confidence).toFixed(1)}%</td>
        <td class="cell-muted">${escapeHtml(h.analyzed_by_username || "—")}</td>
        <td class="cell-muted">${formatDateTime(h.analyzed_at)}</td>
      </tr>
    `).join("");
  } catch (err) {
    showToast(err.message || "Could not load history.", "error");
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  const me = await initNav();
  if (!me) return;

  wireTabs();
  document.getElementById("urlForm").addEventListener("submit", handleUrlSubmit);
  document.getElementById("textForm").addEventListener("submit", handleTextSubmit);
  document.querySelectorAll("[data-sample-url]").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.getElementById("urlInput").value = btn.getAttribute("data-sample-url");
    });
  });

  loadHistory();
});
