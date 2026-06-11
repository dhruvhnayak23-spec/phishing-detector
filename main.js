// ── DOM refs ──────────────────────────────────────────────────
const urlInput      = document.getElementById("urlInput");
const analyzeBtn    = document.getElementById("analyzeBtn");
const loadingState  = document.getElementById("loadingState");
const resultsSection= document.getElementById("resultsSection");

// ── Quick test chips ──────────────────────────────────────────
document.querySelectorAll(".qt-chip").forEach(chip => {
  chip.addEventListener("click", () => {
    urlInput.value = chip.dataset.url;
    urlInput.focus();
    runAnalysis();
  });
});

// ── Analyze button ────────────────────────────────────────────
analyzeBtn.addEventListener("click", runAnalysis);

urlInput.addEventListener("keydown", e => {
  if (e.key === "Enter") runAnalysis();
});

// ── Main function ─────────────────────────────────────────────
async function runAnalysis() {
  const url = urlInput.value.trim();
  if (!url) {
    urlInput.style.borderColor = "var(--danger)";
    setTimeout(() => (urlInput.style.borderColor = ""), 1200);
    return;
  }

  setLoading(true);
  resultsSection.classList.add("hidden");

  try {
    const res = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    const data = await res.json();

    if (data.error) {
      alert(data.error);
      return;
    }

    renderResults(data);
  } catch (err) {
    alert("Something went wrong. Is the Flask server running?");
    console.error(err);
  } finally {
    setLoading(false);
  }
}

// ── Render results ────────────────────────────────────────────
function renderResults(data) {
  const color = data.verdict.color;

  // Verdict banner
  const banner = document.getElementById("verdictBanner");
  banner.className = `verdict-banner ${color}`;
  document.getElementById("verdictEmoji").textContent  = data.verdict.emoji;
  document.getElementById("verdictLabel").textContent  = data.verdict.label;

  // Score ring animation
  const score    = data.score;
  const arc      = document.getElementById("scoreArc");
  const circumference = 201; // 2 * pi * r (r=32)
  const offset   = circumference - (score / 100) * circumference;
  arc.style.strokeDashoffset = offset;
  document.getElementById("scoreNumber").textContent = score;

  // Info cards
  document.getElementById("infoDomain").textContent   = data.domain   || "—";
  document.getElementById("infoProtocol").textContent = data.protocol || "—";
  document.getElementById("infoLength").textContent   = data.url_length + " chars";

  // Flags
  const flagsList = document.getElementById("flagsList");
  flagsList.innerHTML = "";
  if (!data.flags || data.flags.length === 0) {
    flagsList.innerHTML = `<p style="color:var(--text-muted);font-size:0.84rem;">No flags generated.</p>`;
  } else {
    data.flags.forEach(flag => {
      const icon = flag.type === "safe" ? "✅" : flag.type === "warn" ? "⚠️" : "❌";
      const el = document.createElement("div");
      el.className = `flag-item ${flag.type}`;
      el.innerHTML = `<span class="flag-icon">${icon}</span><span class="flag-msg">${escapeHtml(flag.msg)}</span>`;
      flagsList.appendChild(el);
    });
  }

  // Details table
  const tbody = document.getElementById("detailsBody");
  tbody.innerHTML = "";

  const featureLabels = {
    "Has HTTPS":          { good: true,  label: "Has HTTPS" },
    "IP Address Used":    { good: false, label: "IP Address Used" },
    "@ Symbol Present":   { good: false, label: "@ Symbol Present" },
    "Suspicious TLD":     { good: false, label: "Suspicious TLD" },
    "Hyphens in Domain":  { good: null,  label: "Hyphens in Domain" },
    "Dot Count":          { good: null,  label: "Dot Count" },
    "Subdomains":         { good: null,  label: "Subdomains" },
  };

  Object.entries(data.details).forEach(([key, value]) => {
    const meta = featureLabels[key] || { good: null, label: key };
    let badgeClass, badgeText;

    if (typeof value === "boolean") {
      if (meta.good === null) {
        badgeClass = "badge-neutral"; badgeText = value ? "Yes" : "No";
      } else if (meta.good) {
        badgeClass = value ? "badge-safe" : "badge-danger";
        badgeText  = value ? "Yes" : "No";
      } else {
        badgeClass = value ? "badge-danger" : "badge-safe";
        badgeText  = value ? "Yes" : "No";
      }
    } else {
      const num = parseInt(value);
      if (key === "Hyphens in Domain") {
        badgeClass = num >= 2 ? "badge-warn" : num === 0 ? "badge-safe" : "badge-neutral";
      } else if (key === "Dot Count") {
        badgeClass = num >= 4 ? "badge-warn" : "badge-neutral";
      } else if (key === "Subdomains") {
        badgeClass = num >= 2 ? "badge-warn" : "badge-neutral";
      } else {
        badgeClass = "badge-neutral";
      }
      badgeText = value;
    }

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${meta.label}</td>
      <td>${typeof value === "boolean" ? (value ? "true" : "false") : value}</td>
      <td><span class="badge ${badgeClass}">${badgeText}</span></td>
    `;
    tbody.appendChild(tr);
  });

  // Show results
  resultsSection.classList.remove("hidden");
  resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ── Helpers ───────────────────────────────────────────────────
function setLoading(state) {
  analyzeBtn.disabled = state;
  loadingState.classList.toggle("hidden", !state);
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
