const form = document.getElementById("scan-form");
const input = document.getElementById("url-input");
const scanButton = document.getElementById("scan-button");
const resultCard = document.getElementById("result-card");
const errorBox = document.getElementById("error-box");

function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove("hidden");
}
function clearError() {
  errorBox.textContent = "";
  errorBox.classList.add("hidden");
}
function setLoading(loading) {
  scanButton.disabled = loading;
  scanButton.querySelector("span:first-child").textContent = loading ? "Scanning..." : "Scan URL";
}
function renderResult(data) {
  resultCard.classList.remove("hidden");
  document.getElementById("verdict-title").textContent = data.verdict;
  document.getElementById("risk-score").textContent = data.risk_score;
  document.getElementById("scanned-url").textContent = data.url;
  document.getElementById("ml-score").textContent = `${data.ml_score}%`;
  document.getElementById("rule-score").textContent = `${data.rule_score}/100`;
  document.getElementById("disclaimer").textContent = data.disclaimer;

  const ring = document.getElementById("risk-ring");
  const fill = document.getElementById("score-fill");
  const colors = { low: "var(--green)", medium: "var(--orange)", high: "var(--red)" };
  ring.style.borderColor = colors[data.level];
  document.getElementById("verdict-title").style.color = colors[data.level];
  fill.style.width = `${data.risk_score}%`;
  fill.style.background = colors[data.level];

  const list = document.getElementById("reason-list");
  list.replaceChildren();
  data.reasons.forEach((reason) => {
    const item = document.createElement("li");
    item.textContent = reason;
    list.appendChild(item);
  });
}
function renderHistory(items) {
  const container = document.getElementById("history-list");
  container.replaceChildren();
  if (!items.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No scans yet. Check a URL to get started.";
    container.appendChild(empty);
    return;
  }
  items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "history-item";

    const left = document.createElement("div");
    const url = document.createElement("div");
    url.className = "history-url";
    url.textContent = item.url;
    url.title = item.url;
    const time = document.createElement("div");
    time.className = "history-time";
    time.textContent = new Date(item.scanned_at).toLocaleString();
    left.append(url, time);

    const right = document.createElement("div");
    right.className = "history-right";
    const score = document.createElement("span");
    score.className = "history-score";
    score.textContent = `${item.risk_score}/100`;
    const pill = document.createElement("span");
    pill.className = `pill ${item.level}`;
    pill.textContent = item.verdict;
    right.append(score, pill);
    row.append(left, right);
    container.appendChild(row);
  });
}
async function loadHistory() {
  try {
    const response = await fetch("/api/history");
    const data = await response.json();
    renderHistory(data.history || []);
    document.getElementById("stat-total").textContent = data.stats.total;
    document.getElementById("stat-high").textContent = data.stats.high_risk;
    document.getElementById("stat-medium").textContent = data.stats.suspicious;
  } catch {
    // The scanner remains usable; history can refresh on the next page load.
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError();
  resultCard.classList.add("hidden");
  setLoading(true);
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: input.value })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Unable to scan this URL.");
    renderResult(data);
    await loadHistory();
  } catch (error) {
    showError(error.message || "Could not connect to PhishShield. Is the Flask server running?");
  } finally {
    setLoading(false);
  }
});

document.querySelectorAll(".sample").forEach((button) => {
  button.addEventListener("click", () => {
    input.value = button.dataset.url;
    input.focus();
  });
});

document.getElementById("clear-history").addEventListener("click", async () => {
  if (!confirm("Clear all saved scan history?")) return;
  try {
    await fetch("/api/history/clear", { method: "POST" });
    await loadHistory();
  } catch {
    showError("Could not clear scan history.");
  }
});

loadHistory();
