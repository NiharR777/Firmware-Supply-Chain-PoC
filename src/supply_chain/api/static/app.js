const $ = (id) => document.getElementById(id);
let scenarios = [];
let reviewSubmitting = false;
let gateSubmitting = false;

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[c]));
}
async function api(url, options = {}) {
  const response = await fetch(url, {
    headers: {"Content-Type":"application/json", ...(options.headers || {})},
    ...options
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
  return data;
}
function sid() { return $("scenarioSelect").value; }
function updatePackage() {
  const selected = scenarios.find((item) => item.scenario_id === sid());
  $("packageId").value = selected?.package_id || "";
  loadWorkflow();
}
async function loadScenarios() {
  const data = await api("/api/scenarios");
  scenarios = data.scenarios.filter((item) => item.package_id);
  $("scenarioSelect").innerHTML = scenarios.map((item) =>
    `<option value="${esc(item.scenario_id)}">${esc(item.scenario_id)} · ${esc(item.package_id)} · ${esc(item.device_type || "Asset")}</option>`
  ).join("");
  $("scenarioCount").textContent = scenarios.length;
  updatePackage();
}
function renderResult(data) {
  $("assessmentResult").classList.remove("hidden");
  $("resultTitle").textContent = `${data.scenario_id} · ${data.decision.replace("_"," ").toUpperCase()}`;
  $("resultSub").textContent = `${data.package_id} · ${data.affected_assets?.[0]?.asset_name || "Asset"} · ${data.assessed_at}`;
  $("riskScore").textContent = data.risk_score;
  $("evidenceList").innerHTML = data.evidence_layers.map((item) =>
    `<div class="evidence-item"><div><strong>${esc(item.name)}</strong><small>${esc(item.detail)}</small></div><span class="status ${esc(item.status)}">${esc(item.status)}</span></div>`
  ).join("");
  const reasons = data.explanations.length ? data.explanations : ["No risk factors identified by configured deterministic rules."];
  $("reasonList").innerHTML = reasons.map((item) => `<li>${esc(item)}</li>`).join("");
  $("recommendation").textContent = data.recommended_actions.join(", ");
  $("workflowMessage").textContent = `Latest assessment: ${data.decision} · ${Number(data.assessment_duration_ms).toFixed(3)} ms`;
}
async function assess() {
  $("assessmentError").classList.add("hidden");
  $("assessBtn").disabled = true;
  try {
    const data = await api("/api/supply-chain/assess", {
      method:"POST", body:JSON.stringify({scenario_id:sid(), package_id:$("packageId").value})
    });
    renderResult(data);
    await refreshAll();
  } catch (error) {
    $("assessmentError").textContent = error.message;
    $("assessmentError").classList.remove("hidden");
  } finally { $("assessBtn").disabled = false; }
}
async function loadMetrics() {
  const data = await api("/api/metrics");
  $("assessmentCount").textContent = data.dashboard_assessments_recorded;
  $("medianLatency").textContent = data.median_latency_ms == null ? "—" : `${Number(data.median_latency_ms).toFixed(2)} ms`;
}
function renderKpi(prefix, item) {
  const value = item.value_percent;
  $(`${prefix}Value`).textContent = value == null ? "N/M" : `${value.toFixed(1)}%`;
  $(`${prefix}Bar`).style.width = value == null ? "0%" : `${Math.max(0, Math.min(100, value))}%`;
  $(`${prefix}Meta`).textContent = item.numerator == null ? item.basis : `${item.numerator} of ${item.denominator} bundles · ${item.basis}`;
}
async function loadPerformance() {
  const data = await api("/api/performance-dashboard");
  renderKpi("sbom", data.kpis.sbom_coverage);
  renderKpi("signature", data.kpis.signature_compliance);
  renderKpi("vex", data.kpis.vex_coverage);
  renderKpi("vendor", data.kpis.vendor_trust);
  $("dataBasis").textContent = `${data.data_basis}. Available bundles: ${data.scenario_bundles_available}.`;
  $("scopeNote").textContent = data.scope_note;
  const counts = data.vex_status_counts;
  $("vexCounts").innerHTML = [
    ["Affected",counts.affected],["Not affected",counts.not_affected],["Unknown / missing",counts.unknown_or_missing]
  ].map(([label,count]) => `<div class="count-row"><span>${esc(label)}</span><b>${count}</b></div>`).join("");
  $("notMeasuredRows").innerHTML = data.not_measured.map((item) =>
    `<tr><td><strong>${esc(item.metric)}</strong><span class="status review">NOT MEASURED</span></td><td>${esc(item.reason)}</td><td>${esc(item.document_target)}</td></tr>`
  ).join("");
}
async function loadWorkflow() {
  try {
    const data = await api("/api/workflow");
    const workflow = data.workflow[sid()];
    $("workflowState").textContent = workflow
      ? `${workflow.disposition} · Reviewer: ${workflow.reviewer} · ${workflow.recorded_at}${workflow.workflow_status ? " · " + workflow.workflow_status : ""}`
      : "No review recorded for this scenario in this dashboard yet.";
  } catch (error) { $("workflowState").textContent = error.message; }
}
async function saveReview() {
  if (reviewSubmitting) return;
  const reviewer = $("reviewer").value.trim();
  if (!reviewer) { $("workflowMessage").textContent = "Enter reviewer name or role."; return; }
  reviewSubmitting = true; $("saveReviewBtn").disabled = true;
  const oldText = $("saveReviewBtn").textContent; $("saveReviewBtn").textContent = "Saving review…";
  try {
    const data = await api(`/api/workflow/${sid()}/approval`, {
      method:"POST", body:JSON.stringify({reviewer, disposition:$("disposition").value, note:$("reviewNote").value})
    });
    $("workflowMessage").textContent = data.duplicate_submission
      ? `This identical review was already recorded for ${data.scenario_id}; no duplicate audit event was added.`
      : `Review recorded for ${data.scenario_id}. No real deployment is authorized.`;
    await refreshAll();
  } catch (error) { $("workflowMessage").textContent = error.message; }
  finally { reviewSubmitting = false; $("saveReviewBtn").disabled = false; $("saveReviewBtn").textContent = oldText; }
}
async function simulate() {
  if (gateSubmitting) return;
  gateSubmitting = true; $("simulateBtn").disabled = true;
  const oldText = $("simulateBtn").textContent; $("simulateBtn").textContent = "Evaluating gate…";
  try {
    const data = await api(`/api/workflow/${sid()}/simulate-release`, {method:"POST"});
    $("workflowMessage").textContent = data.message || "Simulated gate evaluated.";
  } catch (error) { $("workflowMessage").textContent = error.message; }
  finally { gateSubmitting = false; $("simulateBtn").disabled = false; $("simulateBtn").textContent = oldText; await refreshAll(); }
}
async function loadAudit() {
  const data = await api("/api/audit");
  $("auditRows").innerHTML = data.events.length ? data.events.map((item) => {
    let detail;
    if (item.event === "simulated_release_gate_evaluated") detail = `${item.outcome || ""} · ${item.reason || ""}`;
    else if (item.decision) detail = `${item.decision} · score ${item.risk_score} · ${item.duration_ms} ms`;
    else detail = `${item.disposition || item.workflow_status || ""} ${item.reviewer || ""}`;
    return `<tr><td>${esc(item.timestamp || item.recorded_at || "")}</td><td>${esc(item.event || "")}</td><td>${esc(item.scenario_id || "")}</td><td>${esc(detail)}</td></tr>`;
  }).join("") : '<tr><td colspan="4">No audit events recorded yet.</td></tr>';
}
async function refreshAll() {
  const results = await Promise.allSettled([loadMetrics(), loadPerformance(), loadWorkflow(), loadAudit()]);
  const failed = results.find((r) => r.status === "rejected");
  if (failed) console.error("Dashboard refresh issue:", failed.reason);
}
async function init() {
  try {
    await api("/api/health");
    $("apiStatus").textContent = "Connected";
    await loadScenarios();
    await refreshAll();
  } catch (error) {
    $("apiStatus").textContent = "Unavailable";
    $("assessmentError").textContent = error.message;
    $("assessmentError").classList.remove("hidden");
  }
}
$("scenarioSelect").addEventListener("change", updatePackage);
$("assessBtn").addEventListener("click", assess);
$("refreshBtn").addEventListener("click", async () => { await loadScenarios(); await refreshAll(); });
$("saveReviewBtn").addEventListener("click", saveReview);
$("simulateBtn").addEventListener("click", simulate);
init();
