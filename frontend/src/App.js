import React, { useState, useEffect } from "react";
import jsPDF from "jspdf";

const API_BASE = process.env.REACT_APP_API_URL || "http://localhost:8000/api";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [scanStatus, setScanStatus] = useState("");
  const [history, setHistory] = useState([]);
  const [error, setError] = useState(null);

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  useEffect(() => {
    const saved = JSON.parse(localStorage.getItem("scanHistory")) || [];
    setHistory(saved);
  }, []);

  const saveToHistory = (url, data) => {
    const newEntry = {
      id: Date.now(),
      url,
      score: data.score,
      grade: data.grade,
      time: new Date().toLocaleString(),
      full: data,
    };

    const updated = [newEntry, ...history].slice(0, 10);
    setHistory(updated);
    localStorage.setItem("scanHistory", JSON.stringify(updated));
  };

  const handleScan = async () => {
    setError(null);
    setLoading(true);
    setScanStatus("QUEUED");
    setResult(null);

    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      if (!res.ok) {
        throw new Error(`Scan API failed (${res.status})`);
      }

      const data = await res.json();
      let statusData = { status: "QUEUED" };

      while (statusData.status === "QUEUED" || statusData.status === "SCANNING") {
        await sleep(1500);
        const statusRes = await fetch(`${API_BASE}/scan/${data.scan_id}/status`);
        if (!statusRes.ok) {
          throw new Error(`Status API failed (${statusRes.status})`);
        }
        statusData = await statusRes.json();
        setScanStatus(statusData.status);
      }

      if (statusData.status === "FAILED") {
        throw new Error(statusData.error || "Scan task failed");
      }

      const resultRes = await fetch(`${API_BASE}/result/${data.scan_id}`);
      if (!resultRes.ok) {
        throw new Error(`Result API failed (${resultRes.status})`);
      }

      const resultData = await resultRes.json();
      setResult(resultData);
      saveToHistory(url, resultData);
    } catch (err) {
      setError(err.message);
      console.error(err);
    } finally {
      setLoading(false);
      setScanStatus("");
    }
  };

  const getColor = (score) => {
    if (score >= 90) return "#22c55e";
    if (score >= 75) return "#f59e0b";
    if (score >= 50) return "#f97316";
    return "#ef4444";
  };

  const generatePDF = () => {
    if (!result) return;
    const doc = new jsPDF();
    doc.setFontSize(18);
    doc.text("VulnScan Lite Report", 14, 22);
    doc.setFontSize(12);
    doc.text(`URL: ${result.scanned_url}`, 14, 34);
    doc.text(`Score: ${result.score}`, 14, 44);
    doc.text(`Grade: ${result.grade}`, 14, 52);
    doc.text("Passed Checks:", 14, 64);
    result.checks.passed.forEach((item, idx) => doc.text(`- ${item}`, 14, 72 + idx * 8));
    const start = 72 + result.checks.passed.length * 8 + 8;
    doc.text("Failed Checks:", 14, start);
    result.checks.failed.forEach((item, idx) => doc.text(`- ${item}`, 14, start + 8 + idx * 8));
    doc.save("vulnscan-lite-report.pdf");
  };

  return (
    <div style={{ background: "#0b1120", minHeight: "100vh", color: "#f8fafc", padding: 24, fontFamily: "Inter, sans-serif" }}>
      <div style={{ maxWidth: 980, margin: "0 auto" }}>
        <header style={{ textAlign: "center", marginBottom: 24 }}>
          <h1 style={{ margin: 0, fontSize: 44 }}>VulnScan Lite</h1>
          <p style={{ margin: "12px auto", maxWidth: 720, color: "#cbd5e1" }}>
            A lightweight web security posture scanner for passive analysis. Only scan sites you own or have authorization to test.
          </p>
        </header>

        <section style={{ background: "#111827", borderRadius: 20, padding: 24, marginBottom: 24, boxShadow: "0 20px 60px rgba(15, 23, 42, 0.35)" }}>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", justifyContent: "center" }}>
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL to scan (example.com)"
              style={{ flex: "1 1 320px", padding: 14, borderRadius: 12, border: "1px solid #334155", background: "#0f172a", color: "#f8fafc" }}
            />
            <button
              onClick={handleScan}
              disabled={loading || !url.trim()}
              style={{ padding: "14px 22px", borderRadius: 12, border: "none", background: "#38bdf8", color: "#020617", fontWeight: 700, cursor: loading || !url.trim() ? "not-allowed" : "pointer" }}
            >
              {loading ? "Scanning..." : "Start Scan"}
            </button>
          </div>
          <p style={{ marginTop: 16, color: "#94a3b8" }}>
            Backend endpoint: <strong>{API_BASE}</strong>
          </p>
          {error && <div style={{ marginTop: 12, color: "#fecaca" }}>Error: {error}</div>}
          {scanStatus && <div style={{ marginTop: 12, color: "#fef08a" }}>Status: {scanStatus}</div>}
        </section>

        {result && (
          <section style={{ display: "grid", gridTemplateColumns: "1fr 360px", gap: 24, marginBottom: 24 }}>
            <div style={{ background: "#111827", borderRadius: 20, padding: 24, boxShadow: "0 20px 60px rgba(15, 23, 42, 0.35)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
                <div>
                  <p style={{ margin: 0, color: "#94a3b8", fontSize: 14 }}>Report for</p>
                  <h2 style={{ margin: "8px 0 0", fontSize: 24 }}>{result.scanned_url}</h2>
                </div>
                <button onClick={generatePDF} style={{ background: "#22c55e", color: "#020617", border: "none", borderRadius: 10, padding: "10px 14px", fontWeight: 700, cursor: "pointer" }}>
                  Export PDF
                </button>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>
                <div style={{ background: "#0f172a", borderRadius: 16, padding: 18 }}>
                  <p style={{ margin: 0, color: "#94a3b8" }}>Score</p>
                  <p style={{ margin: "8px 0 0", fontSize: 32, fontWeight: 700, color: getColor(result.score) }}>{result.score}</p>
                </div>
                <div style={{ background: "#0f172a", borderRadius: 16, padding: 18 }}>
                  <p style={{ margin: 0, color: "#94a3b8" }}>Grade</p>
                  <p style={{ margin: "8px 0 0", fontSize: 32, fontWeight: 700 }}>{result.grade}</p>
                </div>
              </div>

              <div style={{ display: "grid", gap: 18 }}>
                <div style={{ background: "#0f172a", borderRadius: 16, padding: 18 }}>
                  <h3 style={{ margin: 0, color: "#e2e8f0" }}>Security Headers</h3>
                  <p style={{ margin: "12px 0 0", color: "#94a3b8" }}><strong>Passed:</strong> {result.headers.passed.join(", ") || "None"}</p>
                  <p style={{ margin: "8px 0 0", color: "#fca5a5" }}><strong>Failed:</strong> {result.headers.failed.join(", ") || "None"}</p>
                </div>
                <div style={{ background: "#0f172a", borderRadius: 16, padding: 18 }}>
                  <h3 style={{ margin: 0, color: "#e2e8f0" }}>TLS / SSL</h3>
                  <p style={{ margin: "12px 0 0", color: "#94a3b8" }}>Protocol: {result.ssl.protocol || "n/a"}</p>
                  <p style={{ margin: "8px 0 0", color: "#94a3b8" }}>Cipher: {result.ssl.cipher || "n/a"}</p>
                  <p style={{ margin: "8px 0 0", color: "#94a3b8" }}>Expires: {result.ssl.expiry_date || "n/a"}</p>
                </div>
                <div style={{ background: "#0f172a", borderRadius: 16, padding: 18 }}>
                  <h3 style={{ margin: 0, color: "#e2e8f0" }}>CMS Detection</h3>
                  <p style={{ margin: "12px 0 0", color: "#94a3b8" }}>Platform: {result.cms.cms}</p>
                  <p style={{ margin: "8px 0 0", color: "#94a3b8" }}>Version: {result.cms.version || "Unknown"}</p>
                </div>
                <div style={{ background: "#0f172a", borderRadius: 16, padding: 18 }}>
                  <h3 style={{ margin: 0, color: "#e2e8f0" }}>Remediation</h3>
                  {Object.keys(result.remediation).length > 0 ? (
                    Object.entries(result.remediation).map(([key, value]) => (
                      <p key={key} style={{ margin: "10px 0 0", color: "#cbd5e1" }}><strong>{key}:</strong> {value}</p>
                    ))
                  ) : (
                    <p style={{ marginTop: 12, color: "#86efac" }}>No remediation issues found.</p>
                  )}
                </div>
              </div>
            </div>

            <div style={{ background: "#111827", borderRadius: 20, padding: 24, boxShadow: "0 20px 60px rgba(15, 23, 42, 0.35)" }}>
              <h3 style={{ marginTop: 0 }}>Latest Scan</h3>
              <div style={{ width: "100%", height: 320, borderRadius: 22, background: "radial-gradient(circle at top, rgba(56, 189, 248, 0.14), transparent 40%), #0f172a", display: "grid", placeItems: "center" }}>
                <div style={{ width: 220, height: 220, borderRadius: "50%", background: `conic-gradient(${getColor(result.score)} ${result.score * 3.6}deg, #2e3a59 0deg)`, display: "grid", placeItems: "center" }}>
                  <div style={{ width: 172, height: 172, borderRadius: "50%", background: "#0f172a", display: "grid", placeItems: "center" }}>
                    <div style={{ textAlign: "center" }}>
                      <p style={{ margin: 0, color: "#94a3b8", fontSize: 14 }}>Health</p>
                      <p style={{ margin: "8px 0 0", fontSize: 40, fontWeight: 700, color: getColor(result.score) }}>{result.score}</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>
        )}

        {history.length > 0 && (
          <section style={{ background: "#111827", borderRadius: 20, padding: 24, boxShadow: "0 20px 60px rgba(15, 23, 42, 0.35)" }}>
            <h3 style={{ marginTop: 0 }}>Scan History</h3>
            <div style={{ display: "grid", gap: 12 }}>
              {history.map((entry) => (
                <div
                  key={entry.id}
                  onClick={() => setResult(entry.full)}
                  style={{
                    background: "#0f172a",
                    borderRadius: 16,
                    padding: 16,
                    color: "#cbd5e1",
                    cursor: "pointer",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap" }}>
                    <div>
                      <p style={{ margin: "0 0 4px" }}><strong>{entry.url}</strong></p>
                      <p style={{ margin: 0, color: "#94a3b8" }}>{entry.time}</p>
                    </div>
                    <div style={{ textAlign: "right" }}>
                      <p style={{ margin: 0, fontWeight: 700, color: getColor(entry.score) }}>{entry.score}</p>
                      <p style={{ margin: 0, color: "#cbd5e1" }}>{entry.grade}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}
      </div>
    </div>
  );
}

export default App;
