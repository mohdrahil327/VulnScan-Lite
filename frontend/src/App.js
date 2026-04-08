import React, { useState, useEffect } from "react";
import jsPDF from 'jspdf';

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [scanStatus, setScanStatus] = useState("");
  const [history, setHistory] = useState([]);

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  // Load history from localStorage
  useEffect(() => {
    const saved = JSON.parse(localStorage.getItem("scanHistory")) || [];
    setHistory(saved);
  }, []);

  // Save history
  const saveToHistory = (url, data) => {
    const newEntry = {
      url,
      score: data.score,
      grade: data.grade,
      time: new Date().toLocaleString(),
      full: data
    };

    const updated = [newEntry, ...history];
    setHistory(updated);
    localStorage.setItem("scanHistory", JSON.stringify(updated));
  };

  const handleScan = async () => {
    setLoading(true);
    setScanStatus("SCANNING");
    setResult(null);

    try {
      const res = await fetch("http://localhost:8000/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ url })
      });

      if (!res.ok) throw new Error(`Scan API failed (${res.status})`);
      const data = await res.json();

      let statusData = { status: "SCANNING" };
      while (statusData.status === "SCANNING") {
        await sleep(1500);
        const statusRes = await fetch(`http://localhost:8000/scan/${data.scan_id}/status`);
        if (!statusRes.ok) throw new Error(`Status API failed (${statusRes.status})`);
        statusData = await statusRes.json();
        setScanStatus(statusData.status);
      }

      if (statusData.status === "FAILED") {
        alert(`Scan failed: ${statusData.error || "unknown error"}`);
        setLoading(false);
        return;
      }

      const resultRes = await fetch(`http://localhost:8000/result/${data.scan_id}`);
      const resultData = await resultRes.json();

      setResult(resultData);
      saveToHistory(url, resultData);

    } catch (err) {
      alert("Error connecting to backend: " + err.message);
      console.error(err);

    } finally {
      setLoading(false);
      setScanStatus("");
    }
  };

  const getColor = (score) => {
    if (score > 80) return "#00ff00";
    if (score > 50) return "#ffa500";
    return "#ff0000";
  };

  const generatePDF = () => {
    const doc = new jsPDF();
    doc.setFontSize(20);
    doc.text('Scanlite Security Report', 10, 20);
    doc.setFontSize(14);
    doc.text(`URL: ${url}`, 10, 40);
    doc.text(`Security Score: ${result.score}`, 10, 50);
    doc.text(`Grade: ${result.grade}`, 10, 60);
    doc.text('Security Headers:', 10, 80);
    doc.text(`Passed: ${result.headers.passed.join(', ') || 'None'}`, 10, 90);
    doc.text(`Failed: ${result.headers.failed.join(', ') || 'None'}`, 10, 100);
    doc.text(`SSL Expiry: ${result.ssl.expiry_date}`, 10, 120);
    doc.text(`CMS: ${result.cms.cms}`, 10, 130);
    if (result.remediation && Object.keys(result.remediation).length > 0) {
      doc.text('Fix Suggestions:', 10, 150);
      let y = 160;
      Object.entries(result.remediation).forEach(([key, value]) => {
        doc.text(`${key}: ${value}`, 10, y);
        y += 10;
      });
    }
    doc.save('scanlite-report.pdf');
  };

  return (
    <div style={{
      backgroundColor: "#0f172a",
      color: "white",
      minHeight: "100vh",
      padding: "20px",
      fontFamily: "Arial"
    }}>
      <h1 style={{ textAlign: "center" }}>🔍 Scanlite</h1>
      <p style={{ textAlign: "center", color: "#e2e8f0" }}><strong>Disclaimer:</strong> Only scan websites you own or have permission to test; this tool performs only passive metadata analysis.</p>
      {scanStatus && <p style={{ textAlign: "center", color: "#ffea00" }}>Status: {scanStatus}</p>}

      {/* INPUT */}
      <div style={{ textAlign: "center", marginBottom: "20px" }}>
        <input
          type="text"
          placeholder="Enter URL (https://...)"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          style={{ padding: "10px", width: "300px", borderRadius: "5px" }}
        />
        <button
          onClick={handleScan}
          style={{ padding: "10px", marginLeft: "10px", borderRadius: "5px" }}
        >
          Scan
        </button>
      </div>

      {loading && <p style={{ textAlign: "center" }}>⏳ Scanning...</p>}

      {/* RESULT */}
      {result && (
        <div style={{
          background: "#1e293b",
          padding: "20px",
          borderRadius: "12px",
          maxWidth: "500px",
          margin: "auto"
        }}>
          <div style={{ textAlign: "center", marginBottom: "20px" }}>
            <div style={{
              width: "200px",
              height: "200px",
              borderRadius: "50%",
              border: `15px solid ${getColor(result.score)}`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              margin: "auto",
              fontSize: "30px",
              fontWeight: "bold"
            }}>
              {result.score}
            </div>
            <p>Security Score</p>
          </div>

          <h3 style={{ textAlign: "center" }}>Grade: {result.grade}</h3>

          <h4>🔐 Security Headers</h4>
          <p>✅ Passed: {result.headers.passed.join(", ") || "None"}</p>
          <p>❌ Failed: {result.headers.failed.join(", ") || "None"}</p>

          <h4>🔒 SSL</h4>
          <p>{result.ssl.expiry_date}</p>

          <h4>⚙️ CMS</h4>
          <p>{result.cms.cms}</p>
          <h4>🛠️ Fix Suggestions</h4>

{result && result.remediation ? (
  Object.keys(result.remediation).length > 0 ? (
    Object.entries(result.remediation).map(([key, value], index) => (
      <p key={index}>
        ❌ <strong>{key}:</strong> {value}
      </p>
    ))
  ) : (
    <p>✅ No major issues found</p>
  )
) : (
  <p>⏳ No data</p>
)}

          <button
            onClick={generatePDF}
            style={{
              padding: "10px",
              marginTop: "20px",
              borderRadius: "5px",
              backgroundColor: "#4CAF50",
              color: "white",
              border: "none",
              cursor: "pointer"
            }}
          >
            📄 Download PDF Report
          </button>
        </div>
      )}

      {/* 🔥 HISTORY SECTION */}
      <div style={{ marginTop: "40px" }}>
        <h2>📜 Scan History</h2>

        {history.length === 0 && <p>No scans yet</p>}

        {history.map((item, index) => (
          <div
            key={index}
            onClick={() => setResult(item.full)}
            style={{
              background: "#1e293b",
              padding: "10px",
              marginBottom: "10px",
              borderRadius: "8px",
              cursor: "pointer"
            }}
          >
            <p><strong>{item.url}</strong></p>
            <p>Score: {item.score} | Grade: {item.grade}</p>
            <small>{item.time}</small>
          </div>
        ))}
      </div>
    </div>
  );
}

export default App;