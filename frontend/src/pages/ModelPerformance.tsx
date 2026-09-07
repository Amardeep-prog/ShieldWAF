import { useEffect, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { Layout } from "../components/Layout";
import { api } from "../lib/api";

export function ModelPerformance() {
  const [metrics, setMetrics] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [retraining, setRetraining] = useState(false);

  function load() {
    api.modelMetrics().then(setMetrics).catch((e) => setError(String(e)));
  }
  useEffect(load, []);

  async function retrain() {
    setRetraining(true);
    try {
      await api.retrain();
      load();
    } catch (e) {
      setError(String(e));
    } finally {
      setRetraining(false);
    }
  }

  if (error) {
    return <Layout title="Model Performance"><div className="note-box" style={{ borderLeftColor: "#b91c1c" }}>{error}</div></Layout>;
  }
  if (!metrics) {
    return <Layout title="Model Performance"><div className="empty-state">Loading model metrics...</div></Layout>;
  }

  const classes: string[] = metrics.classes;
  const cm: number[][] = metrics.confusion_matrix;
  const report = metrics.classification_report;

  const importanceData = Object.entries(metrics.feature_importances || {})
    .map(([name, imp]) => ({ name, importance: imp as number }))
    .sort((a, b) => b.importance - a.importance)
    .slice(0, 12);

  return (
    <Layout
      title="Model Performance"
      subtitle="Real precision/recall/F1, confusion matrix, and impurity-based feature importances computed on a genuine held-out test split."
    >
      <div className="note-box">{metrics.notes}</div>

      <div className="stat-grid">
        <div className="stat-tile tone-good">
          <div className="stat-label">MACRO ROC-AUC (RF, OVR)</div>
          <div className="stat-value">{metrics.roc_auc_macro_ovr?.toFixed(4)}</div>
        </div>
        <div className="stat-tile tone-good">
          <div className="stat-label">ANOMALY DETECTOR AUC</div>
          <div className="stat-value">{metrics.anomaly_detector?.benign_vs_attack_auc?.toFixed(4)}</div>
        </div>
        <div className="stat-tile">
          <div className="stat-label">TRAIN / TEST SPLIT</div>
          <div className="stat-value" style={{ fontSize: 18 }}>{metrics.n_train} / {metrics.n_test}</div>
        </div>
        <div className="stat-tile">
          <div className="stat-label">TRAINING TIME</div>
          <div className="stat-value">{metrics.train_seconds}s</div>
        </div>
      </div>

      <div className="panel" style={{ marginBottom: 20 }}>
        <div className="panel-header">
          <h3>Per-class precision / recall / F1</h3>
          <button className="btn" onClick={retrain} disabled={retraining}>
            {retraining ? "Retraining..." : "Retrain model"}
          </button>
        </div>
        <div className="panel-body" style={{ overflowX: "auto" }}>
          <table className="data-table">
            <thead><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1</th><th>Support</th></tr></thead>
            <tbody>
              {classes.map((c) => (
                <tr key={c}>
                  <td>{c}</td>
                  <td className="mono">{report[c].precision.toFixed(3)}</td>
                  <td className="mono">{report[c].recall.toFixed(3)}</td>
                  <td className="mono">{report[c]["f1-score"].toFixed(3)}</td>
                  <td className="mono">{report[c].support}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="two-col">
        <div className="panel">
          <div className="panel-header"><h3>Confusion matrix (rows = actual, cols = predicted)</h3></div>
          <div className="panel-body" style={{ overflowX: "auto" }}>
            <table className="data-table">
              <thead>
                <tr><th></th>{classes.map((c) => <th key={c}>{c.slice(0, 4)}</th>)}</tr>
              </thead>
              <tbody>
                {cm.map((row, i) => (
                  <tr key={i}>
                    <td><strong>{classes[i].slice(0, 4)}</strong></td>
                    {row.map((v, j) => (
                      <td key={j} className="mono"
                        style={{ background: i === j ? "#e6f4ea" : v > 0 ? "#fdecec" : undefined }}>
                        {v}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header"><h3>Top feature importances</h3></div>
          <div className="panel-body">
            <ResponsiveContainer width="100%" height={320}>
              <BarChart data={importanceData} layout="vertical" margin={{ left: 30 }}>
                <XAxis type="number" />
                <YAxis type="category" dataKey="name" width={120} fontSize={11} />
                <Tooltip />
                <Bar dataKey="importance" fill="#7a3b12" radius={[0, 2, 2, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </Layout>
  );
}
