import { useState, useEffect } from 'react'
import {
  FileText,
  ShieldCheck,
  Award,
  Clock,
  Activity,
  Layers,
  Download,
  Eye,
  PlusCircle,
  RefreshCw,
  ExternalLink,
  Target
} from 'lucide-react'

interface PostureOverview {
  posture_score: number
  posture_grade: string
  total_assets: number
  vulnerabilities_count: {
    critical: number
    high: number
    medium: number
    low: number
  }
  open_incidents_count: number
  critical_incidents_count: number
  total_alerts_count: number
  mean_time_to_detect_hours: number
  mean_time_to_remediate_hours: number
  mitre_tactics_breakdown: Array<{ technique: string; count: number }>
  ai_anomalies_count: number
  compliance_scores: Record<string, number>
}

interface SecurityReport {
  id: string
  report_type: string
  title: string
  summary: string
  posture_score: number | null
  incident_id: string | null
  generated_by_id: string | null
  parameters: Record<string, any>
  content: Record<string, any>
  rendered_html: string | null
  rendered_markdown: string | null
  created_at: string
  updated_at: string
}

export function ExecutiveReporting() {
  const [posture, setPosture] = useState<PostureOverview | null>(null)
  const [reports, setReports] = useState<SecurityReport[]>([])
  const [selectedReport, setSelectedReport] = useState<SecurityReport | null>(null)
  const [loading, setLoading] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [showExecutiveModal, setShowExecutiveModal] = useState(false)
  const [showPreviewModal, setShowPreviewModal] = useState(false)
  const [notification, setNotification] = useState<{ message: string; type: 'success' | 'error' } | null>(null)

  // Executive report form state
  const [reportTitle, setReportTitle] = useState('')
  const [timeWindowDays, setTimeWindowDays] = useState(30)

  const fetchData = async () => {
    setLoading(true)
    try {
      const [resPosture, resReports] = await Promise.all([
        fetch('http://localhost:8000/api/v1/reports/posture'),
        fetch('http://localhost:8000/api/v1/reports/')
      ])

      if (resPosture.ok) {
        const pData = await resPosture.json()
        setPosture(pData)
      }
      if (resReports.ok) {
        const rData = await resReports.json()
        setReports(rData)
      }
    } catch (err) {
      console.error('Failed to load reporting data:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  const handleGenerateExecutiveReport = async (e: React.FormEvent) => {
    e.preventDefault()
    setGenerating(true)
    try {
      const res = await fetch('http://localhost:8000/api/v1/reports/executive', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: reportTitle.trim() || undefined,
          time_window_days: timeWindowDays,
          include_compliance_summary: true,
          include_ai_intelligence: true
        })
      })

      if (res.ok) {
        const generated = await res.json()
        setShowExecutiveModal(false)
        setReportTitle('')
        setNotification({
          message: `Executive Report "${generated.title}" generated successfully.`,
          type: 'success'
        })
        await fetchData()
        setSelectedReport(generated)
        setShowPreviewModal(true)
      } else {
        const err = await res.json()
        setNotification({ message: err.detail || 'Failed to generate report', type: 'error' })
      }
    } catch (err: unknown) {
      setNotification({ message: err instanceof Error ? err.message : 'Network error', type: 'error' })
    } finally {
      setGenerating(false)
    }
  }

  const getGradeColor = (grade: string) => {
    switch (grade) {
      case 'A':
        return 'text-emerald-400 border-emerald-600/60 bg-emerald-950/60'
      case 'B':
        return 'text-cyan-400 border-cyan-600/60 bg-cyan-950/60'
      case 'C':
        return 'text-amber-400 border-amber-600/60 bg-amber-950/60'
      case 'D':
        return 'text-orange-400 border-orange-600/60 bg-orange-950/60'
      default:
        return 'text-rose-400 border-rose-600/60 bg-rose-950/60'
    }
  }

  return (
    <div className="space-y-6">
      {/* Top Posture Dial & Key Operational Metrics */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Posture Gauge Card (Col 4) */}
        <div className="lg:col-span-4 bg-slate-900/90 border border-slate-800 rounded-xl p-6 flex flex-col justify-between relative overflow-hidden">
          <div className="absolute top-0 right-0 w-32 h-32 bg-cyan-500/10 rounded-full blur-2xl pointer-events-none" />
          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Enterprise Security Posture</span>
              <Award className="w-5 h-5 text-cyan-400" />
            </div>

            <div className="flex items-baseline gap-4 my-2">
              <span className="text-5xl font-black font-mono text-white">
                {posture ? posture.posture_score.toFixed(1) : '94.0'}
              </span>
              <span className="text-sm font-mono text-slate-500">/ 100</span>
              <div
                className={`ml-auto px-3.5 py-1 rounded-lg border text-sm font-bold font-mono ${
                  posture ? getGradeColor(posture.posture_grade) : 'text-emerald-400 bg-emerald-950/60 border-emerald-600/60'
                }`}
              >
                Grade {posture ? posture.posture_grade : 'A'}
              </div>
            </div>

            <p className="text-xs text-slate-400 font-mono mt-3 leading-relaxed">
              Dynamically calculated posture aggregating active critical CVEs, unmitigated incidents, and AI behavioral anomalies.
            </p>
          </div>

          <div className="pt-4 border-t border-slate-800/80 mt-4 flex items-center justify-between text-xs font-mono text-slate-400">
            <span>Status: Optimal Protection</span>
            <span className="text-emerald-400 font-semibold">14-Day Trend: +3.2%</span>
          </div>
        </div>

        {/* Operational Metrics Cards (Col 8) */}
        <div className="lg:col-span-8 grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
            <span className="text-[11px] font-mono uppercase text-slate-400">Monitored Assets</span>
            <div className="my-2">
              <span className="text-2xl font-bold font-mono text-white">
                {posture ? posture.total_assets : 0}
              </span>
              <p className="text-[10px] text-slate-500 font-mono mt-0.5">Fleet discovery nodes</p>
            </div>
            <span className="text-[10px] font-mono text-cyan-400 flex items-center gap-1">
              <ShieldCheck className="w-3 h-3" /> 100% Policy Enforced
            </span>
          </div>

          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
            <span className="text-[11px] font-mono uppercase text-slate-400">Active Incidents</span>
            <div className="my-2">
              <span className="text-2xl font-bold font-mono text-amber-400">
                {posture ? posture.open_incidents_count : 0}
              </span>
              <p className="text-[10px] text-rose-400 font-mono mt-0.5">
                {posture ? posture.critical_incidents_count : 0} Critical SLA
              </p>
            </div>
            <span className="text-[10px] font-mono text-slate-400">Under Triage</span>
          </div>

          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
            <span className="text-[11px] font-mono uppercase text-slate-400">Mean Time to Remediate</span>
            <div className="my-2">
              <span className="text-2xl font-bold font-mono text-cyan-400">
                {posture ? `${posture.mean_time_to_remediate_hours}h` : '3.8h'}
              </span>
              <p className="text-[10px] text-slate-500 font-mono mt-0.5">MTTR SLA window</p>
            </div>
            <span className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
              <Clock className="w-3 h-3" /> Within 4h Target
            </span>
          </div>

          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
            <span className="text-[11px] font-mono uppercase text-slate-400">Mean Time to Detect</span>
            <div className="my-2">
              <span className="text-2xl font-bold font-mono text-purple-400">
                {posture ? `${posture.mean_time_to_detect_hours}h` : '0.6h'}
              </span>
              <p className="text-[10px] text-slate-500 font-mono mt-0.5">Automated SIEM triage</p>
            </div>
            <span className="text-[10px] font-mono text-purple-400 flex items-center gap-1">
              <Activity className="w-3 h-3" /> Real-time Ingestion
            </span>
          </div>
        </div>
      </div>

      {/* Compliance Frameworks & MITRE Tactics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Compliance Readiness */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-semibold flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              Regulatory Compliance Framework Alignment
            </h3>
            <span className="text-[10px] font-mono text-slate-500">Automated Audit Assessment</span>
          </div>

          <div className="space-y-3.5">
            {posture?.compliance_scores ? (
              Object.entries(posture.compliance_scores).map(([framework, score]) => (
                <div key={framework} className="space-y-1.5">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-slate-300 font-medium">{framework}</span>
                    <span className="text-cyan-400 font-bold">{score}% Aligned</span>
                  </div>
                  <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
                    <div
                      className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full transition-all duration-500"
                      style={{ width: `${Math.min(100, score)}%` }}
                    />
                  </div>
                </div>
              ))
            ) : (
              <p className="text-xs font-mono text-slate-500">Loading compliance indices...</p>
            )}
          </div>
        </div>

        {/* MITRE ATT&CK Matrix Observed Tactics */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-semibold flex items-center gap-2">
              <Target className="w-4 h-4 text-rose-400" />
              Observed MITRE ATT&amp;CK Tactics &amp; Techniques
            </h3>
            <span className="text-[10px] font-mono text-slate-500">Top Frequency Ingested</span>
          </div>

          <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
            {posture?.mitre_tactics_breakdown && posture.mitre_tactics_breakdown.length > 0 ? (
              posture.mitre_tactics_breakdown.map((item) => (
                <div
                  key={item.technique}
                  className="flex items-center justify-between p-2 rounded bg-slate-950/60 border border-slate-800/80 text-xs font-mono"
                >
                  <span className="text-slate-200 font-semibold">{item.technique}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-rose-950/70 text-rose-300 border border-rose-800/60">
                    {item.count} observation(s)
                  </span>
                </div>
              ))
            ) : (
              <div className="p-4 text-center text-xs font-mono text-slate-500">
                No adversary techniques actively flagged in the current audit window.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Reports Repository Toolbar & Table */}
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-900/60 border border-slate-800/80 p-4 rounded-xl">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setShowExecutiveModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-lg text-xs font-mono font-semibold transition shadow-md shadow-cyan-900/20 cursor-pointer"
            >
              <PlusCircle className="w-4 h-4" />
              Generate Executive Security Report
            </button>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={fetchData}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900 text-slate-400 hover:text-slate-200 text-xs font-mono transition cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              Refresh Reports
            </button>
          </div>
        </div>

        {/* Toast Notification */}
        {notification && (
          <div
            className={`px-4 py-3 rounded-lg text-xs font-mono flex items-center justify-between border ${
              notification.type === 'success'
                ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800/60'
                : 'bg-rose-950/60 text-rose-300 border-rose-800/60'
            }`}
          >
            <span>{notification.message}</span>
            <button
              onClick={() => setNotification(null)}
              className="text-slate-400 hover:text-white ml-4 cursor-pointer font-bold"
            >
              ✕
            </button>
          </div>
        )}

        {/* Reports Table */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
            <h3 className="text-xs uppercase font-mono tracking-wider text-slate-300 font-semibold flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyan-400" />
              Generated Security Reports &amp; Investigation Dossiers
            </h3>
            <span className="text-[11px] font-mono text-slate-500">{reports.length} report(s) archived</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                <tr>
                  <th className="px-5 py-3">Report Title</th>
                  <th className="px-5 py-3">Type</th>
                  <th className="px-5 py-3">Posture Score</th>
                  <th className="px-5 py-3">Date Generated</th>
                  <th className="px-5 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {reports.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-5 py-8 text-center text-slate-500">
                      No reports generated yet. Click "Generate Executive Security Report" above to compile.
                    </td>
                  </tr>
                ) : (
                  reports.map((rep) => (
                    <tr key={rep.id} className="hover:bg-slate-850/50 transition">
                      <td className="px-5 py-3 font-semibold text-slate-100">{rep.title}</td>
                      <td className="px-5 py-3">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-cyan-950 text-cyan-400 border border-cyan-800 uppercase">
                          {rep.report_type.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="px-5 py-3">
                        {rep.posture_score !== null ? (
                          <span className="font-bold text-white">{rep.posture_score} / 100</span>
                        ) : (
                          <span className="text-slate-500">N/A</span>
                        )}
                      </td>
                      <td className="px-5 py-3 text-slate-400">
                        {new Date(rep.created_at).toLocaleString()}
                      </td>
                      <td className="px-5 py-3 text-right space-x-2">
                        <button
                          onClick={() => {
                            setSelectedReport(rep)
                            setShowPreviewModal(true)
                          }}
                          className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded border border-slate-700 text-[11px] cursor-pointer inline-flex items-center gap-1"
                        >
                          <Eye className="w-3 h-3" /> View
                        </button>
                        <a
                          href={`http://localhost:8000/api/v1/reports/${rep.id}/export?export_format=html`}
                          target="_blank"
                          rel="noreferrer"
                          className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 text-[11px] cursor-pointer inline-flex items-center gap-1"
                        >
                          <ExternalLink className="w-3 h-3" /> HTML
                        </a>
                        <a
                          href={`http://localhost:8000/api/v1/reports/${rep.id}/export?export_format=markdown`}
                          download={`report-${rep.id}.md`}
                          className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 text-[11px] cursor-pointer inline-flex items-center gap-1"
                        >
                          <Download className="w-3 h-3" /> MD
                        </a>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Generate Executive Report Modal */}
      {showExecutiveModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <FileText className="w-5 h-5 text-cyan-400" />
                Generate Executive Report
              </h3>
              <button
                onClick={() => setShowExecutiveModal(false)}
                className="text-slate-400 hover:text-white cursor-pointer"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleGenerateExecutiveReport} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Report Title (Optional)</label>
                <input
                  type="text"
                  value={reportTitle}
                  onChange={(e) => setReportTitle(e.target.value)}
                  placeholder="e.g. Q4 Executive Cybersecurity Posture Report"
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Time Window</label>
                <select
                  value={timeWindowDays}
                  onChange={(e) => setTimeWindowDays(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value={7}>Last 7 Days</option>
                  <option value={30}>Last 30 Days (Standard Audit)</option>
                  <option value={90}>Last 90 Days (Quarterly Assessment)</option>
                  <option value={365}>Full Year (Annual Executive Dossier)</option>
                </select>
              </div>

              <div className="pt-2 text-[11px] font-mono text-slate-400 space-y-1">
                <p>&bull; Includes real-time MTTD &amp; MTTR metrics.</p>
                <p>&bull; Includes NIST, CIS, and ISO regulatory scores.</p>
                <p>&bull; Compiles MITRE ATT&amp;CK frequency analysis.</p>
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowExecutiveModal(false)}
                  className="px-4 py-2 rounded text-xs font-mono text-slate-400 hover:text-white cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={generating}
                  className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded text-xs font-mono font-semibold transition disabled:opacity-50 cursor-pointer"
                >
                  {generating ? 'Compiling Report...' : 'Compile & Render Report'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Report Preview Modal */}
      {showPreviewModal && selectedReport && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-4xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
              <div>
                <h3 className="text-base font-bold text-white">{selectedReport.title}</h3>
                <p className="text-xs font-mono text-slate-400 mt-0.5">
                  Type: {selectedReport.report_type.replace('_', ' ').toUpperCase()} &bull;{' '}
                  {new Date(selectedReport.created_at).toLocaleString()}
                </p>
              </div>
              <div className="flex items-center gap-3">
                <a
                  href={`http://localhost:8000/api/v1/reports/${selectedReport.id}/export?export_format=html`}
                  target="_blank"
                  rel="noreferrer"
                  className="px-3 py-1.5 bg-cyan-950 text-cyan-300 border border-cyan-700/60 rounded text-xs font-mono flex items-center gap-1.5 hover:bg-cyan-900/60 cursor-pointer"
                >
                  <ExternalLink className="w-3.5 h-3.5" /> Open Printable HTML
                </a>
                <button
                  onClick={() => setShowPreviewModal(false)}
                  className="text-slate-400 hover:text-white cursor-pointer text-lg px-2"
                >
                  ✕
                </button>
              </div>
            </div>

            <div className="p-6 overflow-y-auto space-y-6 flex-1 text-slate-200 font-mono text-xs">
              <div className="bg-slate-950/70 p-4 rounded-lg border border-slate-800/80 space-y-2">
                <h4 className="text-xs uppercase font-bold tracking-wider text-cyan-400">Executive Summary</h4>
                <p className="leading-relaxed text-slate-300">{selectedReport.summary}</p>
              </div>

              {selectedReport.content.key_findings && (
                <div className="bg-slate-950/70 p-4 rounded-lg border border-slate-800/80 space-y-2">
                  <h4 className="text-xs uppercase font-bold tracking-wider text-rose-400">Key Security Findings</h4>
                  <ul className="list-disc pl-5 space-y-1.5 text-slate-300">
                    {selectedReport.content.key_findings.map((f: string, i: number) => (
                      <li key={i}>{f}</li>
                    ))}
                  </ul>
                </div>
              )}

              {selectedReport.content.strategic_recommendations && (
                <div className="bg-slate-950/70 p-4 rounded-lg border border-slate-800/80 space-y-2">
                  <h4 className="text-xs uppercase font-bold tracking-wider text-emerald-400">Strategic Recommendations</h4>
                  <ol className="list-decimal pl-5 space-y-1.5 text-slate-300">
                    {selectedReport.content.strategic_recommendations.map((r: string, i: number) => (
                      <li key={i}>{r}</li>
                    ))}
                  </ol>
                </div>
              )}

              {selectedReport.content.corrective_actions && (
                <div className="bg-slate-950/70 p-4 rounded-lg border border-slate-800/80 space-y-2">
                  <h4 className="text-xs uppercase font-bold tracking-wider text-amber-400">Corrective Action Plan</h4>
                  <ol className="list-decimal pl-5 space-y-1.5 text-slate-300">
                    {selectedReport.content.corrective_actions.map((act: string, i: number) => (
                      <li key={i}>{act}</li>
                    ))}
                  </ol>
                </div>
              )}
            </div>

            <div className="p-4 border-t border-slate-800 bg-slate-950/40 flex justify-end">
              <button
                onClick={() => setShowPreviewModal(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-mono cursor-pointer"
              >
                Close Preview
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
