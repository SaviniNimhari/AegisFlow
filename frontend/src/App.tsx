import { useState, useEffect } from 'react'
import {
  ShieldAlert,
  ShieldCheck,
  Cpu,
  Terminal,
  Server,
  Activity,
  CheckCircle2,
  Layers,
  Code2,
  Lock,
  RefreshCw,
  LayoutDashboard,
  Box,
  AlertTriangle,
  Radio,
  Brain,
  FileSearch
} from 'lucide-react'
import { AssetInventory } from './components/AssetInventory'
import { VulnerabilityManagement } from './components/VulnerabilityManagement'
import { SecurityMonitoring } from './components/SecurityMonitoring'
import { AIRiskIntelligence } from './components/AIRiskIntelligence'
import { DigitalForensics } from './components/DigitalForensics'
import { IncidentManagement } from './components/IncidentManagement'

interface HealthState {
  status: string
  service: string
  version: string
  database?: string
  checkedAt?: string
}

export function App() {
  const [activeTab, setActiveTab] = useState<'incidents' | 'forensics' | 'ai-risk' | 'monitoring' | 'vulnerabilities' | 'assets' | 'overview'>('incidents')
  const [health, setHealth] = useState<HealthState | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const checkHealth = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('http://localhost:8000/api/v1/health')
      if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`)
      const data = await res.json()
      setHealth({ ...data, checkedAt: new Date().toLocaleTimeString() })
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Unable to reach backend')
      setHealth(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    checkHealth()
  }, [])

  return (
    <div className="min-h-screen bg-[#080d19] text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-black">
      {/* Top Navbar */}
      <header className="border-b border-slate-800/80 bg-[#0b1329]/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-6">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 rounded-lg bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
                <ShieldCheck className="w-6 h-6 text-white" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-bold text-lg tracking-wider text-white">AEGISFLOW</span>
                  <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-700/60 font-semibold tracking-wide">
                    Phase 8 Active: Incident Correlation &amp; Case Response
                  </span>
                </div>
                <p className="text-xs text-slate-400 font-mono tracking-tight">Cybersecurity Defense &amp; Digital Forensics</p>
              </div>
            </div>

            {/* Navigation Tabs */}
            <nav className="hidden md:flex items-center space-x-1 pl-4 border-l border-slate-800">
              <button
                onClick={() => setActiveTab('incidents')}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono transition cursor-pointer ${
                  activeTab === 'incidents'
                    ? 'bg-rose-950/70 text-rose-300 border border-rose-700/60 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                Incidents &amp; Triage (Phase 8)
              </button>
              <button
                onClick={() => setActiveTab('forensics')}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono transition cursor-pointer ${
                  activeTab === 'forensics'
                    ? 'bg-cyan-950/70 text-cyan-300 border border-cyan-700/60 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <FileSearch className="w-3.5 h-3.5 text-cyan-400" />
                Forensics &amp; YARA (Phase 7)
              </button>
              <button
                onClick={() => setActiveTab('ai-risk')}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono transition cursor-pointer ${
                  activeTab === 'ai-risk'
                    ? 'bg-purple-950/70 text-purple-300 border border-purple-700/60 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Brain className="w-3.5 h-3.5 text-purple-400" />
                AI Risk (Phase 6)
              </button>
              <button
                onClick={() => setActiveTab('monitoring')}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono transition cursor-pointer ${
                  activeTab === 'monitoring'
                    ? 'bg-cyan-950/70 text-cyan-400 border border-cyan-700/60 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Radio className="w-3.5 h-3.5 text-red-400" />
                Threat Monitoring (Phase 5)
              </button>
              <button
                onClick={() => setActiveTab('vulnerabilities')}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono transition cursor-pointer ${
                  activeTab === 'vulnerabilities'
                    ? 'bg-cyan-950/70 text-cyan-400 border border-cyan-700/60 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                Vulnerabilities (Phase 4)
              </button>
              <button
                onClick={() => setActiveTab('assets')}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono transition cursor-pointer ${
                  activeTab === 'assets'
                    ? 'bg-cyan-950/70 text-cyan-400 border border-cyan-700/60 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Box className="w-3.5 h-3.5" />
                Asset Inventory (Phase 3)
              </button>
              <button
                onClick={() => setActiveTab('overview')}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono transition cursor-pointer ${
                  activeTab === 'overview'
                    ? 'bg-cyan-950/70 text-cyan-400 border border-cyan-700/60 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <LayoutDashboard className="w-3.5 h-3.5" />
                SOC Architecture Overview
              </button>
            </nav>
          </div>

          <div className="flex items-center space-x-3">
            <a
              href="http://localhost:8000/docs"
              target="_blank"
              rel="noreferrer"
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 transition-colors flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-cyan-500/30 bg-cyan-950/30"
            >
              <Terminal className="w-3.5 h-3.5" />
              API Docs (/docs)
            </a>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl mx-auto px-6 py-8 w-full space-y-8">
        {activeTab === 'incidents' ? (
          <div>
            <div className="mb-6 flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-800/80 pb-4">
              <div>
                <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
                  <ShieldAlert className="w-6 h-6 text-rose-400" />
                  Incident Response, Case Investigation &amp; Alert Correlation
                </h1>
                <p className="text-xs text-slate-400 font-mono mt-1">
                  Automated security alert clustering, blast radius containment, multi-analyst case dossiers, artifact linkage, and immutable timeline tracking.
                </p>
              </div>
            </div>
            <IncidentManagement />
          </div>
        ) : activeTab === 'forensics' ? (
          <div>
            <div className="mb-6 flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-800/80 pb-4">
              <div>
                <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
                  <FileSearch className="w-6 h-6 text-cyan-400" />
                  Digital Forensics, Static Binary Analysis &amp; YARA Engine
                </h1>
                <p className="text-xs text-slate-400 font-mono mt-1">
                  Cryptographic hashing (SHA-256, MD5, SHA-1), Shannon entropy measurement, IOC extraction, YARA matching, and verifiable Chain of Custody tracking.
                </p>
              </div>
            </div>
            <DigitalForensics />
          </div>
        ) : activeTab === 'ai-risk' ? (
          <div>
            <div className="mb-6 flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-800/80 pb-4">
              <div>
                <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
                  <Brain className="w-6 h-6 text-purple-400" />
                  AI Threat Intelligence &amp; SHAP Explainability Engine
                </h1>
                <p className="text-xs text-slate-400 font-mono mt-1">
                  Gradient-boosted behavioral threat scoring, anomaly detection, active learning feedback, and transparent SHAP feature attributions.
                </p>
              </div>
            </div>
            <AIRiskIntelligence />
          </div>
        ) : activeTab === 'monitoring' ? (
          <div>
            <div className="mb-6 flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-800/80 pb-4">
              <div>
                <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
                  <Radio className="w-6 h-6 text-red-400" />
                  Security Monitoring &amp; Rule-Based Detection Engine
                </h1>
                <p className="text-xs text-slate-400 font-mono mt-1">
                  Real-time telemetry ingestion, MITRE ATT&amp;CK rule correlation, brute-force &amp; IOC detection, and SOC analyst triage.
                </p>
              </div>
            </div>
            <SecurityMonitoring />
          </div>
        ) : activeTab === 'vulnerabilities' ? (
          <div>
            <div className="mb-6 flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-800/80 pb-4">
              <div>
                <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
                  <AlertTriangle className="w-6 h-6 text-amber-400" />
                  Vulnerability Management &amp; CVE Intelligence
                </h1>
                <p className="text-xs text-slate-400 font-mono mt-1">
                  Correlate assets against the CVE repository, trigger vulnerability scans, and track remediation lifecycles.
                </p>
              </div>
            </div>
            <VulnerabilityManagement />
          </div>
        ) : activeTab === 'assets' ? (
          <div>
            <div className="mb-6 flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-800/80 pb-4">
              <div>
                <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
                  <Box className="w-6 h-6 text-cyan-400" />
                  Authorized Digital Asset Inventory
                </h1>
                <p className="text-xs text-slate-400 font-mono mt-1">
                  Discover, manage, and catalog authorized network hosts, operating systems, and exposed listening ports.
                </p>
              </div>
            </div>
            <AssetInventory />
          </div>
        ) : (
          /* SOC Overview Tab */
          <div className="space-y-8">
            {/* Hero Section */}
            <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-gradient-to-b from-[#0d1833] to-[#091024] p-8 shadow-2xl">
              <div className="absolute top-0 right-0 -mt-12 -mr-12 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
              <div className="relative z-10 max-w-3xl space-y-4">
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-700/50 text-cyan-300 text-xs font-mono">
                  <Activity className="w-3.5 h-3.5 animate-pulse text-cyan-400" />
                  Phase 4: Vulnerability Management &amp; Scanning Operational
                </div>
                <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight text-white">
                  Autonomous Threat Intelligence &amp; Digital Forensics Platform
                </h1>
                <p className="text-slate-300 text-sm md:text-base leading-relaxed">
                  AegisFlow integrates attack surface discovery, CVE vulnerability correlation, hybrid rule-based &amp; machine learning threat detection engines, and chain-of-custody digital evidence preservation.
                </p>
              </div>
            </div>

            {/* Live System Connectivity Grid */}
            <section className="space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                  <Server className="w-4 h-4 text-cyan-400" />
                  System Stack Connectivity
                </h2>
                <button
                  onClick={checkHealth}
                  disabled={loading}
                  className="text-xs flex items-center gap-1.5 px-2.5 py-1 rounded border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-300 transition cursor-pointer"
                >
                  <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
                  Re-probe API
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                {/* FastAPI Backend */}
                <div className="rounded-xl border border-slate-800/80 bg-[#0d152b] p-5 shadow-lg flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-xs font-mono uppercase text-slate-400">Backend API</span>
                      {health?.status === 'healthy' || health?.status === 'degraded' ? (
                        <span className="flex items-center gap-1 text-[11px] text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800">
                          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping"></span>
                          ONLINE
                        </span>
                      ) : (
                        <span className="text-[11px] text-amber-400 bg-amber-950/50 px-2 py-0.5 rounded border border-amber-800">
                          STANDBY
                        </span>
                      )}
                    </div>
                    <h3 className="font-semibold text-slate-200 text-base">Python 3.12 + FastAPI</h3>
                    <p className="text-xs text-slate-400 mt-1 font-mono">
                      {health ? `v${health.version} - ${health.status}` : error ? error : 'Port 8000 awaiting ping'}
                    </p>
                  </div>
                  <div className="mt-4 pt-3 border-t border-slate-800 flex justify-between text-[11px] text-slate-400 font-mono">
                    <span>Endpoint</span>
                    <span className="text-cyan-400">localhost:8000</span>
                  </div>
                </div>

                {/* React Frontend */}
                <div className="rounded-xl border border-slate-800/80 bg-[#0d152b] p-5 shadow-lg flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-xs font-mono uppercase text-slate-400">User Interface</span>
                      <span className="flex items-center gap-1 text-[11px] text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800">
                        <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                        ONLINE
                      </span>
                    </div>
                    <h3 className="font-semibold text-slate-200 text-base">React + TypeScript</h3>
                    <p className="text-xs text-slate-400 mt-1 font-mono">Vite + Tailwind CSS v4</p>
                  </div>
                  <div className="mt-4 pt-3 border-t border-slate-800 flex justify-between text-[11px] text-slate-400 font-mono">
                    <span>Dev Server</span>
                    <span className="text-cyan-400">localhost:5173</span>
                  </div>
                </div>

                {/* Database Engine */}
                <div className="rounded-xl border border-slate-800/80 bg-[#0d152b] p-5 shadow-lg flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-xs font-mono uppercase text-slate-400">Database</span>
                      <span className="text-[11px] text-blue-400 bg-blue-950/50 px-2 py-0.5 rounded border border-blue-800">
                        CONFIGURED
                      </span>
                    </div>
                    <h3 className="font-semibold text-slate-200 text-base">PostgreSQL 17 / 18</h3>
                    <p className="text-xs text-slate-400 mt-1 font-mono">SQLAlchemy 2 + Alembic</p>
                  </div>
                  <div className="mt-4 pt-3 border-t border-slate-800 flex justify-between text-[11px] text-slate-400 font-mono">
                    <span>Migrations</span>
                    <span className="text-cyan-400">0001, 0002, 0003</span>
                  </div>
                </div>

                {/* Cache & Queue */}
                <div className="rounded-xl border border-slate-800/80 bg-[#0d152b] p-5 shadow-lg flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-xs font-mono uppercase text-slate-400">Tasks &amp; Cache</span>
                      <span className="text-[11px] text-purple-400 bg-purple-950/50 px-2 py-0.5 rounded border border-purple-800">
                        CONFIGURED
                      </span>
                    </div>
                    <h3 className="font-semibold text-slate-200 text-base">Redis + Celery</h3>
                    <p className="text-xs text-slate-400 mt-1 font-mono">Async Forensic Workers</p>
                  </div>
                  <div className="mt-4 pt-3 border-t border-slate-800 flex justify-between text-[11px] text-slate-400 font-mono">
                    <span>Port</span>
                    <span className="text-cyan-400">6379</span>
                  </div>
                </div>
              </div>
            </section>

            {/* Modular Architecture Roadmap */}
            <section className="space-y-4">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                AegisFlow Security &amp; Intelligence Modules
              </h2>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* Core Defensive Modules */}
                <div className="rounded-xl border border-slate-800 bg-[#0b1329] p-5 space-y-3">
                  <div className="flex items-center gap-2 text-cyan-400 font-semibold text-sm">
                    <Lock className="w-4 h-4" />
                    <span>Foundation &amp; Security</span>
                  </div>
                  <ul className="text-xs text-slate-300 space-y-2 font-mono">
                    <li className="flex items-center gap-2 text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>01. Auth &amp; User Management (Phase 2 Done)</span>
                    </li>
                    <li className="flex items-center gap-2 text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>02. Asset Inventory &amp; Host Mapping (Phase 3 Done)</span>
                    </li>
                    <li className="flex items-center gap-2 text-cyan-400">
                      <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                      <span>03. Vulnerability Management (Phase 4 Done)</span>
                    </li>
                    <li className="flex items-center gap-2 text-slate-400">
                      <CheckCircle2 className="w-3.5 h-3.5 text-slate-500" />
                      <span>11. Audit Logging &amp; Administration</span>
                    </li>
                  </ul>
                </div>

                {/* Monitoring & Forensics */}
                <div className="rounded-xl border border-slate-800 bg-[#0b1329] p-5 space-y-3">
                  <div className="flex items-center gap-2 text-blue-400 font-semibold text-sm">
                    <Cpu className="w-4 h-4" />
                    <span>Detection &amp; Forensics</span>
                  </div>
                  <ul className="text-xs text-slate-300 space-y-2 font-mono">
                    <li className="flex items-center gap-2 text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>04. Network Security Monitoring (Phase 5 Done)</span>
                    </li>
                    <li className="flex items-center gap-2 text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>05. Log Ingestion &amp; Rule Detection (Phase 5 Done)</span>
                    </li>
                    <li className="flex items-center gap-2 text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>06. Digital Forensics &amp; YARA Engine (Phase 7 Done)</span>
                    </li>
                    <li className="flex items-center gap-2 text-slate-400">
                      <CheckCircle2 className="w-3.5 h-3.5 text-slate-500" />
                      <span>07. Threat Intelligence Feeds &amp; Hashes</span>
                    </li>
                  </ul>
                </div>

                {/* AI Intelligence & Incident Response */}
                <div className="rounded-xl border border-slate-800 bg-[#0b1329] p-5 space-y-3">
                  <div className="flex items-center gap-2 text-purple-400 font-semibold text-sm">
                    <ShieldAlert className="w-4 h-4" />
                    <span>AI &amp; Incident Management</span>
                  </div>
                  <ul className="text-xs text-slate-300 space-y-2 font-mono">
                    <li className="flex items-center gap-2 text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>08. AI Risk Intelligence (XGBoost + SHAP) (Phase 6 Done)</span>
                    </li>
                    <li className="flex items-center gap-2 text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>09. Incident Correlation &amp; Case Timelines (Phase 8 Done)</span>
                    </li>
                    <li className="flex items-center gap-2 text-slate-400">
                      <CheckCircle2 className="w-3.5 h-3.5 text-slate-500" />
                      <span>10. Executive &amp; Technical Security Reports (Phase 9)</span>
                    </li>
                  </ul>
                </div>
              </div>
            </section>

            {/* Quick Developer Command Reference */}
            <section className="rounded-xl border border-slate-800/80 bg-[#0b1329] p-6 space-y-4">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <Code2 className="w-4 h-4 text-cyan-400" />
                Developer Command Reference
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                <div className="bg-[#050811] p-4 rounded-lg border border-slate-800 space-y-2">
                  <span className="text-slate-400 font-bold block">Python Backend Startup:</span>
                  <p className="text-cyan-300">.\.venv\Scripts\Activate.ps1</p>
                  <p className="text-cyan-300">python -m uvicorn backend.app.main:app --reload</p>
                  <p className="text-slate-500">API: http://127.0.0.1:8000 | Docs: /docs</p>
                </div>
                <div className="bg-[#050811] p-4 rounded-lg border border-slate-800 space-y-2">
                  <span className="text-slate-400 font-bold block">Frontend Dev Server:</span>
                  <p className="text-emerald-300">cd frontend</p>
                  <p className="text-emerald-300">npm run dev</p>
                  <p className="text-slate-500">Dashboard: http://localhost:5173</p>
                </div>
              </div>
            </section>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 py-4 px-6 text-center text-xs text-slate-400 font-mono">
        AegisFlow Cybersecurity Defense &amp; Digital Forensics &bull; Hybrid Rule-Based &amp; Machine-Learning Security Platform
      </footer>
    </div>
  )
}

export default App
