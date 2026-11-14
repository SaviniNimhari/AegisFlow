import { useState, useEffect } from 'react'
import {
  ShieldAlert,
  Flame,
  CheckCircle,
  Clock,
  Activity,
  PlusCircle,
  FileSearch,
  MessageSquare,
  ArrowRight,
  Radio,
  Cpu,
  RefreshCw,
  Lock
} from 'lucide-react'

interface IncidentTimelineEntry {
  id: string
  action: string
  details: string | null
  timestamp: string
  actor_id: string | null
}

interface IncidentCommentEntry {
  id: string
  author_id: string
  content: string
  created_at: string
}

interface CorrelatedAlert {
  id: string
  title: string
  severity: string
  rule_name: string | null
  mitre_technique_id: string | null
  source_ip: string | null
  status: string
  created_at: string
}

interface CorrelatedArtifact {
  id: string
  filename: string
  sha256: string
  classification: string
  risk_score: number
  created_at: string
}

interface Incident {
  id: string
  incident_number: string
  title: string
  description: string | null
  severity: 'low' | 'medium' | 'high' | 'critical'
  status: 'new' | 'triaged' | 'containment' | 'eradication' | 'recovery' | 'closed'
  category: string
  assigned_to: string | null
  containment_notes: string | null
  created_at: string
  updated_at: string
  resolved_at: string | null
  alerts?: CorrelatedAlert[]
  artifacts?: CorrelatedArtifact[]
  timeline?: IncidentTimelineEntry[]
  comments?: IncidentCommentEntry[]
}

interface IncidentStats {
  total_incidents: number
  open_incidents: number
  by_severity: Record<string, number>
  by_status: Record<string, number>
  by_category: Record<string, number>
}

export function IncidentManagement() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [stats, setStats] = useState<IncidentStats | null>(null)
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null)
  const [loading, setLoading] = useState(false)
  const [correlating, setCorrelating] = useState(false)
  const [submittingComment, setSubmittingComment] = useState(false)
  const [updatingStatus, setUpdatingStatus] = useState(false)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [notification, setNotification] = useState<{ message: string; type: 'success' | 'error' } | null>(null)

  // New incident form state
  const [newTitle, setNewTitle] = useState('')
  const [newDescription, setNewDescription] = useState('')
  const [newSeverity, setNewSeverity] = useState<'low' | 'medium' | 'high' | 'critical'>('high')
  const [newCategory, setNewCategory] = useState('malware')

  // Comments and containment inputs
  const [newComment, setNewComment] = useState('')
  const [containmentNotesInput, setContainmentNotesInput] = useState('')

  const fetchIncidents = async () => {
    setLoading(true)
    try {
      const [resIncidents, resStats] = await Promise.all([
        fetch('http://localhost:8000/api/v1/incidents/'),
        fetch('http://localhost:8000/api/v1/incidents/stats/overview')
      ])

      if (resIncidents.ok) {
        const data = await resIncidents.json()
        setIncidents(data)
        if (data.length > 0 && !selectedIncident) {
          fetchIncidentDetail(data[0].id)
        }
      }
      if (resStats.ok) {
        const statsData = await resStats.json()
        setStats(statsData)
      }
    } catch (err) {
      console.error('Failed to load incident management data:', err)
    } finally {
      setLoading(false)
    }
  }

  const fetchIncidentDetail = async (id: string) => {
    try {
      const res = await fetch(`http://localhost:8000/api/v1/incidents/${id}`)
      if (res.ok) {
        const data = await res.json()
        setSelectedIncident(data)
        setContainmentNotesInput(data.containment_notes || '')
      }
    } catch (err) {
      console.error('Failed to fetch incident details:', err)
    }
  }

  useEffect(() => {
    fetchIncidents()
  }, [])

  const triggerCorrelation = async () => {
    setCorrelating(true)
    try {
      const res = await fetch('http://localhost:8000/api/v1/incidents/correlate', {
        method: 'POST'
      })
      if (res.ok) {
        const result = await res.json()
        setNotification({
          message: `Correlation engine completed: ${result.created_incidents} incident(s) correlated from unassigned alerts.`,
          type: 'success'
        })
        await fetchIncidents()
      } else {
        const err = await res.json()
        setNotification({ message: err.detail || 'Correlation failed', type: 'error' })
      }
    } catch (err: unknown) {
      setNotification({ message: err instanceof Error ? err.message : 'Correlation network error', type: 'error' })
    } finally {
      setCorrelating(false)
    }
  }

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newTitle.trim()) return

    try {
      const res = await fetch('http://localhost:8000/api/v1/incidents/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: newTitle,
          description: newDescription || null,
          severity: newSeverity,
          category: newCategory
        })
      })

      if (res.ok) {
        const created = await res.json()
        setShowCreateModal(false)
        setNewTitle('')
        setNewDescription('')
        setNotification({ message: `Incident ${created.incident_number} created successfully.`, type: 'success' })
        await fetchIncidents()
        fetchIncidentDetail(created.id)
      } else {
        const err = await res.json()
        setNotification({ message: err.detail || 'Failed to create incident', type: 'error' })
      }
    } catch (err: unknown) {
      setNotification({ message: err instanceof Error ? err.message : 'Creation error', type: 'error' })
    }
  }

  const handleStatusTransition = async (newStatus: Incident['status']) => {
    if (!selectedIncident) return
    setUpdatingStatus(true)
    try {
      const res = await fetch(`http://localhost:8000/api/v1/incidents/${selectedIncident.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status: newStatus,
          containment_notes: containmentNotesInput || selectedIncident.containment_notes
        })
      })

      if (res.ok) {
        setNotification({ message: `Incident status updated to ${newStatus.toUpperCase()}`, type: 'success' })
        await fetchIncidentDetail(selectedIncident.id)
        await fetchIncidents()
      } else {
        const err = await res.json()
        setNotification({ message: err.detail || 'Status transition failed', type: 'error' })
      }
    } catch (err: unknown) {
      setNotification({ message: err instanceof Error ? err.message : 'Update error', type: 'error' })
    } finally {
      setUpdatingStatus(false)
    }
  }

  const handleSaveContainmentNotes = async () => {
    if (!selectedIncident) return
    try {
      const res = await fetch(`http://localhost:8000/api/v1/incidents/${selectedIncident.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          containment_notes: containmentNotesInput
        })
      })

      if (res.ok) {
        setNotification({ message: 'Containment notes saved to case file.', type: 'success' })
        fetchIncidentDetail(selectedIncident.id)
      }
    } catch (err) {
      console.error(err)
    }
  }

  const handleAddComment = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedIncident || !newComment.trim()) return

    setSubmittingComment(true)
    try {
      const res = await fetch(`http://localhost:8000/api/v1/incidents/${selectedIncident.id}/comments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: newComment })
      })

      if (res.ok) {
        setNewComment('')
        fetchIncidentDetail(selectedIncident.id)
      } else {
        const err = await res.json()
        setNotification({ message: err.detail || 'Failed to post comment', type: 'error' })
      }
    } catch (err: unknown) {
      setNotification({ message: err instanceof Error ? err.message : 'Error', type: 'error' })
    } finally {
      setSubmittingComment(false)
    }
  }

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-700/60 uppercase">Critical</span>
      case 'high':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-950 text-amber-300 border border-amber-700/60 uppercase">High</span>
      case 'medium':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-sky-950 text-sky-300 border border-sky-700/60 uppercase">Medium</span>
      default:
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700 uppercase">Low</span>
    }
  }

  const getStatusBadge = (status: string) => {
    switch (status.toLowerCase()) {
      case 'new':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-blue-950 text-blue-400 border border-blue-800 uppercase">New</span>
      case 'triaged':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-950 text-purple-400 border border-purple-800 uppercase">Triaged</span>
      case 'containment':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-950 text-amber-400 border border-amber-800 uppercase animate-pulse">Containment</span>
      case 'eradication':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-orange-950 text-orange-400 border border-orange-800 uppercase">Eradication</span>
      case 'recovery':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-teal-950 text-teal-400 border border-teal-800 uppercase">Recovery</span>
      case 'closed':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800 uppercase">Closed</span>
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400 uppercase">{status}</span>
    }
  }

  return (
    <div className="space-y-6">
      {/* Top Banner & Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 flex items-center justify-between">
          <div>
            <p className="text-xs font-mono uppercase tracking-wider text-slate-400">Total Cases</p>
            <h3 className="text-2xl font-bold font-mono text-white mt-1">
              {stats ? stats.total_incidents : incidents.length}
            </h3>
            <p className="text-[11px] text-slate-400 font-mono mt-0.5">Automated &amp; triage records</p>
          </div>
          <div className="w-11 h-11 rounded-lg bg-cyan-950/60 border border-cyan-800/50 flex items-center justify-center text-cyan-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 flex items-center justify-between">
          <div>
            <p className="text-xs font-mono uppercase tracking-wider text-slate-400">Open Incidents</p>
            <h3 className="text-2xl font-bold font-mono text-amber-400 mt-1">
              {stats ? stats.open_incidents : incidents.filter(i => i.status !== 'closed').length}
            </h3>
            <p className="text-[11px] text-slate-400 font-mono mt-0.5">Active under investigation</p>
          </div>
          <div className="w-11 h-11 rounded-lg bg-amber-950/60 border border-amber-800/50 flex items-center justify-center text-amber-400">
            <Flame className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 flex items-center justify-between">
          <div>
            <p className="text-xs font-mono uppercase tracking-wider text-slate-400">Critical / High Severity</p>
            <h3 className="text-2xl font-bold font-mono text-rose-400 mt-1">
              {stats
                ? (stats.by_severity['critical'] || 0) + (stats.by_severity['high'] || 0)
                : incidents.filter(i => i.severity === 'critical' || i.severity === 'high').length}
            </h3>
            <p className="text-[11px] text-slate-400 font-mono mt-0.5">Priority response SLA</p>
          </div>
          <div className="w-11 h-11 rounded-lg bg-rose-950/60 border border-rose-800/50 flex items-center justify-center text-rose-400">
            <Activity className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 flex items-center justify-between">
          <div>
            <p className="text-xs font-mono uppercase tracking-wider text-slate-400">Containment Active</p>
            <h3 className="text-2xl font-bold font-mono text-emerald-400 mt-1">
              {stats ? (stats.by_status['containment'] || 0) : incidents.filter(i => i.status === 'containment').length}
            </h3>
            <p className="text-[11px] text-slate-400 font-mono mt-0.5">Isolation &amp; blast radius control</p>
          </div>
          <div className="w-11 h-11 rounded-lg bg-emerald-950/60 border border-emerald-800/50 flex items-center justify-center text-emerald-400">
            <CheckCircle className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Control Actions Ribbon */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-900/60 border border-slate-800/80 p-4 rounded-xl">
        <div className="flex items-center gap-3">
          <button
            onClick={triggerCorrelation}
            disabled={correlating}
            className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-lg text-xs font-mono font-semibold transition shadow-md shadow-cyan-900/20 disabled:opacity-50 cursor-pointer"
          >
            <Cpu className={`w-4 h-4 ${correlating ? 'animate-spin' : ''}`} />
            {correlating ? 'Correlating Alerts...' : 'Run Automated Alert Correlation'}
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-lg text-xs font-mono transition cursor-pointer"
          >
            <PlusCircle className="w-4 h-4 text-cyan-400" />
            New Incident Case
          </button>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              fetchIncidents()
              if (selectedIncident) fetchIncidentDetail(selectedIncident.id)
            }}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900 text-slate-400 hover:text-slate-200 text-xs font-mono transition cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
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

      {/* Master Detail Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Incident List (Left side) */}
        <div className="lg:col-span-5 space-y-3">
          <div className="flex items-center justify-between px-1">
            <h2 className="text-xs uppercase font-mono tracking-wider text-slate-400">Incident Dossiers</h2>
            <span className="text-[11px] font-mono text-slate-500">{incidents.length} record(s)</span>
          </div>

          <div className="space-y-2 max-h-[750px] overflow-y-auto pr-1">
            {incidents.length === 0 ? (
              <div className="p-8 text-center bg-slate-900/40 border border-slate-800/80 rounded-xl">
                <ShieldAlert className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                <p className="text-xs font-mono text-slate-400">No active incidents recorded.</p>
                <p className="text-[11px] text-slate-500 font-mono mt-1">Run Alert Correlation or create a new case.</p>
              </div>
            ) : (
              incidents.map((inc) => {
                const isSelected = selectedIncident?.id === inc.id
                return (
                  <div
                    key={inc.id}
                    onClick={() => fetchIncidentDetail(inc.id)}
                    className={`p-4 rounded-xl border transition cursor-pointer ${
                      isSelected
                        ? 'bg-slate-800/80 border-cyan-500/60 shadow-lg shadow-cyan-950/30'
                        : 'bg-slate-900/70 border-slate-800/80 hover:bg-slate-850 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-cyan-400">{inc.incident_number}</span>
                        {getSeverityBadge(inc.severity)}
                      </div>
                      {getStatusBadge(inc.status)}
                    </div>

                    <h4 className="text-sm font-semibold text-slate-100 line-clamp-1">{inc.title}</h4>

                    <div className="flex items-center justify-between mt-3 pt-2.5 border-t border-slate-800/60 text-[11px] font-mono text-slate-400">
                      <span className="capitalize">{inc.category.replace('_', ' ')}</span>
                      <span>{new Date(inc.created_at).toLocaleDateString()}</span>
                    </div>
                  </div>
                )
              })
            )}
          </div>
        </div>

        {/* Selected Incident Inspector (Right side) */}
        <div className="lg:col-span-7">
          {selectedIncident ? (
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 space-y-6">
              {/* Header */}
              <div className="border-b border-slate-800 pb-5">
                <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2.5">
                    <span className="text-base font-mono font-bold text-cyan-400 bg-cyan-950/70 px-2.5 py-1 rounded border border-cyan-800/60">
                      {selectedIncident.incident_number}
                    </span>
                    {getSeverityBadge(selectedIncident.severity)}
                    {getStatusBadge(selectedIncident.status)}
                  </div>
                  <span className="text-xs font-mono text-slate-400">
                    Logged: {new Date(selectedIncident.created_at).toLocaleString()}
                  </span>
                </div>
                <h2 className="text-xl font-bold text-white mt-2">{selectedIncident.title}</h2>
                {selectedIncident.description && (
                  <p className="text-xs text-slate-300 font-mono mt-2 bg-slate-950/50 p-3 rounded-lg border border-slate-800/60 leading-relaxed">
                    {selectedIncident.description}
                  </p>
                )}
              </div>

              {/* Status Lifecycle Progression Toolbar */}
              <div>
                <h3 className="text-xs uppercase font-mono tracking-wider text-slate-400 mb-2.5 flex items-center gap-1.5">
                  <ArrowRight className="w-3.5 h-3.5 text-cyan-400" />
                  Incident Lifecycle Progression
                </h3>
                <div className="grid grid-cols-3 sm:grid-cols-6 gap-1.5 bg-slate-950/60 p-1.5 rounded-lg border border-slate-800/80">
                  {(['new', 'triaged', 'containment', 'eradication', 'recovery', 'closed'] as Incident['status'][]).map(
                    (st) => {
                      const isActive = selectedIncident.status === st
                      return (
                        <button
                          key={st}
                          onClick={() => handleStatusTransition(st)}
                          disabled={updatingStatus || isActive}
                          className={`py-1.5 px-2 rounded text-[11px] font-mono capitalize transition text-center cursor-pointer ${
                            isActive
                              ? 'bg-cyan-600 text-white font-bold shadow-md shadow-cyan-900/30'
                              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                          }`}
                        >
                          {st}
                        </button>
                      )
                    }
                  )}
                </div>
              </div>

              {/* Containment Protocol & Blast Radius Notes */}
              <div className="bg-slate-950/50 border border-slate-800/80 rounded-lg p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-amber-300 font-semibold flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-amber-400" />
                    Containment &amp; Blast Radius Remediation Plan
                  </span>
                  <button
                    onClick={handleSaveContainmentNotes}
                    className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 bg-cyan-950/40 border border-cyan-800/50 px-2.5 py-1 rounded cursor-pointer"
                  >
                    Save Plan
                  </button>
                </div>
                <textarea
                  value={containmentNotesInput}
                  onChange={(e) => setContainmentNotesInput(e.target.value)}
                  placeholder="Record host isolation status, network segment ACLs applied, revoked credentials, or remediation actions..."
                  className="w-full bg-slate-900 border border-slate-800 rounded p-2.5 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 h-20 resize-none"
                />
              </div>

              {/* Correlated Evidence & Alerts Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Correlated Security Alerts */}
                <div className="bg-slate-950/40 border border-slate-800/80 rounded-lg p-3.5 space-y-2">
                  <div className="flex items-center justify-between border-b border-slate-800/60 pb-2">
                    <span className="text-xs font-mono text-slate-300 font-semibold flex items-center gap-1.5">
                      <Radio className="w-3.5 h-3.5 text-red-400" />
                      Correlated Alerts ({selectedIncident.alerts?.length || 0})
                    </span>
                  </div>
                  <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                    {selectedIncident.alerts && selectedIncident.alerts.length > 0 ? (
                      selectedIncident.alerts.map((al) => (
                        <div key={al.id} className="p-2 rounded bg-slate-900/60 border border-slate-800 text-xs">
                          <div className="flex items-center justify-between">
                            <span className="font-semibold text-slate-200 line-clamp-1">{al.title}</span>
                            <span className="text-[10px] font-mono text-rose-400">{al.severity}</span>
                          </div>
                          <div className="flex items-center gap-2 mt-1 text-[10px] font-mono text-slate-500">
                            {al.mitre_technique_id && <span>MITRE: {al.mitre_technique_id}</span>}
                            {al.source_ip && <span>IP: {al.source_ip}</span>}
                          </div>
                        </div>
                      ))
                    ) : (
                      <p className="text-[11px] font-mono text-slate-500 py-3 text-center">No alerts attached.</p>
                    )}
                  </div>
                </div>

                {/* Correlated Forensic Evidence */}
                <div className="bg-slate-950/40 border border-slate-800/80 rounded-lg p-3.5 space-y-2">
                  <div className="flex items-center justify-between border-b border-slate-800/60 pb-2">
                    <span className="text-xs font-mono text-slate-300 font-semibold flex items-center gap-1.5">
                      <FileSearch className="w-3.5 h-3.5 text-cyan-400" />
                      Forensic Artifacts ({selectedIncident.artifacts?.length || 0})
                    </span>
                  </div>
                  <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                    {selectedIncident.artifacts && selectedIncident.artifacts.length > 0 ? (
                      selectedIncident.artifacts.map((art) => (
                        <div key={art.id} className="p-2 rounded bg-slate-900/60 border border-slate-800 text-xs">
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-slate-200 line-clamp-1">{art.filename}</span>
                            <span className="text-[10px] font-mono text-amber-400">Risk: {art.risk_score}</span>
                          </div>
                          <div className="font-mono text-[9px] text-slate-500 truncate mt-0.5">
                            SHA: {art.sha256}
                          </div>
                        </div>
                      ))
                    ) : (
                      <p className="text-[11px] font-mono text-slate-500 py-3 text-center">No forensic artifacts linked.</p>
                    )}
                  </div>
                </div>
              </div>

              {/* Timeline & Collaboration Tabs */}
              <div className="space-y-4 pt-2">
                {/* Timeline */}
                <div className="bg-slate-950/50 border border-slate-800/80 rounded-lg p-4">
                  <h3 className="text-xs uppercase font-mono tracking-wider text-slate-400 mb-3 flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-cyan-400" />
                    Investigation Chronology &amp; Audit Trail
                  </h3>
                  <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                    {selectedIncident.timeline && selectedIncident.timeline.length > 0 ? (
                      selectedIncident.timeline.map((entry) => (
                        <div key={entry.id} className="flex items-start gap-2.5 text-xs font-mono">
                          <span className="text-cyan-500 mt-0.5">•</span>
                          <div className="flex-1">
                            <div className="flex items-center justify-between">
                              <span className="font-semibold text-slate-300">{entry.action}</span>
                              <span className="text-[10px] text-slate-500">
                                {new Date(entry.timestamp).toLocaleTimeString()}
                              </span>
                            </div>
                            {entry.details && <p className="text-[11px] text-slate-400 mt-0.5">{entry.details}</p>}
                          </div>
                        </div>
                      ))
                    ) : (
                      <p className="text-[11px] font-mono text-slate-500">No timeline entries.</p>
                    )}
                  </div>
                </div>

                {/* Case Collaboration Comments */}
                <div className="bg-slate-950/50 border border-slate-800/80 rounded-lg p-4 space-y-3">
                  <h3 className="text-xs uppercase font-mono tracking-wider text-slate-400 flex items-center gap-1.5">
                    <MessageSquare className="w-3.5 h-3.5 text-purple-400" />
                    Analyst Collaboration Notes
                  </h3>

                  <div className="space-y-2 max-h-36 overflow-y-auto pr-1">
                    {selectedIncident.comments && selectedIncident.comments.length > 0 ? (
                      selectedIncident.comments.map((cm) => (
                        <div key={cm.id} className="p-2.5 rounded bg-slate-900/60 border border-slate-800/80 text-xs">
                          <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 mb-1">
                            <span>Author: SOC Analyst</span>
                            <span>{new Date(cm.created_at).toLocaleString()}</span>
                          </div>
                          <p className="text-slate-200 font-mono text-[11px]">{cm.content}</p>
                        </div>
                      ))
                    ) : (
                      <p className="text-[11px] font-mono text-slate-500">No collaboration comments yet.</p>
                    )}
                  </div>

                  <form onSubmit={handleAddComment} className="flex gap-2">
                    <input
                      type="text"
                      value={newComment}
                      onChange={(e) => setNewComment(e.target.value)}
                      placeholder="Add analyst note or lead to case file..."
                      className="flex-1 bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                    />
                    <button
                      type="submit"
                      disabled={submittingComment || !newComment.trim()}
                      className="px-3 py-1.5 bg-purple-900 hover:bg-purple-800 border border-purple-700/60 text-purple-200 rounded text-xs font-mono transition disabled:opacity-50 cursor-pointer"
                    >
                      Post Note
                    </button>
                  </form>
                </div>
              </div>
            </div>
          ) : (
            <div className="h-full flex items-center justify-center p-12 bg-slate-900/40 border border-slate-800/80 rounded-xl">
              <div className="text-center text-slate-500 font-mono text-xs">
                Select an incident dossier from the list to view its investigation details.
              </div>
            </div>
          )}
        </div>
      </div>

      {/* New Incident Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-cyan-400" />
                Open New Incident Dossier
              </h3>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white cursor-pointer"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateIncident} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Incident Title *</label>
                <input
                  type="text"
                  required
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. Cobalt Strike Beacon Detected on DC-01"
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Summary / Context</label>
                <textarea
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  placeholder="Initial observations, affected subnet, and alert context..."
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 h-20 resize-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">Severity</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">Category</label>
                  <select
                    value={newCategory}
                    onChange={(e) => setNewCategory(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="malware">Malware</option>
                    <option value="unauthorized_access">Unauthorized Access</option>
                    <option value="data_exfiltration">Data Exfiltration</option>
                    <option value="phishing">Phishing</option>
                    <option value="denial_of_service">Denial of Service</option>
                    <option value="insider_threat">Insider Threat</option>
                    <option value="policy_violation">Policy Violation</option>
                    <option value="other">Other</option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded text-xs font-mono text-slate-400 hover:text-white cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded text-xs font-mono font-semibold transition cursor-pointer"
                >
                  Create Incident
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
