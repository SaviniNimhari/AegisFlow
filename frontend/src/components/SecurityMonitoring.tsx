import { useState, useEffect } from 'react'
import {
  ShieldAlert,
  Flame,
  Radio,
  Search,
  Filter,
  AlertTriangle,
  Play,
  Clock,
  Terminal,
  Activity,
  User,
  RefreshCw,
  X,
  FileCode2
} from 'lucide-react'

export interface SecurityAlert {
  id: string
  title: string
  description?: string | null
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: 'open' | 'investigating' | 'resolved' | 'dismissed' | 'escalated'
  confidence_score: number
  rule_id?: string | null
  rule_name?: string | null
  mitre_attack_id?: string | null
  source_ip?: string | null
  destination_ip?: string | null
  target_user?: string | null
  asset_id?: string | null
  evidence?: Record<string, unknown> | null
  created_at: string
  updated_at: string
}

export interface SecurityEvent {
  id: string
  event_type: string
  source: string
  source_ip?: string | null
  destination_ip?: string | null
  destination_port?: number | null
  username?: string | null
  raw_log?: string | null
  details?: Record<string, unknown> | null
  created_at: string
}

export interface DetectionRule {
  id: string
  name: string
  description?: string | null
  rule_type: string
  severity: string
  is_enabled: boolean
  mitre_attack_id?: string | null
  condition_config?: Record<string, unknown> | null
}

const DEMO_RULES: DetectionRule[] = [
  {
    id: 'rule-auth-1',
    name: 'RULE-AUTH-001: Repeated Failed Login Brute Force',
    description: 'Triggers when 5 or more failed authentication events occur within 5 minutes.',
    rule_type: 'brute_force',
    severity: 'high',
    is_enabled: true,
    mitre_attack_id: 'T1110',
    condition_config: { threshold: 5, window_seconds: 300 }
  },
  {
    id: 'rule-ioc-1',
    name: 'RULE-IOC-001: Malicious File Hash (Known Threat)',
    description: 'Triggers when an ingested event contains a known malware SHA-256 or MD5 hash signature.',
    rule_type: 'malicious_hash',
    severity: 'critical',
    is_enabled: true,
    mitre_attack_id: 'T1204',
    condition_config: { ioc_hashes: ['275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'] }
  },
  {
    id: 'rule-priv-1',
    name: 'RULE-PRIV-001: Unusual Privilege Escalation',
    description: 'Triggers upon unauthorized administrative elevation attempts, su/sudo abuse, or admin creations.',
    rule_type: 'privilege_escalation',
    severity: 'high',
    is_enabled: true,
    mitre_attack_id: 'T1078',
    condition_config: { keywords: ['sudo', 'setuid', 'chmod +s', 'su root', 'net user /add', 'runas'] }
  },
  {
    id: 'rule-net-1',
    name: 'RULE-NET-001: Unauthorized Inbound Connection to Sensitive Port',
    description: 'Triggers on unauthorized external connections to administrative ports (22, 23, 3389, 445).',
    rule_type: 'unauthorized_connection',
    severity: 'medium',
    is_enabled: true,
    mitre_attack_id: 'T1071',
    condition_config: { restricted_ports: [22, 23, 3389, 445] }
  }
]

const DEMO_ALERTS: SecurityAlert[] = [
  {
    id: 'alt-1',
    title: 'Known Malicious File Hash Detected: 275a021bbfb6489e...',
    description: 'File hash matches known threat IOC signature from EDR sensor.',
    severity: 'critical',
    status: 'open',
    confidence_score: 0.99,
    rule_name: 'RULE-IOC-001: Malicious File Hash (Known Threat)',
    mitre_attack_id: 'T1204',
    source_ip: '10.0.5.12',
    target_user: 'john_doe',
    evidence: { matched_hash: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', file_path: '/tmp/suspicious_payload.bin' },
    created_at: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
    updated_at: new Date(Date.now() - 1000 * 60 * 12).toISOString()
  },
  {
    id: 'alt-2',
    title: 'SSH Brute Force Attack Detected (198.51.100.24)',
    description: '6 failed login attempts detected within 5-minute threshold.',
    severity: 'high',
    status: 'investigating',
    confidence_score: 0.95,
    rule_name: 'RULE-AUTH-001: Repeated Failed Login Brute Force',
    mitre_attack_id: 'T1110',
    source_ip: '198.51.100.24',
    target_user: 'root',
    evidence: { fail_count: 6, source: 'sshd_audit' },
    created_at: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    updated_at: new Date(Date.now() - 1000 * 60 * 10).toISOString()
  },
  {
    id: 'alt-3',
    title: 'Privilege Escalation Detected (guest_user)',
    description: 'Administrative escalation command/event triggered by guest_user.',
    severity: 'high',
    status: 'open',
    confidence_score: 0.90,
    rule_name: 'RULE-PRIV-001: Unusual Privilege Escalation',
    mitre_attack_id: 'T1078',
    source_ip: '10.0.2.14',
    target_user: 'guest_user',
    evidence: { command: 'sudo -i', raw_log: 'guest_user executed sudo su root' },
    created_at: new Date(Date.now() - 1000 * 60 * 90).toISOString(),
    updated_at: new Date(Date.now() - 1000 * 60 * 90).toISOString()
  },
  {
    id: 'alt-4',
    title: 'Inbound Connection to Restricted Port 3389',
    description: 'Inbound external connection from untrusted IP to sensitive RDP port.',
    severity: 'medium',
    status: 'resolved',
    confidence_score: 0.80,
    rule_name: 'RULE-NET-001: Unauthorized Inbound Connection to Sensitive Port',
    mitre_attack_id: 'T1071',
    source_ip: '203.0.113.88',
    destination_ip: '10.0.1.15',
    evidence: { destination_port: 3389, protocol: 'tcp' },
    created_at: new Date(Date.now() - 1000 * 60 * 240).toISOString(),
    updated_at: new Date(Date.now() - 1000 * 60 * 180).toISOString()
  }
]

const DEMO_EVENTS: SecurityEvent[] = [
  {
    id: 'evt-1',
    event_type: 'malware_indicator',
    source: 'edr_agent',
    source_ip: '10.0.5.12',
    username: 'john_doe',
    raw_log: 'EDR-ALERT: Suspicious file execution blocked in user temp directory',
    details: { file_path: '/tmp/suspicious_payload.bin', file_hash: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f' },
    created_at: new Date(Date.now() - 1000 * 60 * 12).toISOString()
  },
  {
    id: 'evt-2',
    event_type: 'auth_failure',
    source: 'sshd_gateway',
    source_ip: '198.51.100.24',
    username: 'root',
    raw_log: 'Failed password for root from 198.51.100.24 port 44812 ssh2',
    created_at: new Date(Date.now() - 1000 * 60 * 45).toISOString()
  },
  {
    id: 'evt-3',
    event_type: 'privilege_escalation',
    source: 'auditd',
    source_ip: '10.0.2.14',
    username: 'guest_user',
    raw_log: 'USER_CMD: sudo su root [status=SUCCESS]',
    details: { command: 'sudo -i' },
    created_at: new Date(Date.now() - 1000 * 60 * 90).toISOString()
  },
  {
    id: 'evt-4',
    event_type: 'network_connection',
    source: 'pfsense_border',
    source_ip: '203.0.113.88',
    destination_ip: '10.0.1.15',
    destination_port: 3389,
    raw_log: 'BLOCK: INBOUND TCP SYN from 203.0.113.88:51221 to 10.0.1.15:3389',
    created_at: new Date(Date.now() - 1000 * 60 * 240).toISOString()
  }
]

export function SecurityMonitoring() {
  const [alerts, setAlerts] = useState<SecurityAlert[]>(DEMO_ALERTS)
  const [events, setEvents] = useState<SecurityEvent[]>(DEMO_EVENTS)
  const [rules, setRules] = useState<DetectionRule[]>(DEMO_RULES)
  const [subTab, setSubTab] = useState<'alerts' | 'telemetry' | 'rules'>('alerts')
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null)
  const [simulating, setSimulating] = useState(false)
  const [simulationSuccess, setSimulationSuccess] = useState<string | null>(null)

  const fetchMonitoringData = async () => {
    try {
      const [alertsRes, rulesRes] = await Promise.all([
        fetch('http://localhost:8000/api/v1/monitoring/alerts?limit=50'),
        fetch('http://localhost:8000/api/v1/monitoring/rules')
      ])

      if (alertsRes.ok) {
        const alertsData = await alertsRes.json()
        if (Array.isArray(alertsData) && alertsData.length > 0) {
          setAlerts(alertsData)
        }
      }

      if (rulesRes.ok) {
        const rulesData = await rulesRes.json()
        if (Array.isArray(rulesData) && rulesData.length > 0) {
          setRules(rulesData)
        }
      }
    } catch {
      // Fallback silently to mock demo state
    }
  }

  useEffect(() => {
    fetchMonitoringData()
  }, [])

  const handleUpdateAlertStatus = async (alertId: string, newStatus: string) => {
    try {
      const res = await fetch(`http://localhost:8000/api/v1/monitoring/alerts/${alertId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      })

      if (res.ok) {
        const updated = await res.json()
        setAlerts((prev) => prev.map((a) => (a.id === alertId ? updated : a)))
        if (selectedAlert && selectedAlert.id === alertId) {
          setSelectedAlert(updated)
        }
        return
      }
    } catch {
      // Fallback local update
    }

    setAlerts((prev) =>
      prev.map((a) => (a.id === alertId ? { ...a, status: newStatus as SecurityAlert['status'] } : a))
    )
    if (selectedAlert && selectedAlert.id === alertId) {
      setSelectedAlert({ ...selectedAlert, status: newStatus as SecurityAlert['status'] })
    }
  }

  const simulateAttack = async (scenario: 'brute_force' | 'ioc_hash' | 'priv_esc' | 'unauth_port') => {
    setSimulating(true)
    setSimulationSuccess(null)

    let payload: Record<string, unknown> = {}
    let scenarioLabel = ''

    if (scenario === 'brute_force') {
      scenarioLabel = 'Brute Force Attack (5 Failed Logins)'
      for (let i = 0; i < 5; i++) {
        payload = {
          event_type: 'auth_failure',
          source: 'ssh_edge_gateway',
          source_ip: '203.0.113.199',
          username: 'admin_test',
          raw_log: `pam_unix(sshd:auth): authentication failure for user admin_test attempt ${i + 1}`
        }
        try {
          await fetch('http://localhost:8000/api/v1/monitoring/events', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
          })
        } catch {
          // Continue loop
        }
      }
    } else if (scenario === 'ioc_hash') {
      scenarioLabel = 'Known EICAR Malware Hash Indicator'
      payload = {
        event_type: 'malware_indicator',
        source: 'endpoint_edr_sensor',
        source_ip: '10.0.10.88',
        username: 'alice.security',
        details: {
          file_hash: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
          file_name: 'trojan_payload.exe',
          file_path: 'C:\\Users\\alice\\Downloads\\trojan_payload.exe'
        },
        raw_log: 'EDR-IOC: SHA256 matches threat intelligence database signature'
      }
      try {
        await fetch('http://localhost:8000/api/v1/monitoring/events', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        })
      } catch {
        // Mock fallback
      }
    } else if (scenario === 'priv_esc') {
      scenarioLabel = 'Privilege Escalation Event'
      payload = {
        event_type: 'privilege_escalation',
        source: 'auditd_sensor',
        source_ip: '10.0.1.55',
        username: 'webapp_service',
        details: { command: 'sudo -i' },
        raw_log: 'AUDIT_AUTH_PRIVILEGE_ESCALATION: webapp_service gained root interactive shell'
      }
      try {
        await fetch('http://localhost:8000/api/v1/monitoring/events', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        })
      } catch {
        // Mock fallback
      }
    } else if (scenario === 'unauth_port') {
      scenarioLabel = 'Restricted Port Scan (Port 3389)'
      payload = {
        event_type: 'network_connection',
        source: 'perimeter_firewall',
        source_ip: '198.51.100.77',
        destination_ip: '10.0.1.20',
        destination_port: 3389,
        raw_log: 'Firewall detected inbound probe on sensitive administrative port 3389'
      }
      try {
        await fetch('http://localhost:8000/api/v1/monitoring/events', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        })
      } catch {
        // Mock fallback
      }
    }

    // Refresh live alerts & events
    await fetchMonitoringData()

    // Add local event & alert simulation if backend is offline
    const newSimEvent: SecurityEvent = {
      id: `evt-${Date.now()}`,
      event_type: String(payload.event_type || 'simulated_event'),
      source: String(payload.source || 'simulator'),
      source_ip: String(payload.source_ip || '127.0.0.1'),
      destination_port: (payload.destination_port as number) || undefined,
      username: (payload.username as string) || undefined,
      raw_log: String(payload.raw_log || 'Simulation triggered'),
      details: payload.details as Record<string, unknown>,
      created_at: new Date().toISOString()
    }
    setEvents((prev) => [newSimEvent, ...prev])

    const newSimAlert: SecurityAlert = {
      id: `alt-${Date.now()}`,
      title: `${scenarioLabel} Triggered`,
      description: `Rule detection engine flagged suspicious activity: ${scenarioLabel}`,
      severity: scenario === 'ioc_hash' ? 'critical' : scenario === 'unauth_port' ? 'medium' : 'high',
      status: 'open',
      confidence_score: 0.95,
      rule_name: scenario.toUpperCase(),
      mitre_attack_id: scenario === 'brute_force' ? 'T1110' : scenario === 'ioc_hash' ? 'T1204' : scenario === 'priv_esc' ? 'T1078' : 'T1071',
      source_ip: String(payload.source_ip || '127.0.0.1'),
      target_user: (payload.username as string) || undefined,
      evidence: payload,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    }
    setAlerts((prev) => [newSimAlert, ...prev])

    setSimulating(false)
    setSimulationSuccess(scenarioLabel)
    setTimeout(() => setSimulationSuccess(null), 5000)
  }

  const filteredAlerts = alerts.filter((a) => {
    const matchesSearch =
      search === '' ||
      a.title.toLowerCase().includes(search.toLowerCase()) ||
      (a.source_ip && a.source_ip.toLowerCase().includes(search.toLowerCase())) ||
      (a.mitre_attack_id && a.mitre_attack_id.toLowerCase().includes(search.toLowerCase())) ||
      (a.target_user && a.target_user.toLowerCase().includes(search.toLowerCase()))

    const matchesSeverity = severityFilter === 'ALL' || a.severity.toUpperCase() === severityFilter
    const matchesStatus = statusFilter === 'ALL' || a.status.toUpperCase() === statusFilter

    return matchesSearch && matchesSeverity && matchesStatus
  })

  const criticalCount = alerts.filter((a) => a.severity === 'critical').length
  const highCount = alerts.filter((a) => a.severity === 'high').length
  const openCount = alerts.filter((a) => a.status === 'open').length
  const investigatingCount = alerts.filter((a) => a.status === 'investigating').length

  const getSeverityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return 'bg-red-500/15 text-red-400 border-red-500/40'
      case 'high':
        return 'bg-orange-500/15 text-orange-400 border-orange-500/40'
      case 'medium':
        return 'bg-amber-500/15 text-amber-400 border-amber-500/40'
      case 'low':
        return 'bg-blue-500/15 text-blue-400 border-blue-500/40'
      default:
        return 'bg-slate-500/15 text-slate-400 border-slate-500/40'
    }
  }

  const getStatusBadge = (status: string) => {
    switch (status.toLowerCase()) {
      case 'open':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30'
      case 'investigating':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30'
      case 'resolved':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
      case 'dismissed':
        return 'bg-slate-500/10 text-slate-400 border-slate-500/30'
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700'
    }
  }

  return (
    <div className="space-y-6">
      {/* Simulation Banner / Notification */}
      {simulationSuccess && (
        <div className="p-4 rounded-xl border border-cyan-500/40 bg-cyan-950/40 text-cyan-300 flex items-center justify-between shadow-lg shadow-cyan-950/50">
          <div className="flex items-center gap-3">
            <Radio className="w-5 h-5 text-cyan-400 animate-pulse" />
            <div>
              <p className="text-sm font-semibold">Security Telemetry Ingested &amp; Evaluated!</p>
              <p className="text-xs text-cyan-400/80 font-mono">
                Scenario: {simulationSuccess}. Rule engine flagged threat and created triage alert.
              </p>
            </div>
          </div>
          <button onClick={() => setSimulationSuccess(null)} className="text-cyan-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Metrics Ribbon */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-red-500/5 rounded-bl-full pointer-events-none" />
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Critical Alerts</span>
            <Flame className="w-4 h-4 text-red-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-red-400">{criticalCount}</span>
            <span className="text-xs text-slate-500 font-mono">Active zero-day / IOC</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-orange-500/5 rounded-bl-full pointer-events-none" />
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">High Severity</span>
            <AlertTriangle className="w-4 h-4 text-orange-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-orange-400">{highCount}</span>
            <span className="text-xs text-slate-500 font-mono">Escalations &amp; Brute-force</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-amber-500/5 rounded-bl-full pointer-events-none" />
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">In Investigation</span>
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-amber-400">{investigatingCount}</span>
            <span className="text-xs text-slate-500 font-mono">{openCount} unassigned open</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-cyan-500/5 rounded-bl-full pointer-events-none" />
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Active Rules</span>
            <Radio className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-cyan-400">{rules.length}</span>
            <span className="text-xs text-slate-500 font-mono">MITRE ATT&amp;CK synced</span>
          </div>
        </div>
      </div>

      {/* Attack Scenario Simulation Toolbar */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-slate-900/90 via-[#0c142c] to-slate-900/90 border border-slate-800/80 shadow-md">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Play className="w-4 h-4 text-cyan-400" />
              <span className="text-sm font-bold text-white tracking-wide">Threat Simulation &amp; Log Injection Harness</span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Inject synthetic telemetry payloads to verify detection rules, MITRE ATT&amp;CK mapping, and alert triage.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              disabled={simulating}
              onClick={() => simulateAttack('brute_force')}
              className="px-3 py-1.5 rounded-lg bg-orange-950/60 border border-orange-700/50 hover:bg-orange-900/80 text-orange-300 text-xs font-mono transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            >
              <Flame className="w-3.5 h-3.5 text-orange-400" />
              Simulate Brute Force (T1110)
            </button>

            <button
              disabled={simulating}
              onClick={() => simulateAttack('ioc_hash')}
              className="px-3 py-1.5 rounded-lg bg-red-950/60 border border-red-700/50 hover:bg-red-900/80 text-red-300 text-xs font-mono transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            >
              <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
              Simulate Malware Hash (T1204)
            </button>

            <button
              disabled={simulating}
              onClick={() => simulateAttack('priv_esc')}
              className="px-3 py-1.5 rounded-lg bg-amber-950/60 border border-amber-700/50 hover:bg-amber-900/80 text-amber-300 text-xs font-mono transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            >
              <User className="w-3.5 h-3.5 text-amber-400" />
              Simulate Privilege Escalation (T1078)
            </button>

            <button
              disabled={simulating}
              onClick={() => simulateAttack('unauth_port')}
              className="px-3 py-1.5 rounded-lg bg-blue-950/60 border border-blue-700/50 hover:bg-blue-900/80 text-blue-300 text-xs font-mono transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            >
              <Radio className="w-3.5 h-3.5 text-blue-400" />
              Simulate Port Scan (T1071)
            </button>
          </div>
        </div>
      </div>

      {/* Tabs Bar */}
      <div className="flex border-b border-slate-800 gap-6">
        <button
          onClick={() => setSubTab('alerts')}
          className={`pb-3 text-sm font-mono flex items-center gap-2 border-b-2 transition cursor-pointer ${
            subTab === 'alerts'
              ? 'border-cyan-500 text-cyan-400 font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          Alerts Triage Queue ({alerts.length})
        </button>

        <button
          onClick={() => setSubTab('telemetry')}
          className={`pb-3 text-sm font-mono flex items-center gap-2 border-b-2 transition cursor-pointer ${
            subTab === 'telemetry'
              ? 'border-cyan-500 text-cyan-400 font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Activity className="w-4 h-4" />
          Raw Telemetry &amp; Log Stream ({events.length})
        </button>

        <button
          onClick={() => setSubTab('rules')}
          className={`pb-3 text-sm font-mono flex items-center gap-2 border-b-2 transition cursor-pointer ${
            subTab === 'rules'
              ? 'border-cyan-500 text-cyan-400 font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileCode2 className="w-4 h-4" />
          Detection Rules Catalog ({rules.length})
        </button>
      </div>

      {/* SUB-VIEW 1: ALERTS TRIAGE QUEUE */}
      {subTab === 'alerts' && (
        <div className="space-y-4">
          {/* Search & Filter Controls */}
          <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center justify-between">
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search alerts by title, MITRE ID, IP, or user..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full pl-9 pr-4 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2">
                <Filter className="w-3.5 h-3.5 text-slate-500" />
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>

              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Statuses</option>
                <option value="OPEN">Open</option>
                <option value="INVESTIGATING">Investigating</option>
                <option value="RESOLVED">Resolved</option>
                <option value="DISMISSED">Dismissed</option>
              </select>

              <button
                onClick={fetchMonitoringData}
                className="p-2 bg-slate-900 border border-slate-800 hover:bg-slate-800 rounded-lg text-slate-400 hover:text-slate-200 transition cursor-pointer"
                title="Refresh alerts"
              >
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Alerts Table */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 backdrop-blur-sm overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/80 text-slate-400 font-mono uppercase tracking-wider border-b border-slate-800">
                  <tr>
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4">Alert Title &amp; Detection Rule</th>
                    <th className="py-3 px-4">MITRE ATT&amp;CK</th>
                    <th className="py-3 px-4">Source / Target</th>
                    <th className="py-3 px-4">Confidence</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-sans">
                  {filteredAlerts.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-8 text-center text-slate-500 font-mono">
                        No security alerts match the current filter criteria.
                      </td>
                    </tr>
                  ) : (
                    filteredAlerts.map((alert) => (
                      <tr key={alert.id} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-3 px-4">
                          <span
                            className={`inline-block px-2 py-0.5 rounded text-[11px] font-mono uppercase font-bold border ${getSeverityBadge(
                              alert.severity
                            )}`}
                          >
                            {alert.severity}
                          </span>
                        </td>
                        <td className="py-3 px-4 max-w-md">
                          <p className="font-semibold text-slate-200">{alert.title}</p>
                          <p className="text-[11px] text-slate-400 font-mono truncate mt-0.5">
                            {alert.rule_name || alert.description}
                          </p>
                        </td>
                        <td className="py-3 px-4 font-mono">
                          {alert.mitre_attack_id ? (
                            <span className="px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-400 border border-cyan-800/40 text-[11px] font-bold">
                              {alert.mitre_attack_id}
                            </span>
                          ) : (
                            <span className="text-slate-600">-</span>
                          )}
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-300">
                          {alert.source_ip && <div>IP: {alert.source_ip}</div>}
                          {alert.target_user && <div className="text-slate-500 text-[11px]">User: {alert.target_user}</div>}
                          {!alert.source_ip && !alert.target_user && <span className="text-slate-600">N/A</span>}
                        </td>
                        <td className="py-3 px-4 font-mono">
                          <span className="text-cyan-400 font-semibold">{Math.round(alert.confidence_score * 100)}%</span>
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`inline-block px-2 py-0.5 rounded text-[11px] font-mono capitalize border ${getStatusBadge(
                              alert.status
                            )}`}
                          >
                            {alert.status}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              onClick={() => setSelectedAlert(alert)}
                              className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition cursor-pointer"
                            >
                              Details
                            </button>
                            {alert.status === 'open' && (
                              <button
                                onClick={() => handleUpdateAlertStatus(alert.id, 'investigating')}
                                className="px-2 py-1 rounded bg-amber-950/50 hover:bg-amber-900/60 text-amber-300 border border-amber-700/40 text-xs font-mono transition cursor-pointer"
                              >
                                Triage
                              </button>
                            )}
                            {alert.status === 'investigating' && (
                              <button
                                onClick={() => handleUpdateAlertStatus(alert.id, 'resolved')}
                                className="px-2 py-1 rounded bg-emerald-950/50 hover:bg-emerald-900/60 text-emerald-300 border border-emerald-700/40 text-xs font-mono transition cursor-pointer"
                              >
                                Resolve
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* SUB-VIEW 2: RAW TELEMETRY & LOG STREAM */}
      {subTab === 'telemetry' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              Real-time Ingested Security Telemetry Stream
            </h3>
            <p className="text-xs text-slate-400 font-mono mt-1">
              Events are normalized into standard formats, validated, and continuously passed to the detection pipeline.
            </p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-950 overflow-hidden font-mono text-xs">
            <div className="bg-slate-900/80 px-4 py-2 border-b border-slate-800 flex items-center justify-between text-slate-400">
              <span>EVENT STREAM LOG ({events.length} events buffered)</span>
              <span className="flex items-center gap-1.5 text-[11px] text-emerald-400">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                Live Ingestion Engine Active
              </span>
            </div>
            <div className="p-4 space-y-3 max-h-[500px] overflow-y-auto">
              {events.map((evt) => (
                <div key={evt.id} className="p-3 rounded-lg bg-slate-900/40 border border-slate-800/80 hover:border-slate-700 transition">
                  <div className="flex flex-wrap items-center justify-between gap-2 text-slate-400 text-[11px] mb-1">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/60 font-bold uppercase">
                        {evt.event_type}
                      </span>
                      <span>Source: <strong className="text-slate-300">{evt.source}</strong></span>
                      {evt.source_ip && <span>IP: <strong className="text-slate-300">{evt.source_ip}</strong></span>}
                      {evt.username && <span>User: <strong className="text-slate-300">{evt.username}</strong></span>}
                    </div>
                    <span>{new Date(evt.created_at).toLocaleTimeString()}</span>
                  </div>
                  <div className="text-slate-300 font-mono text-[11px] bg-black/40 p-2 rounded border border-slate-900">
                    {evt.raw_log || JSON.stringify(evt.details || {})}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* SUB-VIEW 3: DETECTION RULES CATALOG */}
      {subTab === 'rules' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {rules.map((rule) => (
              <div key={rule.id} className="p-5 rounded-xl border border-slate-800 bg-slate-900/60 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wide">
                      {rule.name.split(':')[0]}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold border ${getSeverityBadge(rule.severity)}`}>
                      {rule.severity}
                    </span>
                  </div>
                  <h4 className="text-sm font-bold text-white mb-1.5">{rule.name}</h4>
                  <p className="text-xs text-slate-400 font-sans leading-relaxed mb-4">{rule.description}</p>
                </div>

                <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs font-mono">
                  <div className="flex items-center gap-2">
                    <span className="text-slate-500">MITRE:</span>
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700 font-bold">
                      {rule.mitre_attack_id}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-emerald-400" />
                    <span className="text-emerald-400 font-bold">ACTIVE</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ALERT DETAILS MODAL */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full p-6 space-y-6 shadow-2xl relative">
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <span className={`px-2 py-0.5 rounded text-[11px] font-mono uppercase font-bold border ${getSeverityBadge(selectedAlert.severity)}`}>
                    {selectedAlert.severity}
                  </span>
                  {selectedAlert.mitre_attack_id && (
                    <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/40 text-[11px] font-mono font-bold">
                      MITRE ATT&amp;CK {selectedAlert.mitre_attack_id}
                    </span>
                  )}
                </div>
                <h3 className="text-lg font-bold text-white">{selectedAlert.title}</h3>
                <p className="text-xs text-slate-400 font-mono mt-0.5">{selectedAlert.rule_name}</p>
              </div>
              <button onClick={() => setSelectedAlert(null)} className="text-slate-400 hover:text-white cursor-pointer">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-4 p-4 rounded-lg bg-slate-950/80 border border-slate-800 text-xs font-mono">
              <div>
                <span className="text-slate-500">Source IP:</span>
                <p className="text-slate-200 font-semibold">{selectedAlert.source_ip || 'N/A'}</p>
              </div>
              <div>
                <span className="text-slate-500">Target User:</span>
                <p className="text-slate-200 font-semibold">{selectedAlert.target_user || 'N/A'}</p>
              </div>
              <div>
                <span className="text-slate-500">Confidence Score:</span>
                <p className="text-cyan-400 font-semibold">{Math.round(selectedAlert.confidence_score * 100)}%</p>
              </div>
              <div>
                <span className="text-slate-500">Status:</span>
                <p className="text-slate-200 capitalize font-semibold">{selectedAlert.status}</p>
              </div>
            </div>

            <div>
              <h4 className="text-xs font-mono uppercase text-slate-400 tracking-wider mb-2">Detection Evidence &amp; Payload</h4>
              <pre className="bg-black/60 p-4 rounded-lg border border-slate-800 text-xs font-mono text-cyan-300 overflow-x-auto max-h-48">
                {JSON.stringify(selectedAlert.evidence || {}, null, 2)}
              </pre>
            </div>

            <div className="flex items-center justify-between pt-4 border-t border-slate-800">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleUpdateAlertStatus(selectedAlert.id, 'investigating')}
                  className="px-3 py-1.5 rounded-lg bg-amber-950/60 border border-amber-700/50 hover:bg-amber-900/80 text-amber-300 text-xs font-mono transition cursor-pointer"
                >
                  Mark Investigating
                </button>
                <button
                  onClick={() => handleUpdateAlertStatus(selectedAlert.id, 'resolved')}
                  className="px-3 py-1.5 rounded-lg bg-emerald-950/60 border border-emerald-700/50 hover:bg-emerald-900/80 text-emerald-300 text-xs font-mono transition cursor-pointer"
                >
                  Mark Resolved
                </button>
                <button
                  onClick={() => handleUpdateAlertStatus(selectedAlert.id, 'dismissed')}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 text-xs font-mono transition cursor-pointer"
                >
                  Dismiss
                </button>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-semibold transition cursor-pointer"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
