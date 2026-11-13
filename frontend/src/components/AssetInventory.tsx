import { useState, useEffect } from 'react'
import {
  Server,
  Shield,
  Plus,
  Search,
  Filter,
  AlertTriangle,
  X,
  RefreshCw,
  Activity
} from 'lucide-react'

export interface PortInfo {
  port: number
  service?: string
  protocol?: string
  state?: string
}

export interface Asset {
  id: string
  name: string
  hostname?: string | null
  ip_address?: string | null
  mac_address?: string | null
  asset_type: string
  criticality: string
  status: string
  environment: string
  os_family?: string | null
  os_version?: string | null
  open_ports?: PortInfo[] | null
  tags?: string[] | null
  description?: string | null
  owner?: string | null
  created_at: string
}

export interface AssetStats {
  total_assets: number
  active_assets: number
  critical_assets: number
  high_risk_assets: number
  by_type: Record<string, number>
  by_environment: Record<string, number>
  by_criticality: Record<string, number>
}

// Initial demo assets to display when backend database is empty or offline
const DEMO_ASSETS: Asset[] = [
  {
    id: 'demo-1',
    name: 'prod-api-gateway-01',
    hostname: 'api-gateway.aegisflow.corp',
    ip_address: '10.0.1.15',
    mac_address: '00:50:56:A1:B2:C3',
    asset_type: 'server',
    criticality: 'critical',
    status: 'active',
    environment: 'production',
    os_family: 'Linux',
    os_version: 'Ubuntu 24.04 LTS',
    open_ports: [
      { port: 443, service: 'https', protocol: 'tcp', state: 'open' },
      { port: 80, service: 'http', protocol: 'tcp', state: 'open' },
      { port: 22, service: 'ssh', protocol: 'tcp', state: 'open' }
    ],
    tags: ['ingress', 'api', 'pci-dss'],
    description: 'Main production reverse proxy and API cluster ingress',
    owner: 'DevOps / Platform Security',
    created_at: new Date().toISOString()
  },
  {
    id: 'demo-2',
    name: 'edge-firewall-paloalto',
    hostname: 'fw01-edge.hq.aegis.corp',
    ip_address: '10.0.0.1',
    mac_address: '00:1B:17:F4:3D:09',
    asset_type: 'firewall',
    criticality: 'critical',
    status: 'active',
    environment: 'production',
    os_family: 'PAN-OS',
    os_version: 'v11.1.2',
    open_ports: [
      { port: 443, service: 'mgmt-web', protocol: 'tcp', state: 'open' },
      { port: 500, service: 'ipsec-ike', protocol: 'udp', state: 'open' }
    ],
    tags: ['perimeter', 'zero-trust', 'vpn'],
    description: 'HQ perimeter security gateway and IPsec tunnel terminator',
    owner: 'Network Security Team',
    created_at: new Date().toISOString()
  },
  {
    id: 'demo-3',
    name: 'k8s-worker-node-04',
    hostname: 'k8s-node04.prod.cloud',
    ip_address: '10.0.4.88',
    mac_address: '02:42:0A:00:04:58',
    asset_type: 'cloud_instance',
    criticality: 'high',
    status: 'active',
    environment: 'production',
    os_family: 'Linux',
    os_version: 'Debian 12 Bookworm',
    open_ports: [
      { port: 10250, service: 'kubelet', protocol: 'tcp', state: 'open' },
      { port: 9100, service: 'node-exporter', protocol: 'tcp', state: 'open' }
    ],
    tags: ['kubernetes', 'cloud', 'container-runtime'],
    description: 'Kubernetes cluster computation worker node',
    owner: 'Infrastructure Engineering',
    created_at: new Date().toISOString()
  },
  {
    id: 'demo-4',
    name: 'analyst-soc-station-07',
    hostname: 'ws-analyst07.aegis.corp',
    ip_address: '192.168.10.42',
    mac_address: '3C:52:82:11:90:EA',
    asset_type: 'workstation',
    criticality: 'medium',
    status: 'active',
    environment: 'internal',
    os_family: 'Windows',
    os_version: 'Windows 11 Enterprise 24H2',
    open_ports: [
      { port: 3389, service: 'rdp', protocol: 'tcp', state: 'filtered' }
    ],
    tags: ['endpoint', 'soc-team', 'edr-enforced'],
    description: 'Dedicated SOC Analyst investigation workstation',
    owner: 'Tier-2 Incident Response',
    created_at: new Date().toISOString()
  }
]

export function AssetInventory() {
  const [assets, setAssets] = useState<Asset[]>(DEMO_ASSETS)
  const [loading, setLoading] = useState(false)
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [critFilter, setCritFilter] = useState('all')
  const [isModalOpen, setIsModalOpen] = useState(false)

  // Form state for creating a new asset
  const [newName, setNewName] = useState('')
  const [newHostname, setNewHostname] = useState('')
  const [newIp, setNewIp] = useState('')
  const [newType, setNewType] = useState('server')
  const [newCriticality, setNewCriticality] = useState('medium')
  const [newEnv, setNewEnv] = useState('production')
  const [newOsFamily, setNewOsFamily] = useState('Linux')
  const [newPorts, setNewPorts] = useState('80:http, 443:https, 22:ssh')
  const [newOwner, setNewOwner] = useState('')

  const fetchAssets = async () => {
    setLoading(true)
    try {
      const res = await fetch('http://localhost:8000/api/v1/assets?limit=50')
      if (res.ok) {
        const data = await res.json()
        if (data.items && data.items.length > 0) {
          setAssets(data.items)
        }
      }
    } catch {
      // Backend not running or unauthenticated; retain loaded/demo assets
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAssets()
  }, [])

  const handleCreateAsset = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newName) return

    const parsedPorts: PortInfo[] = newPorts
      .split(',')
      .map(p => p.trim())
      .filter(Boolean)
      .map(entry => {
        const [portStr, service] = entry.split(':')
        const portNum = parseInt(portStr.trim(), 10)
        return {
          port: isNaN(portNum) ? 80 : portNum,
          service: service ? service.trim() : 'unknown',
          protocol: 'tcp',
          state: 'open'
        }
      })

    const payload = {
      name: newName,
      hostname: newHostname || null,
      ip_address: newIp || null,
      asset_type: newType,
      criticality: newCriticality,
      status: 'active',
      environment: newEnv,
      os_family: newOsFamily,
      open_ports: parsedPorts,
      owner: newOwner || null,
      tags: ['registered-ui']
    }

    try {
      const res = await fetch('http://localhost:8000/api/v1/assets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })
      if (res.ok) {
        const created = await res.json()
        setAssets([created, ...assets])
      } else {
        // Fallback local addition if API requires Bearer auth
        const localAsset: Asset = {
          ...payload,
          id: `local-${Date.now()}`,
          created_at: new Date().toISOString()
        }
        setAssets([localAsset, ...assets])
      }
    } catch {
      const localAsset: Asset = {
        ...payload,
        id: `local-${Date.now()}`,
        created_at: new Date().toISOString()
      }
      setAssets([localAsset, ...assets])
    }

    setIsModalOpen(false)
    setNewName('')
    setNewHostname('')
    setNewIp('')
    setNewOwner('')
  }

  const filteredAssets = assets.filter(a => {
    const matchesSearch =
      !search ||
      a.name.toLowerCase().includes(search.toLowerCase()) ||
      (a.hostname && a.hostname.toLowerCase().includes(search.toLowerCase())) ||
      (a.ip_address && a.ip_address.includes(search))

    const matchesType = typeFilter === 'all' || a.asset_type === typeFilter
    const matchesCrit = critFilter === 'all' || a.criticality === critFilter

    return matchesSearch && matchesType && matchesCrit
  })

  const totalAssets = assets.length
  const criticalAssets = assets.filter(a => a.criticality === 'critical').length
  const highAssets = assets.filter(a => a.criticality === 'high').length
  const activeAssets = assets.filter(a => a.status === 'active').length

  const getCriticalityBadge = (crit: string) => {
    switch (crit) {
      case 'critical':
        return 'bg-rose-950/80 text-rose-300 border-rose-700/80'
      case 'high':
        return 'bg-amber-950/80 text-amber-300 border-amber-700/80'
      case 'medium':
        return 'bg-yellow-950/60 text-yellow-300 border-yellow-700/60'
      case 'low':
        return 'bg-blue-950/60 text-blue-300 border-blue-700/60'
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700'
    }
  }

  return (
    <div className="space-y-6">
      {/* Metrics Ribbon */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
        <div className="rounded-xl border border-slate-800 bg-[#0d152b] p-4 flex items-center justify-between">
          <div>
            <p className="text-xs uppercase font-mono text-slate-400">Total Assets</p>
            <p className="text-2xl font-bold text-white mt-1">{totalAssets}</p>
          </div>
          <div className="p-3 rounded-lg bg-cyan-950/60 border border-cyan-800/50">
            <Server className="w-5 h-5 text-cyan-400" />
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0d152b] p-4 flex items-center justify-between">
          <div>
            <p className="text-xs uppercase font-mono text-slate-400">Critical Tier</p>
            <p className="text-2xl font-bold text-rose-400 mt-1">{criticalAssets}</p>
          </div>
          <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-800/50">
            <AlertTriangle className="w-5 h-5 text-rose-400" />
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0d152b] p-4 flex items-center justify-between">
          <div>
            <p className="text-xs uppercase font-mono text-slate-400">High Risk Assets</p>
            <p className="text-2xl font-bold text-amber-400 mt-1">{highAssets}</p>
          </div>
          <div className="p-3 rounded-lg bg-amber-950/60 border border-amber-800/50">
            <Shield className="w-5 h-5 text-amber-400" />
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0d152b] p-4 flex items-center justify-between">
          <div>
            <p className="text-xs uppercase font-mono text-slate-400">Active Nodes</p>
            <p className="text-2xl font-bold text-emerald-400 mt-1">{activeAssets}</p>
          </div>
          <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-800/50">
            <Activity className="w-5 h-5 text-emerald-400" />
          </div>
        </div>
      </div>

      {/* Control Bar: Search, Filters & Action Button */}
      <div className="flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between bg-[#0b1329] p-4 rounded-xl border border-slate-800">
        <div className="flex flex-1 items-center gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search by name, hostname, or IP address..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full bg-[#060b18] border border-slate-700/80 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-slate-400" />
            <select
              value={typeFilter}
              onChange={e => setTypeFilter(e.target.value)}
              className="bg-[#060b18] border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Types</option>
              <option value="server">Server</option>
              <option value="firewall">Firewall</option>
              <option value="cloud_instance">Cloud Instance</option>
              <option value="workstation">Workstation</option>
              <option value="router">Router</option>
            </select>

            <select
              value={critFilter}
              onChange={e => setCritFilter(e.target.value)}
              className="bg-[#060b18] border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Criticalities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchAssets}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-xs text-slate-300 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            Refresh
          </button>
          <button
            onClick={() => setIsModalOpen(true)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-black font-semibold text-xs transition shadow-md shadow-cyan-600/20"
          >
            <Plus className="w-4 h-4" />
            Register Asset
          </button>
        </div>
      </div>

      {/* Asset Data Table */}
      <div className="rounded-xl border border-slate-800 bg-[#0d152b] overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#070d1d] text-slate-400 uppercase font-mono tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Asset Name &amp; Hostname</th>
                <th className="py-3 px-4">IP &amp; MAC Address</th>
                <th className="py-3 px-4">Type / Environment</th>
                <th className="py-3 px-4">Criticality</th>
                <th className="py-3 px-4">OS &amp; Platform</th>
                <th className="py-3 px-4">Open Ports &amp; Services</th>
                <th className="py-3 px-4">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredAssets.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-10 text-slate-500">
                    No authorized assets found matching your search criteria.
                  </td>
                </tr>
              ) : (
                filteredAssets.map(asset => (
                  <tr key={asset.id} className="hover:bg-slate-800/30 transition">
                    <td className="py-3.5 px-4">
                      <div className="font-semibold text-slate-200">{asset.name}</div>
                      <div className="text-[11px] text-slate-400">{asset.hostname || '—'}</div>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="text-cyan-400 font-semibold">{asset.ip_address || '—'}</div>
                      <div className="text-[10px] text-slate-500">{asset.mac_address || '—'}</div>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="capitalize text-slate-300">{asset.asset_type.replace('_', ' ')}</div>
                      <span className="inline-block mt-0.5 text-[10px] px-1.5 py-0.5 rounded bg-slate-800/80 text-slate-400 border border-slate-700/50 uppercase">
                        {asset.environment}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`inline-block px-2 py-0.5 rounded-full border text-[10px] uppercase font-semibold tracking-wider ${getCriticalityBadge(
                          asset.criticality
                        )}`}
                      >
                        {asset.criticality}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="text-slate-300">{asset.os_family || 'Generic OS'}</div>
                      <div className="text-[10px] text-slate-500">{asset.os_version || '—'}</div>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex flex-wrap gap-1 max-w-[200px]">
                        {asset.open_ports && asset.open_ports.length > 0 ? (
                          asset.open_ports.map((p, idx) => (
                            <span
                              key={idx}
                              className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950/70 border border-cyan-800/60 text-cyan-300"
                            >
                              {p.port}:{p.service || 'open'}
                            </span>
                          ))
                        ) : (
                          <span className="text-slate-500 text-[11px]">No ports listed</span>
                        )}
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="inline-flex items-center gap-1.5 text-[11px] text-emerald-400 font-medium">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                        {asset.status}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal: Register New Asset */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-[#0b1329] border border-slate-700 rounded-2xl w-full max-w-xl overflow-hidden shadow-2xl space-y-4 p-6">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2 text-white font-semibold">
                <Plus className="w-5 h-5 text-cyan-400" />
                <span>Register Authorized Asset</span>
              </div>
              <button
                onClick={() => setIsModalOpen(false)}
                className="text-slate-400 hover:text-white transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreateAsset} className="space-y-4 text-xs font-mono">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-slate-400 mb-1">Asset Name *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. prod-db-01"
                    value={newName}
                    onChange={e => setNewName(e.target.value)}
                    className="w-full bg-[#060b18] border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Hostname</label>
                  <input
                    type="text"
                    placeholder="e.g. db01.corp.internal"
                    value={newHostname}
                    onChange={e => setNewHostname(e.target.value)}
                    className="w-full bg-[#060b18] border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">IP Address</label>
                  <input
                    type="text"
                    placeholder="e.g. 10.0.1.50"
                    value={newIp}
                    onChange={e => setNewIp(e.target.value)}
                    className="w-full bg-[#060b18] border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Asset Type</label>
                  <select
                    value={newType}
                    onChange={e => setNewType(e.target.value)}
                    className="w-full bg-[#060b18] border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="server">Server</option>
                    <option value="firewall">Firewall</option>
                    <option value="cloud_instance">Cloud Instance</option>
                    <option value="workstation">Workstation</option>
                    <option value="router">Router</option>
                    <option value="switch">Switch</option>
                    <option value="iot">IoT Device</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Criticality</label>
                  <select
                    value={newCriticality}
                    onChange={e => setNewCriticality(e.target.value)}
                    className="w-full bg-[#060b18] border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Environment</label>
                  <select
                    value={newEnv}
                    onChange={e => setNewEnv(e.target.value)}
                    className="w-full bg-[#060b18] border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="production">Production</option>
                    <option value="staging">Staging</option>
                    <option value="development">Development</option>
                    <option value="dmz">DMZ</option>
                    <option value="internal">Internal</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">OS Platform</label>
                  <select
                    value={newOsFamily}
                    onChange={e => setNewOsFamily(e.target.value)}
                    className="w-full bg-[#060b18] border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="Linux">Linux (Ubuntu/Debian/RHEL)</option>
                    <option value="Windows">Windows Server / Client</option>
                    <option value="PAN-OS">Palo Alto PAN-OS</option>
                    <option value="Cisco IOS">Cisco IOS / Nexus</option>
                    <option value="macOS">macOS</option>
                    <option value="BSD">FreeBSD / OpenBSD</option>
                    <option value="Embedded">Embedded / IoT</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Open Ports (comma-separated: port:service)</label>
                <input
                  type="text"
                  placeholder="e.g. 80:http, 443:https, 22:ssh"
                  value={newPorts}
                  onChange={e => setNewPorts(e.target.value)}
                  className="w-full bg-[#060b18] border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Owner / Department</label>
                <input
                  type="text"
                  placeholder="e.g. SecOps / Cloud Infrastructure"
                  value={newOwner}
                  onChange={e => setNewOwner(e.target.value)}
                  className="w-full bg-[#060b18] border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-black font-semibold transition"
                >
                  Save Asset
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
