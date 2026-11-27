import { useState, useRef } from 'react';
import type { DragEvent, ChangeEvent } from 'react';
import axios from 'axios';

type MetaPriority = 'Critical' | 'High' | 'Low' | 'Required';
type MetaAction = 'Keep' | 'Remove';

interface ClassifiedMetadetail {
    key: string;
    normalizedKey: string;
    value: any;
    priority: MetaPriority;
    priorityScore: number;
    category: string;
    action: MetaAction;
    isSensitive: boolean;
    isRequired: boolean;
    isEmbeddedWritable: boolean;
    isRuntimeSynthetic: boolean;
    reason: string;
}

interface MetaCoreReport {
    totalCount: number;
    requiredCount: number;
    lowPriorityCount: number;
    highPriorityCount: number;
    criticalPriorityCount: number;
    sensitiveCount: number;
    keptCount: number;
    removedCount: number;
    riskLevel: 'Critical' | 'High' | 'Low' | 'Clean';
    details: ClassifiedMetadetail[];
    keptTags: string[];
    removedTags: string[];
    writablePreserveTags: string[];
}

interface FileResult {
    filename?: string;
    name?: string;
    engine?: string;
    metadata?: Record<string, any>;
    metaCore?: MetaCoreReport;
    gps?: { latitude?: any; longitude?: any; GPSLatitude?: any; GPSLongitude?: any };
}

interface SanitizationResult {
    fileName: string;
    sanitizedFileName: string;
    contentType: string;
    originalSize: number;
    sanitizedSize: number;
    bytesRemoved: number;
    engineUsed: string;
    downloadId: string;
    downloadUrl: string;
    beforeReport: MetaCoreReport;
    afterReport: MetaCoreReport;
    removedFields: ClassifiedMetadetail[];
    keptFields: ClassifiedMetadetail[];
    remainingSensitiveFields: ClassifiedMetadetail[];
    error?: string;
}

const Scan = () => {
    const [mode, setMode] = useState<'file' | 'url'>('file');
    const [files, setFiles] = useState<File[]>([]);
    const [url, setUrl] = useState('');
    const [depth, setDepth] = useState(1);
    const [scanOnly, setScanOnly] = useState(false);

    // MetaCore sanitization policy controls
    const [keepRequired, setKeepRequired] = useState(true);
    const [keepLowPriority, setKeepLowPriority] = useState(true);
    const [strictMode, setStrictMode] = useState(false);
    const [priorityFilter, setPriorityFilter] = useState<'all' | 'sensitive' | 'low' | 'required'>('all');

    const [isDragging, setIsDragging] = useState(false);
    const [progress, setProgress] = useState(0);
    const [progressLabel, setProgressLabel] = useState('');
    const [showProgress, setShowProgress] = useState(false);
    const [errorMsg, setErrorMsg] = useState<string | null>(null);

    const [results, setResults] = useState<FileResult[] | null>(null);
    const [sanitizedResults, setSanitizedResults] = useState<SanitizationResult[] | null>(null);
    const [activeTab, setActiveTab] = useState<'metacore' | 'summary' | 'all-fields' | 'timeline' | 'map'>('metacore');

    const fileInputRef = useRef<HTMLInputElement>(null);

    const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
        e.preventDefault();
        setIsDragging(true);
    };

    const handleDragLeave = () => {
        setIsDragging(false);
    };

    const handleDrop = (e: DragEvent<HTMLDivElement>) => {
        e.preventDefault();
        setIsDragging(false);
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            addFiles(Array.from(e.dataTransfer.files));
        }
    };

    const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files.length > 0) {
            addFiles(Array.from(e.target.files));
        }
        if (fileInputRef.current) fileInputRef.current.value = '';
    };

    const addFiles = (newFiles: File[]) => {
        setErrorMsg(null);
        setFiles(prev => {
            const added = [...prev];
            newFiles.forEach(f => {
                if (!added.some(x => x.name === f.name && x.size === f.size)) {
                    added.push(f);
                }
            });
            return added;
        });
    };

    const removeFile = (index: number) => {
        setFiles(prev => prev.filter((_, i) => i !== index));
    };

    const animateProgress = (from: number, to: number, durationMs: number) => {
        let current = from;
        const steps = 30;
        const increment = (to - from) / steps;
        const stepMs = durationMs / steps;

        const timer = setInterval(() => {
            current += increment;
            setProgress(Math.min(100, current));
            if (current >= to) clearInterval(timer);
        }, stepMs);
    };

    const buildFileFormData = () => {
        const formData = new FormData();
        files.forEach(f => formData.append('files', f));
        formData.append('keepRequired', String(keepRequired));
        formData.append('keepLowPriority', String(keepLowPriority));
        formData.append('strictMode', String(strictMode));
        return formData;
    };

    const handleAnalyze = async () => {
        if (!files.length) return;
        setErrorMsg(null);
        setSanitizedResults(null);
        const formData = buildFileFormData();

        setShowProgress(true);
        setProgressLabel('Uploading files…');
        animateProgress(10, 40, 1000);

        try {
            const token = localStorage.getItem('token');
            setTimeout(() => setProgressLabel('Extracting & scoring metadetails with MetaCore…'), 1000);
            animateProgress(40, 85, 1800);

            const res = await axios.post('/api/analyze', formData, {
                headers: {
                    'Content-Type': 'multipart/form-data',
                    'Authorization': token ? `Bearer ${token}` : ''
                }
            });

            animateProgress(85, 100, 300);
            setTimeout(() => {
                setShowProgress(false);
                setResults(res.data);
                setActiveTab('metacore');
            }, 350);
        } catch (error: any) {
            console.error(error);
            setShowProgress(false);
            setErrorMsg(error?.response?.data?.error || 'Analysis failed');
        }
    };

    const handleSanitize = async () => {
        if (!files.length) return;
        setErrorMsg(null);
        const formData = buildFileFormData();

        setShowProgress(true);
        setProgressLabel('Running MetaCore selective metadata sanitization…');
        animateProgress(15, 75, 1500);

        try {
            const token = localStorage.getItem('token');
            const res = await axios.post('/api/sanitize', formData, {
                headers: {
                    'Content-Type': 'multipart/form-data',
                    'Authorization': token ? `Bearer ${token}` : ''
                }
            });

            animateProgress(75, 100, 300);
            setTimeout(() => {
                setShowProgress(false);
                setSanitizedResults(res.data);
            }, 350);
        } catch (error: any) {
            console.error(error);
            setShowProgress(false);
            setErrorMsg(error?.response?.data?.error || 'Sanitization failed');
        }
    };

    const handleDownloadSanitized = async (item: SanitizationResult) => {
        try {
            const res = await axios.get(item.downloadUrl, { responseType: 'blob' });
            const objUrl = URL.createObjectURL(res.data);
            const a = document.createElement('a');
            a.href = objUrl;
            a.download = item.sanitizedFileName;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(objUrl);
        } catch (error: any) {
            setErrorMsg(error?.response?.data?.error || 'Failed to download sanitized file (it may have expired).');
        }
    };

    const handleScrape = async () => {
        if (!url) {
            alert('Please enter a valid URL');
            return;
        }
        setErrorMsg(null);
        setSanitizedResults(null);
        setShowProgress(true);
        setProgressLabel('Connecting to target…');
        animateProgress(5, 30, 1500);

        try {
            setTimeout(() => setProgressLabel(`Crawling ${url} (depth ${depth})…`), 1500);
            animateProgress(30, 70, 3000);

            const token = localStorage.getItem('token');
            const res = await axios.post('/api/scrape', { url, depth, scanOnly }, {
                headers: {
                    'Authorization': token ? `Bearer ${token}` : ''
                }
            });

            animateProgress(70, 100, 400);
            setTimeout(() => {
                setShowProgress(false);
                setResults(res.data);
                setActiveTab('summary');
            }, 500);
        } catch (error) {
            console.error(error);
            setShowProgress(false);
            setErrorMsg('Scraping failed');
        }
    };

    const formatBytes = (bytes: number) => {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
    };

    const downloadFile = (content: string, filename: string, mimeType: string) => {
        const blob = new Blob([content], { type: mimeType });
        const objUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = objUrl;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(objUrl);
    };

    const handleExportJson = () => {
        if (!results && !sanitizedResults) return;
        const payload = sanitizedResults ? { analysis: results, sanitization: sanitizedResults } : results;
        downloadFile(JSON.stringify(payload, null, 2), `metadetective-${new Date().getTime()}.json`, 'application/json');
    };

    const priorityBadgeClass = (priority: MetaPriority) => {
        switch (priority) {
            case 'Critical': return 'badge badge-critical';
            case 'High': return 'badge badge-high';
            case 'Low': return 'badge badge-low';
            case 'Required': return 'badge badge-required';
            default: return 'badge badge-default';
        }
    };

    const riskBadgeClass = (risk: string) => {
        switch (risk) {
            case 'Critical': return 'badge badge-critical';
            case 'High': return 'badge badge-high';
            case 'Low': return 'badge badge-low';
            default: return 'badge badge-required';
        }
    };

    const filterDetails = (details: ClassifiedMetadetail[]) => {
        if (priorityFilter === 'sensitive') return details.filter(d => d.isSensitive);
        if (priorityFilter === 'low') return details.filter(d => d.priority === 'Low');
        if (priorityFilter === 'required') return details.filter(d => d.priority === 'Required');
        return details;
    };

    const renderMetaCore = () => {
        if (!results) return null;

        const withReports = results.filter(r => r.metaCore);
        if (!withReports.length) {
            return (
                <div className="empty-state">
                    <h3>No MetaCore classification available</h3>
                    <p>Upload a supported file to inspect MetaCore priority scoring and sanitization policies.</p>
                </div>
            );
        }

        return (
            <div>
                <div className="filter-pills">
                    <button className={`filter-pill ${priorityFilter === 'all' ? 'active' : ''}`} onClick={() => setPriorityFilter('all')}>All Metadetails</button>
                    <button className={`filter-pill ${priorityFilter === 'sensitive' ? 'active' : ''}`} onClick={() => setPriorityFilter('sensitive')}>Sensitive (Remove)</button>
                    <button className={`filter-pill ${priorityFilter === 'low' ? 'active' : ''}`} onClick={() => setPriorityFilter('low')}>Low Priority (Keep)</button>
                    <button className={`filter-pill ${priorityFilter === 'required' ? 'active' : ''}`} onClick={() => setPriorityFilter('required')}>Required (Keep)</button>
                </div>

                {withReports.map((r, idx) => {
                    const mc = r.metaCore!;
                    const visible = filterDetails(mc.details);

                    return (
                        <div key={idx} className="sanitize-card">
                            <div className="sanitize-card-header">
                                <div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                                        <strong>{r.filename || r.name || `File ${idx + 1}`}</strong>
                                        <span className={riskBadgeClass(mc.riskLevel)}>Risk: {mc.riskLevel}</span>
                                        {r.engine && <span className="badge badge-default">{r.engine}</span>}
                                    </div>
                                </div>
                                {files.length > 0 && (
                                    <button className="btn btn-primary btn-sm" onClick={handleSanitize}>
                                        Sanitize with MetaCore
                                    </button>
                                )}
                            </div>

                            <div className="stats-grid">
                                <div className="stat-card">
                                    <div className="stat-number" style={{ color: '#f87171' }}>{mc.sensitiveCount}</div>
                                    <div className="stat-label">Sensitive (Remove)</div>
                                </div>
                                <div className="stat-card">
                                    <div className="stat-number" style={{ color: '#38bdf8' }}>{mc.lowPriorityCount}</div>
                                    <div className="stat-label">Low Priority (Keep)</div>
                                </div>
                                <div className="stat-card">
                                    <div className="stat-number" style={{ color: '#34d399' }}>{mc.requiredCount}</div>
                                    <div className="stat-label">Required (Keep)</div>
                                </div>
                                <div className="stat-card">
                                    <div className="stat-number">{mc.keptCount} / {mc.totalCount}</div>
                                    <div className="stat-label">Kept After Sanitize</div>
                                </div>
                            </div>

                            <div className="table-wrapper">
                                <table className="table">
                                    <thead>
                                        <tr>
                                            <th>Priority</th>
                                            <th>Field</th>
                                            <th>Category</th>
                                            <th>Value</th>
                                            <th>Policy</th>
                                            <th>Reason</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {visible.map((d, i) => (
                                            <tr key={`${d.key}-${i}`}>
                                                <td><span className={priorityBadgeClass(d.priority)}>{d.priority}</span></td>
                                                <td className="text-mono" style={{ whiteSpace: 'nowrap' }}>{d.key}</td>
                                                <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>{d.category}</td>
                                                <td style={{ maxWidth: '240px', wordBreak: 'break-word' }}>{String(d.value ?? '').substring(0, 120)}</td>
                                                <td>
                                                    <span className={d.action === 'Remove' ? 'badge badge-remove' : 'badge badge-keep'}>
                                                        {d.action}
                                                    </span>
                                                </td>
                                                <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>{d.reason}</td>
                                            </tr>
                                        ))}
                                        {visible.length === 0 && (
                                            <tr>
                                                <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
                                                    No metadetails match the selected priority filter.
                                                </td>
                                            </tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    );
                })}
            </div>
        );
    };

    const renderSanitizedResults = () => {
        if (!sanitizedResults) return null;

        return (
            <div style={{ marginTop: '28px' }}>
                <div className="results-header">
                    <h2>Sanitized Output (MetaCore Engine)</h2>
                    <div className="export-buttons">
                        <button className="btn btn-secondary btn-sm" onClick={handleExportJson}>Export Audit JSON</button>
                    </div>
                </div>

                {sanitizedResults.map((item, idx) => {
                    if (item.error) {
                        return (
                            <div key={idx} className="form-error">
                                <strong>{item.fileName}:</strong> {item.error}
                            </div>
                        );
                    }

                    const isClean = item.remainingSensitiveFields.length === 0;
                    return (
                        <div key={idx} className="sanitize-card">
                            <div className="sanitize-card-header">
                                <div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                                        <strong>{item.sanitizedFileName}</strong>
                                        <span className={isClean ? 'badge badge-required' : 'badge badge-high'}>
                                            {isClean ? 'Verified Clean (0 sensitive remaining)' : `${item.remainingSensitiveFields.length} non-removable sensitive`}
                                        </span>
                                        <span className="badge badge-default">{item.engineUsed}</span>
                                    </div>
                                    <div className="sanitize-meta-row">
                                        <span>Size: {formatBytes(item.originalSize)} → {formatBytes(item.sanitizedSize)}</span>
                                        <span>•</span>
                                        <span>Removed {item.removedFields.length} sensitive field(s) ({formatBytes(item.bytesRemoved)})</span>
                                        <span>•</span>
                                        <span>Kept {item.keptFields.length} low-priority &amp; required field(s)</span>
                                    </div>
                                </div>
                                <button className="btn btn-primary" onClick={() => handleDownloadSanitized(item)}>
                                    Download Sanitized File
                                </button>
                            </div>

                            <div className="sanitize-columns">
                                <div>
                                    <h3 style={{ fontSize: '0.85rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#f87171', marginBottom: '10px' }}>
                                        Removed Sensitive Metadata ({item.removedFields.length})
                                    </h3>
                                    <div className="table-wrapper">
                                        <table className="table">
                                            <thead><tr><th>Priority</th><th>Field</th><th>Original Value</th></tr></thead>
                                            <tbody>
                                                {item.removedFields.map((f, i) => (
                                                    <tr key={i}>
                                                        <td><span className={priorityBadgeClass(f.priority)}>{f.priority}</span></td>
                                                        <td className="text-mono">{f.key}</td>
                                                        <td>{String(f.value ?? '').substring(0, 80)}</td>
                                                    </tr>
                                                ))}
                                                {item.removedFields.length === 0 && (
                                                    <tr><td colSpan={3} style={{ color: 'var(--text-muted)' }}>No embedded sensitive fields detected.</td></tr>
                                                )}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>

                                <div>
                                    <h3 style={{ fontSize: '0.85rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#34d399', marginBottom: '10px' }}>
                                        Kept Low-Priority &amp; Required ({item.keptFields.length})
                                    </h3>
                                    <div className="table-wrapper">
                                        <table className="table">
                                            <thead><tr><th>Priority</th><th>Field</th><th>Value</th></tr></thead>
                                            <tbody>
                                                {item.keptFields.map((f, i) => (
                                                    <tr key={i}>
                                                        <td><span className={priorityBadgeClass(f.priority)}>{f.priority}</span></td>
                                                        <td className="text-mono">{f.key}</td>
                                                        <td>{String(f.value ?? '').substring(0, 80)}</td>
                                                    </tr>
                                                ))}
                                                {item.keptFields.length === 0 && (
                                                    <tr><td colSpan={3} style={{ color: 'var(--text-muted)' }}>No metadata fields preserved.</td></tr>
                                                )}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    );
                })}
            </div>
        );
    };

    const renderSummary = () => {
        if (!results) return null;

        const keyMap: Record<string, Set<string>> = {};
        results.forEach(r => {
            Object.entries(r.metadata || {}).forEach(([k, v]) => {
                if (!keyMap[k]) keyMap[k] = new Set();
                keyMap[k].add(String(v));
            });
        });

        const sortedKeys = Object.keys(keyMap).sort((a, b) => keyMap[b].size - keyMap[a].size);

        return (
            <div className="summary-field-section">
                <div className="stats-grid">
                    <div className="stat-card">
                        <div className="stat-number">{results.length}</div>
                        <div className="stat-label">Files Analyzed</div>
                    </div>
                </div>
                <h3>All Metadata Fields</h3>
                <div className="table-wrapper">
                    <table className="table">
                        <thead>
                            <tr>
                                <th>Field</th>
                                <th>Unique Values</th>
                                <th style={{ textAlign: 'right' }}>Count</th>
                            </tr>
                        </thead>
                        <tbody>
                            {sortedKeys.map(key => {
                                const vals = Array.from(keyMap[key]).slice(0, 5);
                                return (
                                    <tr key={key}>
                                        <td className="text-mono" style={{ whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>{key}</td>
                                        <td>
                                            {vals.map((v, i) => <span key={i} style={{ display: 'inline-block', marginRight: '6px', marginBottom: '4px' }}>{v.substring(0, 80)}</span>)}
                                            {keyMap[key].size > 5 && <span className="badge badge-default">+{keyMap[key].size - 5} more</span>}
                                        </td>
                                        <td style={{ textAlign: 'right', color: 'var(--text-muted)' }}>{keyMap[key].size}</td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                </div>
            </div>
        );
    };

    const renderAllFields = () => {
        if (!results) return null;
        return (
            <div className="accordion">
                {results.map((r, idx) => (
                    <div key={idx} className="accordion-item open">
                        <div className="accordion-header">
                            <span>{r.filename || r.name || `File ${idx + 1}`}</span>
                            <span className="badge badge-default">{Object.keys(r.metadata || {}).length} fields</span>
                        </div>
                        <div className="accordion-body">
                            <div className="table-wrapper">
                                <table className="table">
                                    <thead><tr><th>Field</th><th>Value</th></tr></thead>
                                    <tbody>
                                        {Object.entries(r.metadata || {}).map(([k, v]) => (
                                            <tr key={k}>
                                                <td className="text-mono" style={{ color: 'var(--text-muted)' }}>{k}</td>
                                                <td style={{ wordBreak: 'break-all' }}>{String(v)}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                ))}
            </div>
        );
    };

    const parseExifDate = (raw: any): Date | null => {
        const str = String(raw || '').trim();
        if (!str) return null;
        // Convert EXIF "YYYY:MM:DD HH:MM:SS" to ISO-compatible "YYYY-MM-DD HH:MM:SS"
        const normalized = str.replace(/^(\d{4}):(\d{2}):(\d{2})/, '$1-$2-$3');
        const date = new Date(normalized);
        return isNaN(date.getTime()) ? null : date;
    };

    const renderTimeline = () => {
        if (!results) return null;
        const dateFields = [
            'CreateDate', 'ModifyDate', 'FileModifyDate', 'DateTimeOriginal',
            'MetadataDate', 'TrackCreateDate', 'TrackModifyDate', 'MediaCreateDate',
            'MediaModifyDate', 'ContentCreateDate', 'LastModifiedDate', 'DateCreated'
        ];

        const events: any[] = [];
        results.forEach(r => {
            const meta = r.metadata || {};
            dateFields.forEach(field => {
                if (meta[field]) {
                    const date = parseExifDate(meta[field]);
                    if (date) {
                        events.push({
                            date,
                            label: field,
                            filename: r.filename || r.name || 'Unknown',
                            raw: meta[field]
                        });
                    }
                }
            });
        });

        if (!events.length) {
            return (
                <div className="empty-state">
                    <h3>No date fields found</h3>
                    <p>The analyzed files did not contain recognizable date metadata.</p>
                </div>
            );
        }

        events.sort((a, b) => a.date - b.date);

        return (
            <div className="timeline">
                {events.map((ev, i) => (
                    <div key={i} className="timeline-item">
                        <div className="timeline-date">{ev.date.toLocaleDateString()}</div>
                        <div className="timeline-line">
                            <div className="timeline-dot"></div>
                            <div className="timeline-connector"></div>
                        </div>
                        <div className="timeline-content">
                            <h4>{ev.label}</h4>
                            <p>{ev.filename}</p>
                            <p className="text-mono text-xs" style={{ marginTop: '2px', color: 'var(--text-subtle)' }}>{ev.raw}</p>
                        </div>
                    </div>
                ))}
            </div>
        );
    };

    const parseGpsCoord = (raw: any, ref?: any): number | null => {
        if (typeof raw === 'number' && !isNaN(raw)) return raw;
        const text = String(raw || '').trim();
        if (!text) return null;

        const dmsMatch = text.match(/(-?\d+(?:\.\d+)?)\s*(?:deg|°|,)\s*(\d+(?:\.\d+)?)\s*(?:'|,)?\s*(\d+(?:\.\d+)?)?"?\s*([NSEW])?/i);
        let value: number;
        if (dmsMatch) {
            const deg = parseFloat(dmsMatch[1]);
            const min = parseFloat(dmsMatch[2] || '0');
            const sec = parseFloat(dmsMatch[3] || '0');
            value = Math.abs(deg) + min / 60 + sec / 3600;
            if (deg < 0) value = -value;
            const hemi = (dmsMatch[4] || String(ref || '')).trim().toUpperCase();
            if (hemi.startsWith('S') || hemi.startsWith('W')) value = -Math.abs(value);
        } else {
            value = parseFloat(text.replace(/[^0-9.-]/g, ''));
            if (isNaN(value)) return null;
            const hemi = String(ref || text).trim().toUpperCase();
            if (hemi.endsWith('S') || hemi.endsWith('W')) value = -Math.abs(value);
        }
        return isNaN(value) ? null : value;
    };

    const renderMap = () => {
        if (!results) return null;
        const gpsItems: any[] = [];

        results.forEach(r => {
            const meta = r.metadata || {};
            const latVal = meta.GPSLatitude || meta.Latitude || (r.gps && (r.gps.latitude || r.gps.GPSLatitude));
            const lonVal = meta.GPSLongitude || meta.Longitude || (r.gps && (r.gps.longitude || r.gps.GPSLongitude));

            if (latVal !== undefined && lonVal !== undefined) {
                const lat = parseGpsCoord(latVal, meta.GPSLatitudeRef);
                const lon = parseGpsCoord(lonVal, meta.GPSLongitudeRef);
                if (lat !== null && lon !== null) {
                    gpsItems.push({ lat, lon, filename: r.filename || r.name || 'Unknown', meta });
                }
            }
        });

        if (!gpsItems.length) {
            return (
                <div className="empty-state">
                    <h3>No GPS data found</h3>
                    <p>None of the analyzed files contained embedded GPS coordinates.</p>
                </div>
            );
        }

        return (
            <div>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '20px' }}>
                    Found GPS coordinates in <strong>{gpsItems.length}</strong> file(s).
                </p>
                {gpsItems.map((item, i) => {
                    const embedUrl = `https://www.openstreetmap.org/export/embed.html?bbox=${item.lon - 0.01},${item.lat - 0.01},${item.lon + 0.01},${item.lat + 0.01}&layer=mapnik&marker=${item.lat},${item.lon}`;
                    const osmUrl = `https://www.openstreetmap.org/?mlat=${item.lat}&mlon=${item.lon}&zoom=15`;

                    return (
                        <div key={i} className="gps-card">
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', marginBottom: '10px', flexWrap: 'wrap' }}>
                                <div>
                                    <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '4px' }}>{item.filename}</div>
                                    <div className="gps-coords">{item.lat.toFixed(6)}°, {item.lon.toFixed(6)}°</div>
                                </div>
                                <a href={osmUrl} target="_blank" rel="noopener noreferrer" className="btn btn-secondary btn-sm">Open in OSM</a>
                            </div>
                            <div className="map-embed">
                                <iframe src={embedUrl} title={`Map location for ${item.filename}`} loading="lazy" allowFullScreen style={{ width: '100%', height: '300px', border: 'none' }}></iframe>
                            </div>
                        </div>
                    );
                })}
            </div>
        );
    };

    return (
        <div className="scan-page">
            <h1 className="page-title">Metadata Scanner &amp; Sanitizer</h1>
            <p className="page-subtitle">Upload files to score metadetails with MetaCore and selectively sanitize sensitive metadata while preserving low-priority &amp; required fields.</p>

            <div className="mode-toggle" role="tablist">
                <button className={`mode-btn ${mode === 'file' ? 'active' : ''}`} onClick={() => { setMode('file'); setResults(null); setSanitizedResults(null); setErrorMsg(null); }}>File Upload</button>
                <button className={`mode-btn ${mode === 'url' ? 'active' : ''}`} onClick={() => { setMode('url'); setResults(null); setSanitizedResults(null); setErrorMsg(null); }}>Web Scrape</button>
            </div>

            {errorMsg && <div className="form-error">{errorMsg}</div>}

            {mode === 'file' && (
                <div className="scan-panel">
                    <div className={`dropzone ${isDragging ? 'drag-over' : ''}`} onDragOver={handleDragOver} onDragLeave={handleDragLeave} onDrop={handleDrop} onClick={() => fileInputRef.current?.click()}>
                        <p>Drop files here or <span>browse</span></p>
                    </div>
                    <input type="file" multiple hidden ref={fileInputRef} onChange={handleFileChange} />
                    <div className="file-list">
                        {files.map((f, i) => (
                            <div key={i} className="file-item">
                                <span className="file-item-name">{f.name}</span>
                                <span className="file-item-size">{formatBytes(f.size)}</span>
                                <button className="file-item-remove" onClick={() => removeFile(i)}>X</button>
                            </div>
                        ))}
                    </div>

                    <div className="metacore-controls">
                        <label>
                            <input type="checkbox" checked={keepRequired} onChange={e => setKeepRequired(e.target.checked)} />
                            Keep Required Metadata
                        </label>
                        <label>
                            <input type="checkbox" checked={keepLowPriority} onChange={e => setKeepLowPriority(e.target.checked)} />
                            Keep Low-Priority Metadata
                        </label>
                        <label>
                            <input type="checkbox" checked={strictMode} onChange={e => setStrictMode(e.target.checked)} />
                            Strict Mode (strip unrecognized tags)
                        </label>
                    </div>

                    <div className="scan-actions">
                        <button className="btn btn-secondary" disabled={files.length === 0} onClick={handleAnalyze}>Analyze &amp; Prioritize</button>
                        <button className="btn btn-primary" disabled={files.length === 0} onClick={handleSanitize}>Sanitize Sensitive Metadata</button>
                    </div>
                </div>
            )}

            {mode === 'url' && (
                <div className="scan-panel">
                    <div className="input-group">
                        <label>Target URL</label>
                        <input type="url" className="input" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://target.com/" />
                    </div>
                    <div className="scrape-options">
                        <label>Crawl depth: <input type="number" value={depth} onChange={e => setDepth(Number(e.target.value))} min="0" max="3" /></label>
                        <label><input type="checkbox" checked={scanOnly} onChange={e => setScanOnly(e.target.checked)} /> Scan only</label>
                    </div>
                    <button className="btn btn-primary" onClick={handleScrape}>Start Scraping</button>
                </div>
            )}

            {showProgress && (
                <div className="scan-progress">
                    <div className="progress"><div className="progress-bar" style={{ width: `${progress}%` }}></div></div>
                    <p>{progressLabel}</p>
                </div>
            )}

            {renderSanitizedResults()}

            {results && (
                <div id="results-panel" style={{ marginTop: '28px' }}>
                    <div className="results-header">
                        <h2>Analysis Results</h2>
                        <div className="export-buttons">
                            <button className="btn btn-secondary" onClick={handleExportJson}>JSON</button>
                        </div>
                    </div>
                    <div className="tabs">
                        <button className={`tab ${activeTab === 'metacore' ? 'active' : ''}`} onClick={() => setActiveTab('metacore')}>MetaCore Priority</button>
                        <button className={`tab ${activeTab === 'summary' ? 'active' : ''}`} onClick={() => setActiveTab('summary')}>Summary</button>
                        <button className={`tab ${activeTab === 'all-fields' ? 'active' : ''}`} onClick={() => setActiveTab('all-fields')}>All Fields</button>
                        <button className={`tab ${activeTab === 'timeline' ? 'active' : ''}`} onClick={() => setActiveTab('timeline')}>Timeline</button>
                        <button className={`tab ${activeTab === 'map' ? 'active' : ''}`} onClick={() => setActiveTab('map')}>GPS &amp; Map</button>
                    </div>
                    {activeTab === 'metacore' && <div className="tab-content">{renderMetaCore()}</div>}
                    {activeTab === 'summary' && <div className="tab-content">{renderSummary()}</div>}
                    {activeTab === 'all-fields' && <div className="tab-content">{renderAllFields()}</div>}
                    {activeTab === 'timeline' && <div className="tab-content">{renderTimeline()}</div>}
                    {activeTab === 'map' && <div className="tab-content">{renderMap()}</div>}
                </div>
            )}
        </div>
    );
};

export default Scan;
