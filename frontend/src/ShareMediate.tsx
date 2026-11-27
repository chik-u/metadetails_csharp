import { useEffect, useState } from 'react';
import type { ChangeEvent } from 'react';
import axios from 'axios';

interface TamperFlag {
  ruleId: string;
  ruleName: string;
  severity: string;
  evidence: string;
}

interface TamperAuditReport {
  isTampered: boolean;
  flaggedRulesCount: number;
  flags: TamperFlag[];
}

interface RiskClusterMatch {
  clusterId: string;
  name: string;
  beta: number;
  synergyContribution: number;
  involvedTags: string[];
}

interface UsabilityPreservationMetrics {
  hadColorProfile: boolean;
  colorProfilePreserved: boolean;
  hadOrientation: boolean;
  orientationPreserved: boolean;
  isPdf: boolean;
  hadPdfAccessibilityTree: boolean;
  pdfAccessibilityPreserved: boolean;
  isOpenXml: boolean;
  openXmlIntegrityPreserved: boolean;
  compositeUsabilityScore: number;
}

interface MediatedAssetResult {
  fileName: string;
  sanitizedFileName: string;
  contentType: string;
  originalSize: number;
  sanitizedSize: number;
  bytesRemoved: number;
  engineUsed: string;
  sourceChannel: string;
  zeroTransitVerified: boolean;
  volatileMemoryOnly: boolean;
  beforePri: number;
  afterPri: number;
  privacyExposureReductionPercent: number;
  beforeRiskBand: string;
  afterRiskBand: string;
  processingLatencyMs: number;
  dispatchId: string;
  dispatchUri: string;
  tamperAudit: TamperAuditReport;
  usability: UsabilityPreservationMetrics;
  beforeReport: {
    privacyRiskIndex: number;
    priRiskBand: string;
    riskClusters: RiskClusterMatch[];
  };
  removedFields: Array<{ key: string; normalizedKey: string; category: string }>;
  generalizedFields: Array<{ key: string; normalizedKey: string; generalizedValue?: string }>;
  keptFields: Array<{ key: string; normalizedKey: string; priority: string }>;
  remainingSensitiveFields: Array<{ key: string }>;
}

interface OsMediationBatchResult {
  mediationMode: string;
  sourceChannel: string;
  zeroTransitVerified: boolean;
  totalLatencyMs: number;
  meanBeforePri: number;
  meanAfterPri: number;
  meanPerPercent: number;
  meanUsabilityScore: number;
  tamperedFilesCount: number;
  assets: MediatedAssetResult[];
  errors: string[];
}

const SHARE_CACHE = 'metaguard-share-buffer-v1';

const ShareMediate = () => {
  const [files, setFiles] = useState<File[]>([]);
  const [enableTier3, setEnableTier3] = useState(true);
  const [strictMode, setStrictMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState<string>('Ready for OS Share Target hand-off or manual mediation.');
  const [batch, setBatch] = useState<OsMediationBatchResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get('shared') === '1' && 'caches' in window) {
      loadSharedFilesFromSwCache();
    }
  }, []);

  const loadSharedFilesFromSwCache = async () => {
    try {
      const cache = await caches.open(SHARE_CACHE);
      const manifestRes = await cache.match('/_metaguard_shared/manifest.json');
      if (!manifestRes) return;
      const manifest: Array<{ key: string; name: string; type: string }> = await manifestRes.json();
      const loaded: File[] = [];
      for (const entry of manifest) {
        const res = await cache.match(entry.key);
        if (res) {
          const blob = await res.blob();
          loaded.push(new File([blob], entry.name, { type: entry.type || blob.type }));
        }
      }
      await caches.delete(SHARE_CACHE);
      if (loaded.length > 0) {
        setFiles(loaded);
        await runMediation(loaded, 'web-share-target');
      }
    } catch (err) {
      console.error(err);
    }
  };

  const onFileSelect = (e: ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files?.length) return;
    const picked = Array.from(e.target.files);
    setFiles(picked);
  };

  const runMediation = async (targetFiles = files, channel = 'web-os-mediation') => {
    if (!targetFiles.length) return;
    setLoading(true);
    setErrorMsg(null);
    setStatus(`Running MetaGuard OS Mediation on ${targetFiles.length} file(s) in volatile memory...`);

    try {
      const formData = new FormData();
      targetFiles.forEach((f) => formData.append('files', f));
      formData.append('sourceChannel', channel);
      formData.append('enableTier3Normalization', String(enableTier3));
      formData.append('keepRequired', 'true');
      formData.append('keepLowPriority', 'true');
      formData.append('strictMode', String(strictMode));

      const token = localStorage.getItem('token');
      const res = await axios.post<OsMediationBatchResult>('/api/mediate', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          ...(token ? { Authorization: `Bearer ${token}` } : {})
        }
      });

      setBatch(res.data);
      setStatus(`Completed ${res.data.mediationMode} mediation in ${res.data.totalLatencyMs.toFixed(2)} ms.`);
    } catch (err: any) {
      setErrorMsg(err?.response?.data?.error || 'OS Mediation request failed');
      setStatus('Mediation failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleOsShareDispatch = async (asset: MediatedAssetResult) => {
    try {
      const res = await axios.get(asset.dispatchUri, { responseType: 'blob' });
      const cleanFile = new File([res.data], asset.sanitizedFileName, { type: asset.contentType });

      if (navigator.canShare && navigator.canShare({ files: [cleanFile] })) {
        await navigator.share({
          files: [cleanFile],
          title: asset.sanitizedFileName,
          text: `Sanitized by MetaGuard (PER ${asset.privacyExposureReductionPercent.toFixed(1)}%, Usability ${asset.usability.compositeUsabilityScore.toFixed(1)}%)`
        });
        return;
      }

      const objUrl = URL.createObjectURL(res.data);
      const a = document.createElement('a');
      a.href = objUrl;
      a.download = asset.sanitizedFileName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(objUrl);
    } catch (err: any) {
      if (err?.name !== 'AbortError') {
        setErrorMsg(err?.message || 'Safe dispatch failed or expired.');
      }
    }
  };

  return (
    <div style={{ maxWidth: 960, margin: '0 auto', textAlign: 'left' }}>
      <h2>MetaGuard Just-In-Time OS Mediation Layer</h2>
      <p style={{ color: '#94a3b8' }}>
        Intercepts OS Share Target / local media assets, audits forensic tamper rules, evaluates non-linear
        Privacy Risk Index (PRI), applies Three-Tier selective redaction/generalization, and prepares sanitized
        files for safe downstream sharing.
      </p>

      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'center', marginBottom: 16 }}>
        <input
          type="file"
          multiple
          accept="image/*,video/*,audio/*,.pdf,.docx,.pptx,.xlsx,.svg"
          onChange={onFileSelect}
        />
        <label style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <input type="checkbox" checked={enableTier3} onChange={(e) => setEnableTier3(e.target.checked)} />
          Tier 3 Generalization
        </label>
        <label style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <input type="checkbox" checked={strictMode} onChange={(e) => setStrictMode(e.target.checked)} />
          Strict Mode
        </label>
        <button onClick={() => runMediation()} disabled={!files.length || loading}>
          {loading ? 'Mediating...' : 'Mediate Selected Files'}
        </button>
      </div>

      <div style={{ marginBottom: 12, color: '#38bdf8' }}>{status}</div>
      {errorMsg && <div style={{ color: '#f87171', marginBottom: 12 }}>{errorMsg}</div>}

      {batch && (
        <div>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))',
              gap: 12,
              padding: 14,
              borderRadius: 8,
              background: '#0f172a',
              border: '1px solid #334155',
              marginBottom: 18
            }}
          >
            <div>
              <div style={{ fontSize: 12, color: '#94a3b8' }}>Mode / Channel</div>
              <strong>{batch.mediationMode}</strong>
              <div style={{ fontSize: 12 }}>{batch.sourceChannel}</div>
            </div>
            <div>
              <div style={{ fontSize: 12, color: '#94a3b8' }}>Mean PRI Reduction</div>
              <strong>
                {batch.meanBeforePri.toFixed(1)} → {batch.meanAfterPri.toFixed(1)}
              </strong>
              <div style={{ fontSize: 12, color: '#34d399' }}>PER: {batch.meanPerPercent.toFixed(1)}%</div>
            </div>
            <div>
              <div style={{ fontSize: 12, color: '#94a3b8' }}>Composite Usability</div>
              <strong style={{ color: '#34d399' }}>{batch.meanUsabilityScore.toFixed(1)}%</strong>
              <div style={{ fontSize: 12 }}>Latency: {batch.totalLatencyMs.toFixed(2)} ms</div>
            </div>
            <div>
              <div style={{ fontSize: 12, color: '#94a3b8' }}>Tamper Audit</div>
              <strong style={{ color: batch.tamperedFilesCount > 0 ? '#fbbf24' : '#34d399' }}>
                {batch.tamperedFilesCount > 0 ? `${batch.tamperedFilesCount} Flagged` : 'Consistent'}
              </strong>
              <div style={{ fontSize: 12 }}>Zero-Transit: {batch.zeroTransitVerified ? 'Yes' : 'No'}</div>
            </div>
          </div>

          {batch.assets.map((asset) => (
            <div
              key={asset.dispatchId || asset.fileName}
              style={{
                padding: 16,
                marginBottom: 14,
                borderRadius: 8,
                background: '#1e293b',
                border: '1px solid #334155'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
                <div>
                  <strong>{asset.fileName}</strong> → <code>{asset.sanitizedFileName}</code>
                  <div style={{ fontSize: 12, color: '#94a3b8' }}>
                    {asset.engineUsed} | RAM-Only: {String(asset.volatileMemoryOnly)} | {asset.processingLatencyMs.toFixed(2)} ms |{' '}
                    {asset.bytesRemoved} B stripped
                  </div>
                </div>
                <button onClick={() => handleOsShareDispatch(asset)} style={{ background: '#059669', color: '#fff' }}>
                  Safe Dispatch (Share / Download Clean)
                </button>
              </div>

              <div style={{ marginTop: 10, fontSize: 13 }}>
                PRI: <strong>{asset.beforePri.toFixed(1)}</strong> ({asset.beforeRiskBand}) →{' '}
                <strong style={{ color: '#34d399' }}>{asset.afterPri.toFixed(1)}</strong> ({asset.afterRiskBand}) | PER:{' '}
                <strong>{asset.privacyExposureReductionPercent.toFixed(1)}%</strong> | Remaining Sensitive:{' '}
                <strong>{asset.remainingSensitiveFields.length}</strong>
              </div>

              {asset.beforeReport?.riskClusters?.length > 0 && (
                <div style={{ marginTop: 8, fontSize: 12, color: '#fca5a5' }}>
                  Quasi-Identifier Clusters:{' '}
                  {asset.beforeReport.riskClusters
                    .map((c) => `${c.clusterId} (β=${c.beta}, +${c.synergyContribution})`)
                    .join(' · ')}
                </div>
              )}

              {asset.tamperAudit?.isTampered && (
                <div
                  style={{
                    marginTop: 10,
                    padding: 10,
                    borderRadius: 6,
                    background: 'rgba(245, 158, 11, 0.14)',
                    border: '1px solid #f59e0b',
                    fontSize: 12.5
                  }}
                >
                  <strong>Pre-Sanitization Tamper Alert ({asset.tamperAudit.flaggedRulesCount} rule(s)):</strong>
                  <ul style={{ margin: '6px 0 0 18px' }}>
                    {asset.tamperAudit.flags.map((f, idx) => (
                      <li key={idx}>
                        <code>{f.ruleId}</code> ({f.ruleName}): {f.evidence}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <div style={{ marginTop: 10, fontSize: 12, color: '#cbd5e1' }}>
                <div>
                  <strong>Tier 1 Purged ({asset.removedFields.length}):</strong>{' '}
                  {asset.removedFields.map((f) => f.normalizedKey).join(', ') || 'None'}
                </div>
                <div>
                  <strong>Tier 3 Generalized ({asset.generalizedFields.length}):</strong>{' '}
                  {asset.generalizedFields.map((f) => `${f.normalizedKey} -> ${f.generalizedValue}`).join(', ') || 'None'}
                </div>
                <div>
                  <strong>Tier 2 Utility &amp; Low Kept ({asset.keptFields.length}):</strong>{' '}
                  {asset.keptFields.map((f) => f.normalizedKey).join(', ') || 'None'}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default ShareMediate;
