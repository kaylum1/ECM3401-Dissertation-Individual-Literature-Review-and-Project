// extension/popup.js

// ── Helper: show the “server off” UI ───────────────────────────
function showError(message) {
  const spinner         = document.getElementById('spinner');
  const scoreText       = document.getElementById('scoreText');
  const scoreCircle     = document.getElementById('scoreCircle');
  const statusContainer = document.getElementById('statusContainer');
  const statusMessage   = document.getElementById('statusMessage');
  const retryBtn        = document.getElementById('retryBtn');

  // hide spinner, show dash
  spinner.style.display   = 'none';
  scoreText.style.display = 'block';
  scoreText.textContent   = '–';

  // red circle & banner
  scoreCircle.style.backgroundColor = '#F44336';
  statusContainer.classList.add('error');
  statusMessage.textContent = message;

  // show retry
  retryBtn.style.display = 'inline-block';
  retryBtn.onclick = () => {
    window.location.href = 'info_pages/serverOff.html';
  };
}

// ── Main updater ────────────────────────────────────────────────
function updatePopup() {
  chrome.storage.local.get(
    ['activeTab', 'lastScan', 'weightSystem'],
    function(data) {
      const activeTabUrl   = data.activeTab;
      const scanData       = data.lastScan;
      const weightSystem   = data.weightSystem || 'normal';

      // grab UI elements
      const link               = document.getElementById('urlLink');
      const scoreCircle        = document.getElementById('scoreCircle');
      const spinner            = document.getElementById('spinner');
      const scoreText          = document.getElementById('scoreText');
      const statusContainer    = document.getElementById('statusContainer');
      const statusMessage      = document.getElementById('statusMessage');
      const retryBtn           = document.getElementById('retryBtn');
      const failureTallyElement= document.getElementById('failureTally');

      // ── 1) Reset to neutral grey + spinner ────────────────────
      statusContainer.classList.remove('error');
      statusContainer.style.backgroundColor = '';  // let CSS (#ccc) apply
      statusMessage.textContent = 'SCORE: Not changed';
      retryBtn.style.display    = 'none';
      spinner.style.display     = 'block';
      scoreText.style.display   = 'none';
      failureTallyElement.style.display = 'none';

      // show URL immediately in the pill
      if (activeTabUrl) {
        link.href = activeTabUrl;
        link.textContent = activeTabUrl;
      } else {
        link.removeAttribute('href');
        link.textContent = 'Not available';
      }

      // ── 2) If no valid scan arrives in 5000 ms → show “server off” ─
      let offlineTimer = setTimeout(() => {
        showError('Server is off or error');
      }, 5000);

      // ── 3) If we do have real data for this URL, cancel offlineTimer
      if (scanData && scanData.url === activeTabUrl) {
        clearTimeout(offlineTimer);

        // pick the correct score & status
        let finalScore, status;
        switch (weightSystem) {
          case 'privacy':
            finalScore = scanData.final_score_privacy;
            status     = scanData.scoreStatus_privacy || 'SCORE: Not changed';
            break;
          case 'security':
            finalScore = scanData.final_score_security;
            status     = scanData.scoreStatus_security || 'SCORE: Not changed';
            break;
          case 'random':
            finalScore = scanData.final_score_rand;
            status     = scanData.scoreStatus_rand || 'SCORE: Not changed';
            break;
          case 'adversarial':
            finalScore = scanData.final_score_adver;
            status     = scanData.scoreStatus_adver || 'SCORE: Not changed';
            break;
          default: // 'normal'
            finalScore = scanData.final_score_norm;
            status     = scanData.scoreStatus_norm || 'SCORE: Not changed';
        }

        // show score, hide spinner
        scoreText.textContent   = finalScore;
        scoreText.style.display = 'block';
        spinner.style.display   = 'none';

        // circle color by score
        let circleColor = '#ccc';
        if (finalScore >= 8)      circleColor = '#4CAF50';
        else if (finalScore >= 5) circleColor = '#FFC107';
        else                      circleColor = '#F44336';
        scoreCircle.style.backgroundColor = circleColor;

        // banner text & color
        statusMessage.textContent = status;
        let bannerColor = '#ccc';
        if (status === 'better score')     bannerColor = '#4CAF50';
        else if (status === 'worse score') bannerColor = '#F44336';
        statusContainer.style.backgroundColor = bannerColor;

        // tally failures
        const failureKeyword = '❌';
        let failedCount = 0;
        const scanResultKeys = [
          "xss_scan_result","vuln_scan_result","privacy_tracker_scan_result",
          "privacy_third_party_script_scan_result","ssl_scan_result",
          "sql_scan_result","headers_scan_result","privacy_audit_scan_result",
          "performance_scan_result","outdated_scan_result","mixed_scan_result",
          "directory_scan_result","csrf_scan_result","csp_scan_result",
          "https_scan_result","third_party_data_collection_scan_result",
          "tracker_detection_scan_result","fingerprinting_scan_result",
          "referrer_dnt_scan_result","data_leakage_scan_result",
          "dnt_scan_result","cookie_scan_result"
        ];
        scanResultKeys.forEach(key => {
          if (scanData[key] && scanData[key].includes(failureKeyword)) {
            failedCount++;
          }
        });
        if (failedCount > 0) {
          failureTallyElement.textContent =
            `${failedCount} out of ${scanResultKeys.length} scans failed`;
          failureTallyElement.style.display = 'block';
        }

        // done!
        return;
      }

      // ── 4) else: still loading → keep grey spinner until
      //      either real data or the timer fires.
    }
  );
}

// ── Initialize & live‐update wiring ─────────────────────────────
document.addEventListener('DOMContentLoaded', updatePopup);
chrome.storage.onChanged.addListener((changes, area) => {
  if (
    area === 'local' &&
    (changes.activeTab || changes.lastScan || changes.weightSystem)
  ) {
    updatePopup();
  }
});
chrome.runtime.onMessage.addListener(msg => {
  if (msg.type === 'metricChanged') updatePopup();
});

// ── Navigation buttons (unchanged) ─────────────────────────────
document.getElementById('securityBtn').addEventListener('click', () => {
  window.location.href = 'security.html';
});
document.getElementById('privacyBtn').addEventListener('click', () => {
  window.location.href = 'privacy.html';
});
document.getElementById('settingsBtn').addEventListener('click', () => {
  window.location.href = 'settings.html';
});
document.getElementById('logsPage').addEventListener('click', () => {
  window.open('http://localhost:8000/logs', '_blank');
});
document.getElementById('metricsBtn').addEventListener('click', () => {
  window.location.href = 'metrics.html';
});
document.getElementById('educationBtn').addEventListener('click', () => {
  window.location.href = 'education.html';
});
document.getElementById('helpBtn').addEventListener('click', () => {
  window.location.href = 'help.html';
});
