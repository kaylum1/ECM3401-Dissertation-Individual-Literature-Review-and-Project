
// extension/popup.js


/*#################################################################
This is the main page of the web browser extension, has the links 
to all other pages ,does with displaying the score
###################################################################*/




// ────────────────────────────────────────────────────────────────
//THIS SECTION deal with web extension if the server if off or there is an error
//────────────────────────────────────────────────────────────────────

// UI for the popup.js when server off
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

  // shows the INFO BUTTON, used to be retry, that shows intrtsuctrion on what to do.
  retryBtn.style.display = 'inline-block';
  retryBtn.onclick = () => {
    window.location.href = 'info_pages/serverOff.html';
  };
}


// ────────────────────────────────────────────────────────────────
//THIS SECTION IS THE MAIN SECTION THAT DEAL WITH THE MAIN UI
//────────────────────────────────────────────────────────────────────



// ── Main updater ────────────────────────────────────────────────
function updatePopup() {
  chrome.storage.local.get(
    ['activeTab','lastScan','weightSystem'],
    function(data) {
      const activeTabUrl = data.activeTab;
      const scanData = data.lastScan;
      const weightSystem  = data.weightSystem || 'normal';

      // grab UI elements
      const urlText             = document.getElementById('urlText');
      const scoreCircle         = document.getElementById('scoreCircle');
      const spinner             = document.getElementById('spinner');
      const scoreText           = document.getElementById('scoreText');
      const statusContainer     = document.getElementById('statusContainer');
      const statusMessage       = document.getElementById('statusMessage');
      const retryBtn            = document.getElementById('retryBtn');
      const failureTallyElement = document.getElementById('failureTally');

      // ── 1) Reset to neutral grey + spinner ────────────────────
      statusContainer.classList.remove('error');
      statusContainer.style.backgroundColor = '';         
      statusMessage.textContent = 'nothing changed';
      retryBtn.style.display    = 'none';
      spinner.style.display     = 'block';
      scoreText.style.display   = 'none';
      failureTallyElement.style.display = 'none';

      // show URL immediately
      urlText.textContent = activeTabUrl
        ? `URL: ${activeTabUrl}`
        : 'URL: Not available';

      // ── 2) If no valid scan arrives in 500 ms → show “server off” ─
      let offlineTimer = setTimeout(() => {
        showError('Server is off or error');
      }, 5000);

      // ── 3) If we do have real data for this URL, cancel offlineTimer
      if (scanData && scanData.url === activeTabUrl) {
        clearTimeout(offlineTimer);




        // ----- This is is making the nothing chnages -----

        // THIS HAS BEEN CHNAGED FOR PHASE 2 so tha the popup apear with no name 

        // pick the correct score & status
        let finalScore, status;
        switch (weightSystem) {
          case 'privacy':         //privacy
            finalScore = scanData.final_score_privacy;
            status     = scanData.scoreStatus_privacy || 'nothing changed';
            break;
          case 'security':       //scurity 
            finalScore = scanData.final_score_security;
            status     = scanData.scoreStatus_security || 'nothing changed';
            break;
          case 'random':        //random (removed for the final version)
            finalScore = scanData.final_score_rand;
            status     = scanData.scoreStatus_rand || 'nothing changed';
            break;
          case 'adversarial':     //adversarial
            finalScore = scanData.final_score_adver;
            status     = scanData.scoreStatus_adver || 'nothing changed'; ///------------------------------Phase 2
            break;
          default: // 'normal'
            finalScore = scanData.final_score_norm;
            status     = scanData.scoreStatus_norm || 'nothing changed';
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
        return;
      }
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

// ── Navigation buttons─────────────────────────────
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
