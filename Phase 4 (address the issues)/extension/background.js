

//extension/background.js

// Helper to normalize URLs to their base form (scheme + host + normalized path)
function normalizeUrl(url) {
  try {
    let parsed = new URL(url);
    // Remove trailing slashes from pathname; if empty, use '/'
    let normalizedPath = parsed.pathname.replace(/\/+$/, '');
    if (normalizedPath === '') {
      normalizedPath = '/';
    }
    return parsed.origin + normalizedPath;
  } catch (e) {
    return url;
  }
}

let lastLoggedUrl = "";

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (
    changeInfo.status === 'complete' &&
    tab.url &&
    (tab.url.startsWith('http://') ||
     tab.url.startsWith('https://') ||
     tab.url.startsWith('file://'))
  ) {
    const normalizedTabUrl = normalizeUrl(tab.url);
    // Only log if this URL is different from the last logged one.
    if (normalizedTabUrl === lastLoggedUrl) {
      return;
    }
    lastLoggedUrl = normalizedTabUrl;

    // Update the active tab in storage using normalized URL.
    chrome.storage.local.set({ activeTab: normalizedTabUrl });

    // Log the URL to your backend server.
    fetch('http://localhost:8000/log', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: tab.url })
    })
      .then(response => response.json())
      .then(newData => {
        // Retrieve the previous scan data for comparison.
        chrome.storage.local.get('lastScan', function(result) {
          let previousScan = result.lastScan;
          let scoreStatus = "nothing changed"; // Default status

          // If we have a previous scan for the same URL, compare final scores.
          if (
            previousScan &&
            previousScan.url === newData.url &&
            previousScan.final_score !== undefined
          ) {
            if (newData.final_score > previousScan.final_score) {
              scoreStatus = "better score";
            } else if (newData.final_score < previousScan.final_score) {
              scoreStatus = "worse score";
            }
          }
          // Attach the status to the new scan data.
          newData.scoreStatus = scoreStatus;
          
          // Save the new scan data and update the active tab.
          chrome.storage.local.set({ lastScan: newData, activeTab: newData.url });
        });
      })
      .catch(error => {
        console.error('Error logging URL:', error);
      });

    // --- Cookie Decliner Injection ---
    chrome.storage.local.get('cookieDeclinerEnabled', (result) => {
      if (result.cookieDeclinerEnabled === true) {
        chrome.scripting.executeScript({
          target: { tabId: tab.id, allFrames: true },
          func: function autoDeclineCookies() {
            // Log that the script is running.
            console.log("autoDeclineCookies script injected.");

            // Attempt to click the specific "Essential cookies only" button.
            function clickEssentialButton() {
              const btn = document.querySelector('button[aria-label="Essential cookies only"]');
              if (btn) {
                btn.click();
                console.log("Clicked 'Essential cookies only' button.");
                return true;
              }
              return false;
            }
            
            // Generic approach for other decline buttons.
            const declineKeywords = ['decline', 'no thanks', 'reject', 'reject all'];
            function searchNodes(root) {
              let nodes = [];
              const candidates = root.querySelectorAll('button, input[type="button"]');
              candidates.forEach(el => nodes.push(el));
              // Search within any shadow DOMs.
              root.querySelectorAll('*').forEach(el => {
                if (el.shadowRoot) {
                  nodes = nodes.concat(searchNodes(el.shadowRoot));
                }
              });
              return nodes;
            }
            function genericTryDecline() {
              const buttons = searchNodes(document);
              for (let button of buttons) {
                const text = (button.innerText || button.value || '').toLowerCase().trim();
                if (declineKeywords.some(keyword => text.includes(keyword))) {
                  button.click();
                  console.log("Clicked decline button using generic approach.");
                  return true;
                }
              }
              return false;
            }
            
            // First try the specific selector.
            if (clickEssentialButton()) return;
            
            // Increase delay to 5000ms for pages that load banners later.
            setTimeout(() => {
              if (clickEssentialButton()) return;
              genericTryDecline();
            }, 5000);
            
            // Use MutationObserver to catch dynamically inserted banners.
            const observer = new MutationObserver((mutations, observerInstance) => {
              if (clickEssentialButton() || genericTryDecline()) {
                observerInstance.disconnect();
              }
            });
            observer.observe(document.body, { childList: true, subtree: true });
          }
        }, () => {
          if (chrome.runtime.lastError) {
            console.error("Error injecting cookie decliner script:", chrome.runtime.lastError);
          }
        });
      }
    });
  }
});

// Listen for tab activation (when the user switches tabs)
chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, function(tab) {
    if (tab && tab.url) {
      const normalizedTabUrl = normalizeUrl(tab.url);
      chrome.storage.local.set({ activeTab: normalizedTabUrl });
    }
  });
});

// --- Ad Blocker Code ---

const adBlockingRules = [
  {
    id: 1,
    priority: 1,
    action: { type: "block" },
    condition: { urlFilter: "doubleclick.net", resourceTypes: ["script", "image", "xmlhttprequest", "sub_frame"] }
  },
  {
    id: 2,
    priority: 1,
    action: { type: "block" },
    condition: { urlFilter: "googlesyndication.com", resourceTypes: ["script", "image", "xmlhttprequest", "sub_frame"] }
  },
  {
    id: 3,
    priority: 1,
    action: { type: "block" },
    condition: { urlFilter: "adservice.google.com", resourceTypes: ["script", "image", "xmlhttprequest", "sub_frame"] }
  },
  {
    id: 4,
    priority: 1,
    action: { type: "block" },
    condition: { urlFilter: "ads.", resourceTypes: ["script", "image", "xmlhttprequest", "sub_frame"] }
  },
  {
    id: 5,
    priority: 1,
    action: { type: "block" },
    condition: { urlFilter: "clicktrack.pubmatic.com", resourceTypes: ["script", "image", "xmlhttprequest", "sub_frame"] }
  },
  {
    id: 6,
    priority: 1,
    action: { type: "block" },
    condition: { urlFilter: "googleads.g.doubleclick.net", resourceTypes: ["script", "image", "xmlhttprequest", "sub_frame"] }
  },
  {
    id: 7,
    priority: 1,
    action: { type: "block" },
    condition: { urlFilter: "clicktrack.pubmatic.com", resourceTypes: ["script", "image", "xmlhttprequest", "sub_frame"] }
  },
  {
    id: 8,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: "cdn.flashtalking.com",
      resourceTypes: ["sub_frame"]
    }
  },
  {
    id: 9,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: "js.ad-score.com",
      resourceTypes: ["script"]
    }
  },
  {
    id: 10,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: "ajs-assets.ftstatic.com",
      resourceTypes: ["script"]
    }
  }
];

function updateAdBlockingRules(enabled) {
  chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: adBlockingRules.map(rule => rule.id),
    addRules: enabled ? adBlockingRules : []
  }, () => {
    if (chrome.runtime.lastError) {
      console.error("Error updating ad blocking rules:", chrome.runtime.lastError);
    } else {
      console.log(`Ad blocker is now ${enabled ? "enabled" : "disabled"}.`);
    }
  });
}

// On startup, retrieve the stored adBlockerEnabled setting and update rules.
chrome.storage.local.get('adBlockerEnabled', (result) => {
  const enabled = result.adBlockerEnabled === true;
  updateAdBlockingRules(enabled);
});

// Listen for changes to the settings (adBlockerEnabled and vpnEnabled).
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local') {
    if (changes.adBlockerEnabled) {
      updateAdBlockingRules(changes.adBlockerEnabled.newValue === true);
    }
    if (changes.vpnEnabled) {
      const enabled = changes.vpnEnabled.newValue === true;
      if (enabled) {
        // Replace with your actual VPN/proxy server details.
        chrome.proxy.settings.set({
          value: {
            mode: "fixed_servers",
            rules: {
              singleProxy: {
                scheme: "http", // or "https" if supported by your VPN server
                host: "vpn.example.com", // Replace with your VPN server's host
                port: 8080             // Replace with your VPN server's port
              },
              bypassList: ["<local>"]
            }
          },
          scope: "regular"
        }, () => {
          if (chrome.runtime.lastError) {
            console.error("Error enabling VPN:", chrome.runtime.lastError);
          } else {
            console.log("VPN enabled");
          }
        });
      } else {
        chrome.proxy.settings.clear({ scope: "regular" }, () => {
          if (chrome.runtime.lastError) {
            console.error("Error disabling VPN:", chrome.runtime.lastError);
          } else {
            console.log("VPN disabled");
          }
        });
      }
    }
  }
});
