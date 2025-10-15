document.addEventListener('DOMContentLoaded', function () {
    chrome.storage.local.get('lastScan', function (data) {
        const container = document.getElementById('securityList');
        if (data.lastScan) {
            // Build an array of scan objects using the updated server keys.
            const securityScans = [
                { name: data.lastScan.csp_scan_name, result: data.lastScan.csp_scan_result },
                { name: data.lastScan.csrf_scan_name, result: data.lastScan.csrf_scan_result },
                { name: data.lastScan.directory_scan_name, result: data.lastScan.directory_scan_result }, 
                { name: data.lastScan.https_scan_name, result: data.lastScan.https_scan_result },
                { name: data.lastScan.mixed_scan_name, result: data.lastScan.mixed_scan_result },
                { name: data.lastScan.outdated_scan_name, result: data.lastScan.outdated_scan_result },
                { name: data.lastScan.performance_scan_name, result: data.lastScan.performance_scan_result },
                { name: data.lastScan.headers_scan_name, result: data.lastScan.headers_scan_result },
                { name: data.lastScan.sql_scan_name, result: data.lastScan.sql_scan_result },
                { name: data.lastScan.ssl_scan_name, result: data.lastScan.ssl_scan_result },
                { name: data.lastScan.vuln_scan_name, result: data.lastScan.vuln_scan_result },
                { name: data.lastScan.xss_scan_name, result: data.lastScan.xss_scan_result }

            ];

            // Map each updated scan name to a specific file that shows more info.
            const fileMap = {


                "Passive CSP Security Scan"                         : "Secuirty_Pages/Passive_CSP_Security_Scanner.html",
                "Passive CSRF Security Scan"                        : "Secuirty_Pages/Passive_CSRF_Security_Scanner.html",
                "Passive Directory Listing Security Scan"           : "Secuirty_Pages/Passive_Directory_Listing_Security_Scanner.html",
                "Passive HTTPS Security Scan"                       : "Secuirty_Pages/Passive_HTTPS_Scanner.html",
                "Passive Mixed Content Detection Scan"              : "Secuirty_Pages/Passive_Mixed_Content_Detection_Scanner.html",
                "Passive Outdated Plugin Security Scan"             : "Secuirty_Pages/Passive_Outdated_Plugin_Security_Scanner.html",
                "Passive Performance & Configuration Analysis Scan" : "Secuirty_Pages/Passive_Performance_and_Configuration_Analysis_Scanner.html",
                "Passive Security Headers Scan"                     : "Secuirty_Pages/Passive_Security_Headers_Scanner.html",
                "Passive SQL Injection Security Scan"               : "Secuirty_Pages/Passive_SQL_Injection_Security_Scanner.html",
                "Passive SSL/TLS Certificate Validation Scan"       : "Secuirty_Pages/Passive_SSL_TLS_Certificate_Validation_Scanner.html",
                "Passive Vulnerability Cross-Reference Scan"        : "Secuirty_Pages/Passive_Vulnerability_Cross_Reference_Scanner.html",
                "Passive XSS Security Scan"                         : "Secuirty_Pages/Passive_XSS_Security_Scanner.html"
            };

            // Explanations for some scans (add or adjust as needed)
            const explanations = {
                "Passive CSP Security Scan"                         : "A missing or misconfigured Content Security Policy can leave the site vulnerable to cross-site scripting (XSS) and data injection attacks.",
                "Passive CSRF Security Scan"                        : "Missing CSRF tokens allow attackers to trick users into performing unintended actions on authenticated sites.",
                "Passive Directory Listing Security Scan"           : "If directory listing is enabled, attackers can browse internal files and potentially discover sensitive data.",
                "Passive HTTPS Security Scan"                       : "A low HTTPS score means the site is using outdated TLS versions or lacks HTTPS (secure version of HTTP), making it vulnerable to eavesdropping.",
                "Passive Mixed Content Detection Scan"              : "Mixed content (HTTP resources on HTTPS pages) weakens the security of encrypted connections.",
                "Passive Outdated Plugin Security Scan"             : "Outdated plugins can introduce known vulnerabilities and are often targeted by attackers.",
                "Passive Performance & Configuration Analysis Scan" : "Poor performance or insecure configuration settings can expose the site to stability and security risks.",
                "Passive Security Headers Scan"                     :  "Missing security headers (like X-Frame-Options or HSTS) reduce browser-enforced protections.",
                "Passive SQL Injection Security Scan"               : "A low SQL injection score suggests that user inputs might be improperly sanitized, allowing attackers to manipulate database queries.",
                "Passive SSL/TLS Certificate Validation Scan"       : "Weak SSL/TLS settings can expose sensitive data to man-in-the-middle attacks.",
                "Passive Vulnerability Cross-Reference Scan"        : "This scan cross-references known vulnerabilities; a low score may indicate outdated or vulnerable components.",
                "Passive XSS Security Scan"                         : "A low XSS score means the site does not properly escape user inputs, allowing attackers to inject malicious scripts."
            };

            // Loop over each scan and create its UI element.
            securityScans.forEach(function (scan) {
                if (scan.name && scan.result) {
                    const scanItem = document.createElement('div');
                    scanItem.classList.add('scan-item');

                    const scanHeader = document.createElement('div');
                    scanHeader.textContent = scan.name;
                    scanHeader.classList.add('scan-header');

                    // Use a regex to extract the score (expects format like "Score: 5 - ...")
                    let match = scan.result.match(/Score:\s*(\d+)/);
                    let scanDetails = document.createElement('div');
                    scanDetails.classList.add('scan-details', 'hidden');

                    // Add scan result text.
                    const resultText = document.createElement('p');
                    resultText.textContent = scan.result;
                    scanDetails.appendChild(resultText);

                    // If the score is low, mark the header red and add explanation plus "More Info" button.
                    if (match) {
                        let score = parseInt(match[1]);
                        if (score <= 4) {
                            scanHeader.style.color = 'red';
                            scanHeader.style.fontWeight = 'bold';

                            let explanation = document.createElement('p');
                            explanation.classList.add('low-score-message');
                            explanation.textContent = explanations[scan.name] || "This issue may pose a security risk.";
                            scanDetails.appendChild(explanation);

                            let moreInfoButton = document.createElement("button");
                            moreInfoButton.textContent = "More Info";
                            moreInfoButton.classList.add("more-info-btn");

                            let filename = fileMap[scan.name] || scan.name.replace(/ /g, "_") + ".html";
                            moreInfoButton.addEventListener("click", function () {
                                chrome.tabs.create({ url: chrome.runtime.getURL("info_pages/" + filename) });
                            });

                            scanDetails.appendChild(moreInfoButton);
                        }
                    }

                    // Toggle details on header click.
                    scanHeader.addEventListener("click", function () {
                        scanDetails.classList.toggle("hidden");
                    });

                    scanItem.appendChild(scanHeader);
                    scanItem.appendChild(scanDetails);
                    container.appendChild(scanItem);
                }
            });
        } else {
            container.innerHTML = '<p>No security scan results available.</p>';
        }
    });

    document.getElementById('backBtn').addEventListener('click', function () {
        window.location.href = chrome.runtime.getURL('popup.html');
    });
});
