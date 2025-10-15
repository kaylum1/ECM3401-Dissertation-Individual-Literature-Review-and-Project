//-------------------------------------------------------
//this is the privacy.js pages, this will display all of the 
// different scan and open up the edu pages only when there 
// is a poor rankimng score 
//-------------------------------------------------------



//

document.addEventListener('DOMContentLoaded', function () {
    chrome.storage.local.get('lastScan', function (data) {
        const container = document.getElementById('privacyList');
        if (data.lastScan) {
            // Build an array of privacy scans from the updated server fields.
            const privacyScans = [
                { name: data.lastScan.cookie_scan_name, result: data.lastScan.cookie_scan_result },
                { name: data.lastScan.data_leakage_scan_name, result: data.lastScan.data_leakage_scan_result },
                { name: data.lastScan.dnt_scan_name, result: data.lastScan.dnt_scan_result },
                { name: data.lastScan.fingerprinting_scan_name, result: data.lastScan.fingerprinting_scan_result },
                { name: data.lastScan.privacy_audit_scan_name, result: data.lastScan.privacy_audit_scan_result },
                { name: data.lastScan.referrer_dnt_scan_name, result: data.lastScan.referrer_dnt_scan_result },
                { name: data.lastScan.third_party_data_collection_scan_name, result: data.lastScan.third_party_data_collection_scan_result },
                { name: data.lastScan.privacy_third_party_script_scan_name, result: data.lastScan.privacy_third_party_script_scan_result },
                { name: data.lastScan.tracker_detection_scan_name, result: data.lastScan.tracker_detection_scan_result },
                { name: data.lastScan.privacy_tracker_scan_name, result: data.lastScan.privacy_tracker_scan_result }

            ];

            // Map each privacy scan name to a specific file that shows more info.
            const fileMap = {
                "Passive Cookie Privacy Scan": "Privacy_Pages/Passive_Cookie_Privacy_Scan.html",
                "Passive Data Leakage HTTP Headers Scan": "Privacy_Pages/Passive_Data_Leakage_HTTP_Headers_Scan.html",
                "Passive Do Not Track Support Scan": "Privacy_Pages/Passive_Do_Not_Track_Support_Scan.html",
                "Passive Fingerprinting Detection Scan": "Privacy_Pages/Passive_Fingerprinting_Detection_Scan.html",
                "Passive Privacy & Tracker Audit Scan": "Privacy_Pages/Passive_Privacy_and_Tracker_Audit_Scanner.html",
                "Passive Referrer & DNT Analysis Scan": "Privacy_Pages/Passive_Referrer_DNT_Analysis_Scan.html",
                "Passive Third-Party Data Collection Scan": "Privacy_Pages/Passive_Third_Party_Data_Collection_Scanner.html",
                "Passive Privacy Third-Party Script Evaluation Scan": "Privacy_Pages/Passive_Third_Party_Script_Evaluation_Scanner.html",
                "Passive Tracker Detection Scan": "Privacy_Pages/tracker_detection_scan.html",
                "Passive Privacy Tracker Script Scan": "Privacy_Pages/Passive_Tracker_Script_Scanner.html", 
            };

            // Explanations for each privacy scan.
            const explanations = {
                "Passive Privacy Tracker Script Scan"               : "A high number of trackers means the website collects and shares user data extensively.",
                "Passive Privacy Third-Party Script Evaluation Scan": "This scan checks if third-party scripts compromise user privacy by tracking and collecting data.",
                "Passive Privacy & Tracker Audit Scan"              : "A low score here indicates inadequate privacy protections or excessive tracking practices.",
                "Passive Third-Party Data Collection Scan"          : "This scan measures how much third-party data collection occurs; a high score indicates a risk to privacy.",
                "Passive Tracker Detection Scan"                    : "This scan detects hidden trackers that may monitor user behavior without consent.",
                "Passive Fingerprinting Detection Scan"             : "A high fingerprinting risk means the site can uniquely identify users across sessions, reducing anonymity.",
                "Passive Referrer & DNT Analysis Scan"              : "This scan checks if the site respects Do Not Track settings and minimizes referrer leakage.",
                "Passive Do Not Track Support Scan"                 : "A low score indicates that the site does not properly implement DNT headers, exposing user data.",
                "Passive Data Leakage HTTP Headers Scan"            : "A low score suggests personal data might be inadvertently exposed through HTTP headers.",
                "Passive Cookie Privacy Scan"                       : "A low score means cookies lack essential security attributes, putting user data at risk."
            };

            // Loop through each scan and create its UI element.
            privacyScans.forEach(function (scan) {
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
                            explanation.textContent = explanations[scan.name] || "This issue may pose a privacy risk.";
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
            container.innerHTML = '<p>No privacy scan results available.</p>';
        }
    });

    document.getElementById('backBtn').addEventListener('click', function () {
        window.location.href = chrome.runtime.getURL('popup.html');
    });
});

