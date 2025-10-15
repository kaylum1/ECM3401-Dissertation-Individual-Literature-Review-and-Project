# Tracking & Profiling Online – Data/Code Package


talk about the computer used and the modle software and others and tghen mention software requirmnet like chorimum 



## What is this?
Four project phases that build, test and study a browser-extension privacy scorer.

| Phase | Folder                                | One-liner                                     |
|-------|---------------------------------------|-----------------------------------------------|
| 1     | `Phase 1 (Benign version)/`           | Honest scoring extension (1 = poor security)  |
| 2     | `Phase 2 (Adversarial version)/`      | Deceptive version (1 = secure)                |
| 3     | `Phase 3 (User Study)/`               | Survey data + analysis notebook               |
| 4     | `Phase 4 (address the issues)/`       | Improved design to fix usability issues       |

------------------------
<details>
<summary>Phase 1 (Benign version) Setup Guide</summary>

# Setup Guide

## Starting Phase 1 (Benign)

**From the root folder (folder containing requirements.txt) in the terminal:**

```bash
cd "Phase 1 (Benign version)"
cd server
pip install -r "../../requirements.txt"
python server.py
```

You should see the following when the server has successfully started:

```bash
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process [92633] using StatReload
INFO:     Started server process [92635]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```

---

## Loading the Extension

1. Open Chromium and navigate to `chrome://extensions/`.
2. Enable **Developer Mode** (toggle in the top right).
3. Click **Load unpacked**.
4. Navigate to:
   
   ```text
   (root folder)/Phase 1 (Benign version)/extension
   ```

5. Select the **extension** folder to load it.

You can now use the extension freely.



## Stopping the Server

When you are finished using the extension:

1. In the terminal where the server is running, press:

   ```bash
   CTRL+C
   ```

2. You should then see output similar to:

   ```bash
   ^CINFO:     Shutting down
   INFO:     Waiting for application shutdown.
   INFO:     Application shutdown complete.
   INFO:     Finished server process [92787]
   INFO:     Stopping reloader process [92785]
   ```

</details>

------------------------


<details>
<summary>Phase 2 (Adversarial version) Setup Guide</summary>

# Setup Guide

## Starting Phase 1 (Benign)

**From the root folder (folder containing requirements.txt) in the terminal:**

```bash
cd "Phase 2 (Adversarial version)"
cd server
pip install -r "../../requirements.txt"
python server.py
```

You should see the following when the server has successfully started:

```bash
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process [92633] using StatReload
INFO:     Started server process [92635]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```

---

## Loading the Extension

1. Open Chromium and navigate to `chrome://extensions/`.
2. Enable **Developer Mode** (toggle in the top right).
3. Click **Load unpacked**.
4. Navigate to:
   
   ```text
   (root folder)/Phase 1 (Benign version)/extension
   ```

5. Select the **extension** folder to load it.

You can now use the extension freely.



## Stopping the Server

When you are finished using the extension:

1. In the terminal where the server is running, press:

   ```bash
   CTRL+C
   ```

2. You should then see output similar to:

   ```bash
   ^CINFO:     Shutting down
   INFO:     Waiting for application shutdown.
   INFO:     Application shutdown complete.
   INFO:     Finished server process [92787]
   INFO:     Stopping reloader process [92785]

## Unloading the Extension

When you're done using the extension in Chromium:

1. Go to: `chrome://extensions/`
2. Locate the **HTTPS Scanner** extension in the list.
3. Toggle the blue switch (bottom-right of the extension box) to turn it **off**.
4. (Optional) Click **Remove** to completely uninstall it from the browser.

You can always re-load it again using the steps in the **"Loading the Extension"** section.


</details>


------------------------
<details>
<summary>Phase 3 (User Study) Dataset & Reproduction Guide</summary>

This section contain the raw data that was exctracted form the User study which supports the claims made in the report

### What’s in this folder?



| File / sub-folder | Purpose |
|-------------------|---------|
| **`cleaned - confidence_improvement.xlsx`** | Per-participant pre- vs post-task self-confidence ratings and calculated scores|
| **`cleaned - survey_full.xlsx`** | De-duplicated version of the raw sheet with extra info added at the end from cleaning|
| **`cleaned - sus_scores_dataset.xlsx`** | Adds calculated System Usability Scale (SUS) scores for each participant. |
| **`cleaned - user confidence increase.xlsx`** | Aggregated *gain* scores (average) used in the report figures. |
| **`original - Tracking and Profiling Online - User Survey (Responses).xlsx`** | Raw export from Google Forms (one row per participant). No cleaning applied. |


</details>

------------------------


<details>
<summary>Phase 4 (address the issues) Setup Guide</summary>

# Setup Guide

## Starting Phase 4 (address the issues)

**From the root folder (folder containing requirements.txt) in the terminal:**

```bash
cd "Phase 4 (address the issues)"
cd server
pip install -r "../../requirements.txt"
python server.py
```

You should see the following when the server has successfully started:

```bash
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process [92633] using StatReload
INFO:     Started server process [92635]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```

---

## Loading the Extension

1. Open Chromium and navigate to `chrome://extensions/`.
2. Enable **Developer Mode** (toggle in the top right).
3. Click **Load unpacked**.
4. Navigate to:
   
   ```text
   (root folder)/Phase 1 (Benign version)/extension
   ```

5. Select the **extension** folder to load it.

You can now use the extension freely.



## Stopping the Server

When you are finished using the extension:

1. In the terminal where the server is running, press:

   ```bash
   CTRL+C
   ```

2. You should then see output similar to:

   ```bash
   ^CINFO:     Shutting down
   INFO:     Waiting for application shutdown.
   INFO:     Application shutdown complete.
   INFO:     Finished server process [92787]
   INFO:     Stopping reloader process [92785]



## Unloading the Extension

When you're done using the extension in Chromium:

1. Go to: `chrome://extensions/`
2. Locate the **HTTPS Scanner** extension in the list.
3. Toggle the blue switch (bottom-right of the extension box) to turn it **off**.
4. (Optional) Click **Remove** to completely uninstall it from the browser.

You can always re-load it again using the steps in the **"Loading the Extension"** section.


</details>


------------------

<details>
<summary>⚠️ Important: Close Previous Server Before Starting Another</summary>



## ⚠️ Important: Close Previous Server Before Starting Another

Before starting a new phase or running a different server:

> **Always stop the currently running server first.**

If you forget to stop the server, the new one may fail to start due to port conflicts.

### How to Stop the Running Server

In the terminal where the server is running:

```bash
CTRL+C
```

You should see shutdown messages like:

```bash
^CINFO:     Shutting down
INFO:     Waiting for application shutdown.
INFO:     Application shutdown complete.
```

### If That Doesn't Work (Force Kill the Process)

If the server doesn't close properly or the port is still in use, run the following command to find and kill it:

```bash
lsof -i :8000
```

This will show something like:

```bash
python3   12345 username   3u  IPv4  ...  TCP *:8000 (LISTEN)
```

Then kill it with:

```bash
kill -9 12345
```

Replace `12345` with the actual PID from the previous command.

</details>

------------
<details>
<summary>Unit Test</summary>

to run test go to server directory of any of the phases and run in terminal:


python -m unittest Privacy_scan.Privacy_scan_tests.Passive_Cookie_Privacy_Scan_test -v

python -m unittest Privacy_scan.Privacy_scan_tests.Passive_Data_Leakage_HTTP_Headers_Scan_test -v

python -m unittest Privacy_scan.Privacy_scan_tests.Passive_Do_Not_Track_Support_Scan_test -v

python -m unittest Privacy_scan.Privacy_scan_tests.Passive_Fingerprinting_Detection_Scan_test -v

python -m unittest Privacy_scan.Privacy_scan_tests.Passive_Privacy_and_Tracker_Audit_Scanner_test -v

python -m unittest Privacy_scan.Privacy_scan_tests.Passive_Referrer_DNT_Analysis_Scan_test -v

python -m unittest Privacy_scan.Privacy_scan_tests.Passive_Third_Party_Data_Collection_Scanner_test -v

python -m unittest Privacy_scan.Privacy_scan_tests.Passive_Third_Party_Script_Evaluation_Scanner_test -v

python -m unittest Privacy_scan.Privacy_scan_tests.Passive_Tracker_Detection_Scan_test -v   

python -m unittest Privacy_scan.Privacy_scan_tests.Passive_Tracker_Script_Scanner_test -v  





python -m unittest Security_scans.Security_scans_tests.Passive_CSP_Security_Scanner_test -v   

python -m unittest Security_scans.Security_scans_tests.Passive_CSRF_Security_Scanner_test -v

python -m unittest Security_scans.Security_scans_tests.Passive_Directory_Listing_Security_Scanner_test -v

python -m unittest Security_scans.Security_scans_tests.Passive_HTTPS_Scanner_test -v   

python -m unittest Security_scans.Security_scans_tests.Passive_Mixed_Content_Detection_Scanner_test -v 

python -m unittest Security_scans.Security_scans_tests.Passive_Outdated_Plugin_Security_Scanner_test -v  

python -m unittest Security_scans.Security_scans_tests.Passive_Performance_and_Configuration_Analysis_Scanner_test -v

python -m unittest Security_scans.Security_scans_tests.Passive_Security_Headers_Scanner_test -v  

python -m unittest Security_scans.Security_scans_tests.Passive_SQL_Injection_Security_Scanner_test -v 

python -m unittest Security_scans.Security_scans_tests.Passive_SSL_TLS_Certificate_Validation_Scanner_test -v   

python -m unittest Security_scans.Security_scans_tests.Passive_Vulnerability_Cross_Reference_Scanner_test -v  

python -m unittest Security_scans.Security_scans_tests.Passive_XSS_Security_Scanner_test -v     


<details>