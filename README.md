# DMARC Checker

A simple tool to quickly parse DMARC aggregate report .zip, .gz, or .xml files (containing XML), providing an on-screen summary when triggered from Finder on macOS.

---

## 📌 Intent

The main goal is to automate the process of extracting and summarizing DMARC aggregate reports (sent as zipped or gzipped XML files via email). By right-clicking a .zip, .gz, or .xml file in Finder and running a Quick Action, users get a clear, human-readable summary of the DMARC report directly on their Mac, without manual extraction or complex tools.

---

## ⚙️ Actions

Primary functions this project performs:
- Unzip or decompress the selected .zip or .gz file (or accept a raw .xml file).
- Locate and parse the enclosed DMARC XML report(s).
- Extract key statistics: sending domain, report period, total messages, pass/fail counts for SPF/DKIM, source IPs, etc.
- Display a concise, emoji-enhanced summary in a persistent dialog box (or terminal window if run directly).
- (Optional) Handle multiple XML files in one .zip.

---

## 📥 Input

Necessary inputs for this project:
- A .zip, .gz, or .xml file containing one or more DMARC aggregate XML reports (as received from mailbox providers).

Constraints/prerequisites:
- The archive must contain valid DMARC XML files.
- Script should be executable from Finder’s “Quick Actions” (recommended) or from the terminal.

---

## 📤 Output

What the project produces:
- On-screen summary in a persistent dialog box (via AppleScript) showing:
  - Reporting organization
  - Report date range
  - Domain(s) covered
  - Total messages analyzed
  - SPF/DKIM pass/fail counts
  - Notable source IPs
  - Emoji-enhanced status and recommendations
- (Optional) Output to terminal for debugging or direct use.

---

## 🧱 Framework

Technology stack and setup instructions:
- **Primary Language/Framework:** Python 3 (pre-installed on macOS)
- **Dependencies:**
  - Standard libraries: zipfile, gzip, xml.etree.ElementTree, subprocess, sys, os, datetime
  - Uses AppleScript via `osascript` for dialog output (no extra install needed)

---

## 🚀 Setup & Usage

### 1. Clone or Download
Clone this repository or download the script to your Mac.

### 2. Place the Script
Put `dmarc_report_parser.py` in a convenient location (e.g., your home or scripts directory).

### 3. Create a Finder Quick Action (Automator)
1. Open **Automator** and create a new **Quick Action**.
2. Set "Workflow receives current" to **files or folders** in **Finder**.
3. Add a **Run Shell Script** action:
   - Shell: `/bin/zsh` (or `/bin/bash`)
   - Pass input: **as arguments**
   - Script:
     ```sh
     python3 /path/to/dmarc_report_parser.py "$@"
     ```
   - Replace `/path/to/dmarc_report_parser.py` with the actual path to your script.
4. Save the Quick Action (e.g., "Parse DMARC Report").

### 4. Use It!
- Right-click any DMARC .zip, .gz, or .xml report in Finder.
- Choose your Quick Action (e.g., "Parse DMARC Report").
- A dialog box will appear with a summary of the report.

### 5. (Optional) Run from Terminal
You can also run the script directly:
```sh
python3 dmarc_report_parser.py /path/to/report.zip
```

---

## 📝 Example Output

```
Report for: example.com
From: google.com
Policy: p=quarantine, sp=quarantine, pct=100
Report Period: 2025-07-22 00:00:00 UTC to 2025-07-22 23:59:59 UTC

❌ Failure

4 emails was sent from IP 62.60.208.87
❌ Passed SPF
❌ Passed DKIM checks
🚫 Blocked or sent to spam
google.com rejected or quarantined the message based on your DMARC policy.

⸻

✅ Successful Delivery

One (1) email was sent from IP 209.85.220.41
✅ Passed SPF
✅ Passed DKIM checks
✅ No delivery issues
google.com fully accepted and processed the message in line with your DMARC policy.
```

---

## 🙏 Credits

Created by [sjelms](https://github.com/sjelms).

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 🌐 Repository

Find the latest version and contribute at: [https://github.com/sjelms/dmarc-checker](https://github.com/sjelms/dmarc-checker)