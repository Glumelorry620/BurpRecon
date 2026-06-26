# 🔍 BurpRecon - Find security flaws in saved scans

[![Download the latest version](https://img.shields.io/badge/Download-Releases-blue.svg)](https://github.com/Glumelorry620/BurpRecon/releases)

BurpRecon helps you identify potential security issues in your web applications. You use this tool to process data exported from Burp Suite. The program searches for broken object level access, host header injections, and password reset flaws. It automates the analysis of large log files to save you time. 

## ⚙️ System Requirements

This application requires a Windows operating system. Ensure your computer meets these basic specifications to run the software smoothly:

- Windows 10 or Windows 11
- 4 GB of RAM
- 500 MB of available disk space
- An active internet connection for updates

## 📥 How to Install

Follow these steps to set up the software on your computer.

1. Visit [this page to download](https://github.com/Glumelorry620/BurpRecon/releases).
2. Look for the latest version under the Releases section.
3. Click the link that ends in .exe to start your download.
4. Open the folder where your browser saved the file.
5. Double-click the BurpRecon installer file.
6. Follow the on-screen prompts to complete the setup process.
7. Click Finish to close the installer.

## 🚀 Getting Started

Launch BurpRecon from your desktop shortcut or the Start menu. The main interface displays a clean dashboard with several tabs. You start by importing log files.

### Preparing your data

Burp Suite tracks your activity in a log file. You need this file to let BurpRecon perform its analysis. 

1. Open Burp Suite.
2. Go to the HTTP history tab.
3. Select all items you want to test.
4. Right-click your selection and choose Save items.
5. Save the file in XML format.

### Running an analysis

Once you have your XML file, you feed it into BurpRecon.

1. Open BurpRecon.
2. Click the Import button on the left sidebar.
3. Find your XML file and select Open.
4. Choose the type of scan you want to perform.
5. Select the Analyze button to start the process.
6. Wait for the progress bar to reach the end.

## 🛡️ Understanding Results

The tool provides a list of findings once it finishes the scan. The results screen categorizes each item by risk level.

- Critical: These items require your immediate attention. They often point to direct access flaws.
- High: These issues identify significant security gaps. Address these after you fix the critical items.
- Medium: These items suggest configuration errors that attackers might exploit.
- Low: These findings represent minor issues or informational logs.

Select any item in the list to see more details. The sidebar displays the specific part of the request that triggered the alert. You can copy the request to your clipboard for further testing in Burp Suite.

## 🛠️ Configuration Settings

You can customize how BurpRecon scans your data. Open the Settings menu to change your preferences.

- Network: Use this section if you need to set up a proxy for your connection.
- Reporting: Choose your preferred format for output files. You can save reports as PDF or CSV files.
- Filters: Exclude specific file types or domains to focus your analysis on relevant areas.

Click Save at the bottom of the window to apply your changes.

## ❓ Common Questions

### Does the software send my data to a server?
No. BurpRecon performs all analysis locally on your computer. Data never leaves your machine.

### Can I run multiple scans at once?
Yes. Open separate instances of the software if you need to run large scans in parallel.

### Do I need a paid Burp Suite license?
No. BurpRecon works with exported logs from both the Community and Professional editions of Burp Suite.

### Will this software harm my computer?
No. BurpRecon only reads files. It does not modify system settings or delete your personal data.

### How often should I check for updates?
Check the releases page once a month. New versions often include better detection logic for the latest security patterns.

### Can I save my scan results?
Yes. Select the Export button to save a report after your analysis. This keeps a record of each vulnerability found during your session.

## 📝 Troubleshooting

If the software fails to open, check that you have the latest Windows updates installed. Sometimes, security software on your computer might block the program. Check your antivirus settings if the application fails to launch or closes unexpectedly. 

If you cannot import a file, ensure your file uses the correct XML format. BurpRecon expects the standard Burp Suite XML structure. If you see an error message during the scan, take a screenshot of the error and verify your internet connection. 

Persistence is key in security testing. If a scan returns no results, try expanding the scope of your saved logs in Burp Suite. Ensure you navigate through all pages of your target application before you export the history. This provides the tool with more data to analyze.