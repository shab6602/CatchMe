# CatchMe <img width="107" height="94" alt="image" src="https://github.com/user-attachments/assets/09d76900-5814-41e5-8c75-df4dfca89726" />

CatchMe is an intelligent phishing-detection browser extension that safeguards users from malicious websites and suspicious email links.
It combines VirusTotal threat intelligence with Gemini AI content analysis to evaluate URLs and webpage behavior in real time and provide instant, actionable security insights.
# Features

## Real-Time URL Scanning
Automatically checks every visited or clicked URL using the VirusTotal API.

## AI-Driven Content Analysis
Uses Gemini AI to evaluate webpage text, structure, and intent for phishing patterns.

## Instant Risk Scoring
Provides a clear, easy-to-understand risk score (Safe / Suspicious / Malicious).

## Smart Alerts & Recommendations
Shows warnings and quick security suggestions to help users avoid unsafe sites.

## Lightweight & Fast
Designed for minimal performance overhead and smooth browser usage.

# How It Works

1)User visits a webpage or clicks a link.

2)CatchMe extracts the URL and sends it to VirusTotal for reputation analysis.

3)Simultaneously, the webpage’s content is processed by Gemini AI to detect phishing cues such as:

  a) Urgency or fear-based language

  b) Fake login pages

  c) Spoofed branding and deceptive UI

4)Results are combined into a final risk score and shown to the user through the extension popup.

# TechStack
JavaScript – Core logic

HTML/CSS – UI and popup design

VirusTotal API – URL reputation checks

Gemini AI API – Semantic content analysis

Browser Extension APIs – For Chrome/Edge/Brave/Firefox compatibility


