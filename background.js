// ealmonte32
// v:google.chrome

// API Keys
const VIRUSTOTAL_API_KEY = '<your api key>';
const GEMINI_API_KEY = 'your api key';

// Cache for results (to speed up repeated checks)
const cache = new Map();
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

// declare variables
var google_query;
var parsed_url;
var parsed_url_query;
var uri;
var uri_decode;
var url_scheme;
var url_address;
var url_query_match;

// main
chrome.contextMenus.create({
    "id": "id_checkVT",
    "title": "Scan with CatchMe",
    "contexts": ["selection", "link"]
});

chrome.contextMenus.onClicked.addListener(function (item, tab) {
    "use strict";

    // if both a link and plaintext selection were detected, we remove the plaintext
    if ((item.linkUrl) && (item.selectionText)) {
        delete item.selectionText;
    }

    // if the item right clicked is plaintext
    if (item.selectionText) {
        uri = item.selectionText;
        uri_decode = decodeURIComponent(uri);
        item.selectionText = uri_decode;

        if (!(/^http:\/\//.test(item.selectionText)) && !(/^https:\/\//.test(item.selectionText))) {
            url_scheme = 'http://';
            parsed_url = url_scheme.concat(item.selectionText);
            chrome.tabs.create({
                url: chrome.runtime.getURL(`report.html?url=${encodeURIComponent(parsed_url)}`),
                index: tab.index + 1
            });
        } else {
            chrome.tabs.create({
                url: chrome.runtime.getURL(`report.html?url=${encodeURIComponent(item.selectionText)}`),
                index: tab.index + 1
            });
        }
    }

    // if the item right clicked is a link
    if (item.linkUrl) {
        // if url is a google.com search query, take the url= part only
        if ((/^https:\/\/www.google.com(.*)/.test(item.linkUrl)) && ((item.linkUrl).toString().match(/url\=(.*)/g))) {
            google_query = item.linkUrl;
            url_query_match = google_query.toString().match(/url\=(.*)/g);
            parsed_url_query = url_query_match.toString().replace('url=', '');
            chrome.tabs.create({
                url: chrome.runtime.getURL(`report.html?url=${encodeURIComponent(parsed_url_query)}`),
                index: tab.index + 1
            });
        } else {
            chrome.tabs.create({
                url: chrome.runtime.getURL(`report.html?url=${encodeURIComponent(item.linkUrl)}`),
                index: tab.index + 1
            });
        }
    }
});

// Handle messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'checkURL') {
        checkURLWithAI(request.url)
            .then(result => sendResponse(result))
            .catch(error => sendResponse({ error: error.message }));
        return true;
    }
    
    if (request.action === 'getDetailedReport') {
        getDetailedReportWithAI(request.url)
            .then(result => sendResponse(result))
            .catch(error => sendResponse({ error: error.message }));
        return true;
    }
});

// Extract JSON from various formats
function extractJSON(text) {
    try {
        // Remove markdown code blocks
        let jsonText = text.trim();
        
        // Remove ```json and ``` markers (including newlines)
        jsonText = jsonText.replace(/```json\n?/g, '').replace(/```\n?/g, '');
        
        // Try to find JSON object in the text (including nested objects)
        const jsonMatch = jsonText.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
            jsonText = jsonMatch[0];
        }
        
        // Clean up any remaining non-JSON text before the object
        const firstBrace = jsonText.indexOf('{');
        if (firstBrace > 0) {
            jsonText = jsonText.substring(firstBrace);
        }
        
        // Parse the JSON
        const parsed = JSON.parse(jsonText);
        
        // Validate required fields
        if (!parsed.risk_score && parsed.risk_score !== 0) {
            throw new Error('Missing risk_score field');
        }
        
        return parsed;
    } catch (error) {
        console.error('❌ JSON extraction failed:', error.message);
        console.error('📄 Original text:', text);
        console.error('📄 First 500 chars:', text.substring(0, 500));
        throw new Error(`Failed to parse AI response: ${error.message}`);
    }
}

// AI-Powered URL Analysis with Gemini
async function analyzeURLWithGemini(url) {
    console.log('Starting Gemini analysis for:', url);
    
    // Check cache first
    const cacheKey = `gemini_${url}`;
    const cached = cache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
        console.log('Using cached Gemini result');
        return cached.data;
    }
    
    try {
        const prompt = `Analyze this URL for phishing and security threats: ${url}

You must respond with ONLY valid JSON, no markdown formatting. Use this exact format:

{
  "risk_score": 25,
  "risk_level": "low",
  "is_phishing": false,
  "threats_detected": ["Suspicious TLD"],
  "warnings": ["URL uses uncommon domain"],
  "indicators": {
    "domain_spoofing": false,
    "suspicious_tld": true,
    "missing_https": false,
    "suspicious_keywords": false,
    "url_shortener": false,
    "credential_harvesting": false
  },
  "analysis": "Brief security analysis",
  "recommendation": "What user should do"
}

Rules:
- risk_score: 0-100 (0=safe, 100=phishing)
- risk_level: "safe", "low", "medium", "high", or "critical"
- is_phishing: true or false
- Check for domain spoofing, suspicious TLDs, missing HTTPS, phishing keywords
- Keep analysis brief (2-3 sentences max)
- Respond with ONLY the JSON object, no extra text`;

        console.log('Sending request to Gemini API...');
        
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${GEMINI_API_KEY}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                contents: [{
                    parts: [{
                        text: prompt
                    }]
                }],
                generationConfig: {
                    temperature: 0.1,
                    topK: 20,
                    topP: 0.8,
                    maxOutputTokens: 2048,
                },
                safetySettings: [
                    {
                        category: "HARM_CATEGORY_HARASSMENT",
                        threshold: "BLOCK_NONE"
                    },
                    {
                        category: "HARM_CATEGORY_HATE_SPEECH",
                        threshold: "BLOCK_NONE"
                    },
                    {
                        category: "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                        threshold: "BLOCK_NONE"
                    },
                    {
                        category: "HARM_CATEGORY_DANGEROUS_CONTENT",
                        threshold: "BLOCK_NONE"
                    }
                ]
            })
        });

        console.log('Gemini API response status:', response.status);

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Gemini API error response:', errorText);
            throw new Error(`Gemini API error: ${response.status}`);
        }

        const data = await response.json();
        console.log('Gemini API full response:', JSON.stringify(data, null, 2));
        
        // Check if response was blocked
        if (data.promptFeedback && data.promptFeedback.blockReason) {
            console.error('❌ Content blocked:', data.promptFeedback.blockReason);
            throw new Error(`Content blocked: ${data.promptFeedback.blockReason}`);
        }
        
        // Check for candidates
        if (!data.candidates || data.candidates.length === 0) {
            console.error('❌ No candidates in response:', data);
            throw new Error('No response generated by Gemini');
        }
        
        // Check if candidate was blocked
        const candidate = data.candidates[0];
        if (candidate.finishReason === 'SAFETY') {
            console.error('❌ Response blocked by safety filters');
            throw new Error('Response blocked by safety filters');
        }
        
        if (!candidate.content || !candidate.content.parts || !candidate.content.parts[0]) {
            console.error('❌ Invalid candidate structure:', candidate);
            throw new Error('Invalid response structure from Gemini');
        }
        
        const aiResponse = candidate.content.parts[0].text;
        console.log('AI Response:', aiResponse.substring(0, 200) + '...');
        
        const analysis = extractJSON(aiResponse);
        console.log('Parsed analysis successfully');
        
        // Cache the result
        cache.set(cacheKey, {
            data: analysis,
            timestamp: Date.now()
        });
        
        return analysis;
    } catch (error) {
        console.error('Gemini Analysis Error:', error.message);
        
        // Return a simple safe default
        return {
            risk_score: 0,
            risk_level: 'unknown',
            is_phishing: false,
            threats_detected: [],
            warnings: ['AI analysis unavailable - using VirusTotal only'],
            indicators: {},
            analysis: 'AI analysis could not be completed. Relying on VirusTotal scan results.',
            recommendation: 'Review the VirusTotal scan results below.'
        };
    }
}

// Combined URL Check: VirusTotal + Gemini AI
async function checkURLWithAI(url) {
    try {
        console.log('Starting combined check for:', url);
        
        // Check cache first
        const cacheKey = `combined_${url}`;
        const cached = cache.get(cacheKey);
        if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
            console.log('Using cached combined result');
            return cached.data;
        }
        
        // Run VirusTotal first (it's faster)
        console.log('Checking VirusTotal...');
        const vtResult = await checkVirusTotal(url).catch(e => {
            console.error('VT Error:', e.message);
            return { error: e.message, positives: 0, total: 0 };
        });
        
        // Then run Gemini in parallel if VT succeeded
        console.log('Starting Gemini analysis...');
        const aiResult = await analyzeURLWithGemini(url);
        
        const result = {
            ...vtResult,
            ai_analysis: aiResult,
            combined_risk_score: calculateCombinedRisk(vtResult, aiResult)
        };
        
        // Cache the result
        cache.set(cacheKey, {
            data: result,
            timestamp: Date.now()
        });
        
        return result;
    } catch (error) {
        console.error('Combined check error:', error);
        throw error;
    }
}

// Calculate combined risk score from both sources
function calculateCombinedRisk(vtResult, aiResult) {
    const vtScore = vtResult.positives && vtResult.total 
        ? (vtResult.positives / vtResult.total) * 100 
        : 0;
    const aiScore = aiResult.risk_score || 0;
    
    // Weighted average: 60% AI, 40% VirusTotal
    const combined = (aiScore * 0.6) + (vtScore * 0.4);
    
    let level = 'safe';
    if (combined >= 75) level = 'critical';
    else if (combined >= 50) level = 'high';
    else if (combined >= 25) level = 'medium';
    else if (combined >= 10) level = 'low';
    
    return {
        score: Math.round(combined),
        level: level,
        vt_score: Math.round(vtScore),
        ai_score: Math.round(aiScore)
    };
}

async function checkVirusTotal(url) {
    try {
        // Check cache first
        const cacheKey = `vt_${url}`;
        const cached = cache.get(cacheKey);
        if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
            console.log('Using cached VT result');
            return cached.data;
        }
        
        // First try to get existing report (faster)
        const reportResponse = await fetch(
            `https://www.virustotal.com/vtapi/v2/url/report?apikey=${VIRUSTOTAL_API_KEY}&resource=${encodeURIComponent(url)}`
        );
        
        if (!reportResponse.ok) {
            throw new Error(`HTTP error! status: ${reportResponse.status}`);
        }
        
        const reportText = await reportResponse.text();
        if (!reportText) {
            throw new Error('Empty response from VirusTotal');
        }
        
        const reportData = JSON.parse(reportText);
        
        // If URL not found, submit it but don't wait
        if (reportData.response_code === 0) {
            // Submit scan in background (don't await)
            fetch('https://www.virustotal.com/vtapi/v2/url/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `apikey=${VIRUSTOTAL_API_KEY}&url=${encodeURIComponent(url)}`
            }).catch(e => console.error('VT scan submission error:', e));
            
            const result = {
                url: url,
                positives: 0,
                total: 0,
                scan_date: 'Not yet scanned',
                permalink: `https://www.virustotal.com/gui/url/${btoa(url)}/detection`,
                message: 'URL submitted for scanning. Check back in a few minutes.'
            };
            
            return result;
        }
        
        const result = {
            url: reportData.url || url,
            positives: reportData.positives || 0,
            total: reportData.total || 0,
            scan_date: reportData.scan_date,
            permalink: reportData.permalink
        };
        
        // Cache the result
        cache.set(cacheKey, {
            data: result,
            timestamp: Date.now()
        });
        
        return result;
    } catch (error) {
        console.error('VirusTotal API Error:', error);
        throw new Error(`Failed to check URL: ${error.message}`);
    }
}

async function getDetailedReportWithAI(url) {
    try {
        console.log('Getting detailed report for:', url);
        
        // Run both in parallel for speed
        const [vtResult, aiResult] = await Promise.all([
            getDetailedReport(url).catch(e => ({ error: e.message, positives: 0, total: 0, scans: {} })),
            analyzeURLWithGemini(url)
        ]);

        return {
            ...vtResult,
            ai_analysis: aiResult,
            combined_risk_score: calculateCombinedRisk(vtResult, aiResult)
        };
    } catch (error) {
        console.error('Detailed report error:', error);
        throw error;
    }
}

async function getDetailedReport(url) {
    try {
        const reportResponse = await fetch(
            `https://www.virustotal.com/vtapi/v2/url/report?apikey=${VIRUSTOTAL_API_KEY}&resource=${encodeURIComponent(url)}`
        );
        
        if (!reportResponse.ok) {
            throw new Error(`HTTP error! status: ${reportResponse.status}`);
        }
        
        const reportText = await reportResponse.text();
        if (!reportText) {
            throw new Error('Empty response from VirusTotal');
        }
        
        const reportData = JSON.parse(reportText);
        
        if (reportData.response_code === 0) {
            // Submit scan in background
            fetch('https://www.virustotal.com/vtapi/v2/url/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `apikey=${VIRUSTOTAL_API_KEY}&url=${encodeURIComponent(url)}`
            }).catch(e => console.error('VT scan error:', e));
            
            throw new Error('URL not yet scanned. Scan submitted - please try again in 1-2 minutes.');
        }
        
        return {
            url: reportData.url || url,
            positives: reportData.positives || 0,
            total: reportData.total || 0,
            scan_date: reportData.scan_date,
            permalink: reportData.permalink,
            scans: reportData.scans || {}
        };
    } catch (error) {
        console.error('VirusTotal API Error:', error);
        throw error;
    }
}

// Test function
async function testGeminiAPI() {
    try {
        console.log('Testing Gemini API...');
        
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${GEMINI_API_KEY}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                contents: [{
                    parts: [{
                        text: 'Respond with only this JSON: {"status": "ok"}'
                    }]
                }]
            })
        });

        const data = await response.json();
        
        if (response.ok && data.candidates) {
            console.log('✅ Gemini API is working!');
            return true;
        } else {
            console.error('❌ Gemini API test failed:', data);
            return false;
        }
    } catch (error) {
        console.error('❌ Gemini API test error:', error);
        return false;
    }
}

// Call this when extension loads
chrome.runtime.onInstalled.addListener(() => {
    console.log('CatchMe extension installed/updated');
    testGeminiAPI();
});
