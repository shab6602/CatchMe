document.getElementById('checkForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const urlInput = document.getElementById('incoming_url').value;
    const loader = document.getElementById('loader');
    const results = document.getElementById('results');
    
    if (!isValidUrl(urlInput)) {
        results.style.display = 'block';
        results.innerHTML = `<div class="error-message">⚠️ Please enter a valid URL (e.g., https://example.com)</div>`;
        return;
    }
    
    loader.style.display = 'block';
    results.style.display = 'none';
    
    try {
        const response = await chrome.runtime.sendMessage({
            action: 'checkURL',
            url: urlInput
        });
        
        loader.style.display = 'none';
        results.style.display = 'block';
        results.innerHTML = formatResults(response, urlInput);
        
        const reportLink = document.getElementById('detailedReportLink');
        if (reportLink) {
            reportLink.addEventListener('click', (e) => {
                e.preventDefault();
                openDetailedReport(urlInput);
            });
        }
    } catch (error) {
        loader.style.display = 'none';
        results.style.display = 'block';
        results.innerHTML = `<div class="error-message">⚠️ Error: ${error.message}</div>`;
    }
});

// Add event listener for scanning current page
document.getElementById('scanCurrentBtn').addEventListener('click', async () => {
    const loader = document.getElementById('loader');
    const results = document.getElementById('results');
    
    try {
        // Get the current active tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        if (!tab || !tab.url) {
            results.style.display = 'block';
            results.innerHTML = `<div class="error-message">⚠️ Unable to get current page URL</div>`;
            return;
        }
        
        // Don't scan chrome:// or extension pages
        if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
            results.style.display = 'block';
            results.innerHTML = `<div class="error-message">⚠️ Cannot scan browser internal pages</div>`;
            return;
        }
        
        // Fill the input field with current URL
        document.getElementById('incoming_url').value = tab.url;
        
        // Start scanning
        loader.style.display = 'block';
        results.style.display = 'none';
        
        const response = await chrome.runtime.sendMessage({
            action: 'checkURL',
            url: tab.url
        });
        
        loader.style.display = 'none';
        results.style.display = 'block';
        results.innerHTML = formatResults(response, tab.url);
        
        const reportLink = document.getElementById('detailedReportLink');
        if (reportLink) {
            reportLink.addEventListener('click', (e) => {
                e.preventDefault();
                openDetailedReport(tab.url);
            });
        }
    } catch (error) {
        loader.style.display = 'none';
        results.style.display = 'block';
        results.innerHTML = `<div class="error-message">⚠️ Error: ${error.message}</div>`;
    }
});

function isValidUrl(string) {
    try {
        if (!string.startsWith('http://') && !string.startsWith('https://')) {
            string = 'http://' + string;
        }
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

function formatResults(data, originalUrl) {
    if (!data || data.error) {
        return `<div class="error-message">⚠️ ${data?.error || 'Failed to check URL'}</div>`;
    }
    
    const aiAnalysis = data.ai_analysis || {};
    const combinedRisk = data.combined_risk_score || { score: 0, level: 'unknown' };
    
    let detectionClass = 'safe';
    let statusIcon = '✓';
    let statusText = 'URL appears safe';
    let statusClass = 'safe';
    
    if (combinedRisk.level === 'critical' || aiAnalysis.is_phishing) {
        detectionClass = 'danger';
        statusIcon = '🚨';
        statusText = 'PHISHING DETECTED - DO NOT VISIT';
        statusClass = 'danger';
    } else if (combinedRisk.level === 'high') {
        detectionClass = 'danger';
        statusIcon = '⚠️';
        statusText = 'High risk - Avoid this URL';
        statusClass = 'danger';
    } else if (combinedRisk.level === 'medium') {
        detectionClass = 'warning';
        statusIcon = '⚠️';
        statusText = 'Suspicious activity detected';
        statusClass = 'warning';
    } else if (data.message) {
        statusIcon = 'ℹ️';
        statusText = data.message;
        statusClass = 'info';
    }
    
    let html = '<h3>🤖 AI Security Analysis</h3>';
    
    html += `<div class="result-item">
        <strong>URL:</strong><br>
        <span class="result-url">${escapeHtml(data.url || originalUrl)}</span>
    </div>`;
    
    html += `<div class="result-item">
        <strong>Combined Risk Score:</strong><br>
        <span class="detection-rate ${detectionClass}">${combinedRisk.score}/100</span>
        <small style="display: block; margin-top: 5px; color: #9ca3af;">
            AI: ${combinedRisk.ai_score || 0}/100 | VirusTotal: ${combinedRisk.vt_score || 0}/100
        </small>
    </div>`;
    
    if (aiAnalysis.threats_detected && aiAnalysis.threats_detected.length > 0) {
        html += `<div class="result-item">
            <strong>Threats Detected:</strong><br>
            <div style="margin-top: 8px;">
                ${aiAnalysis.threats_detected.map(threat => 
                    `<span class="detection-rate danger" style="margin: 4px; display: inline-block;">${escapeHtml(threat)}</span>`
                ).join('')}
            </div>
        </div>`;
    }
    
    html += `<div class="status-message ${statusClass}">
        <span>${statusIcon}</span>
        <span><strong>${statusText}</strong></span>
    </div>`;
    
    if (aiAnalysis.warnings && aiAnalysis.warnings.length > 0) {
        html += `<div class="result-item" style="background: rgba(239, 68, 68, 0.1); padding: 12px; border-radius: 8px; border-left: 3px solid #ef4444;">
            <strong style="color: #ef4444;">⚠️ Warnings:</strong>
            <ul style="margin: 8px 0 0 20px; color: #fca5a5;">
                ${aiAnalysis.warnings.map(w => `<li>${escapeHtml(w)}</li>`).join('')}
            </ul>
        </div>`;
    }
    
    if (aiAnalysis.recommendation) {
        html += `<div class="result-item" style="background: rgba(59, 130, 246, 0.1); padding: 12px; border-radius: 8px;">
            <strong>💡 Recommendation:</strong><br>
            <span style="color: #60a5fa;">${escapeHtml(aiAnalysis.recommendation)}</span>
        </div>`;
    }
    
    html += `<div class="result-item">
        <strong>VirusTotal:</strong> ${data.positives}/${data.total} engines flagged this URL
    </div>`;
    
    html += `<a href="#" id="detailedReportLink" class="view-report-link">
        View Detailed Report →
    </a>`;
    
    return html;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function openDetailedReport(url) {
    chrome.tabs.create({
        url: chrome.runtime.getURL(`report.html?url=${encodeURIComponent(url)}`)
    });
}

document.querySelector('input[type="reset"]').addEventListener('click', () => {
    document.getElementById('results').style.display = 'none';
});