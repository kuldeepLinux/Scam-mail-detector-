function analyzeEmail() {
    const headerText = document.getElementById('headerInput').value;
    if (!headerText.trim()) return alert("Please paste email headers first!");

    let score = 0;
    let redFlags = [];
    let safeFlags = [];
    
    // Extract Sender and Subject
    const fromMatch = headerText.match(/^From:\s*(.*)$/mi);
    const subjectMatch = headerText.match(/^Subject:\s*(.*)$/mi);
    document.getElementById('senderSpan').textContent = fromMatch ? fromMatch[1].trim() : "Unknown";
    document.getElementById('subjectSpan').textContent = subjectMatch ? subjectMatch[1].trim() : "Unknown";

    // Check Auth Results
    const authMatch = headerText.match(/^Authentication-Results:\s*(.*?)(?=\n\S)/mis);
    
    if (authMatch) {
        const authText = authMatch[1].toLowerCase();
        
        if (authText.includes("spf=pass")) safeFlags.push("SPF Authentication Passed");
        else { redFlags.push("SPF Authentication Failed/Missing (Sender may be forged)"); score += 30; }

        if (authText.includes("dkim=pass")) safeFlags.push("DKIM Authentication Passed");
        else { redFlags.push("DKIM Authentication Failed/Missing (Email may be tampered)"); score += 30; }

        if (authText.includes("dmarc=pass")) safeFlags.push("DMARC Authentication Passed");
        else { redFlags.push("DMARC Authentication Failed/Missing"); score += 20; }
    } else {
        redFlags.push("No Authentication-Results found. Cannot verify sender.");
        score += 50;
    }

    // Final Risk Level
    let riskLevel = "";
    let color = "";
    if (score >= 70) { riskLevel = "HIGH RISK (SCAM)"; color = "red"; }
    else if (score >= 40) { riskLevel = "SUSPICIOUS"; color = "orange"; }
    else { riskLevel = "LIKELY SAFE"; color = "green"; }

    // Update UI
    const scoreDiv = document.getElementById('scoreDiv');
    scoreDiv.textContent = `Risk Score: ${score}/100 (${riskLevel})`;
    scoreDiv.style.color = color;
    
    const resultBox = document.getElementById('resultBox');
    resultBox.style.display = "block";
    resultBox.style.borderLeftColor = color;

    const redList = document.getElementById('redFlagsList');
    redList.innerHTML = redFlags.length ? redFlags.map(f => `<li class="red-flag">${f}</li>`).join('') : '<li>None detected.</li>';

    const safeList = document.getElementById('safeFlagsList');
    safeList.innerHTML = safeFlags.length ? safeFlags.map(f => `<li class="safe-flag">${f}</li>`).join('') : '<li>None detected.</li>';
}
