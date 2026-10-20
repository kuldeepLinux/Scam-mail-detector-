function analyzeEmail() {
    const headerText = document.getElementById('headerInput').value;
    if (!headerText.trim()) return alert("Please paste email headers first!");

    let score = 0;
    let redFlags = [];
    let safeFlags = [];
    
    // 1. Extract Sender and Subject
    const fromMatch = headerText.match(/^From:\s*(.*)$/mi);
    const subjectMatch = headerText.match(/^Subject:\s*(.*)$/mi);
    const replyToMatch = headerText.match(/^Reply-To:\s*(.*)$/mi);
    
    const sender = fromMatch ? fromMatch[1].trim() : "Unknown";
    const subject = subjectMatch ? subjectMatch[1].trim() : "Unknown";
    
    document.getElementById('senderSpan').textContent = sender;
    document.getElementById('subjectSpan').textContent = subject;

    // 2. Check Authentication Results (Global search)
    const spfMatch = headerText.match(/spf=(\w+)/i);
    const dkimMatch = headerText.match(/dkim=(\w+)/i);
    const dmarcMatch = headerText.match(/dmarc=(\w+)/i);

    if (spfMatch) {
        if (spfMatch[1].toLowerCase() === "pass") safeFlags.push("SPF Authentication Passed");
        else { redFlags.push(`SPF Authentication Failed (${spfMatch[1]}) - Sender likely forged`); score += 30; }
    } else {
        redFlags.push("SPF Authentication Missing - Cannot verify sender"); score += 20;
    }

    if (dkimMatch) {
        if (dkimMatch[1].toLowerCase() === "pass") safeFlags.push("DKIM Authentication Passed");
        else { redFlags.push(`DKIM Authentication Failed (${dkimMatch[1]}) - Email may be tampered`); score += 30; }
    } else {
        redFlags.push("DKIM Authentication Missing"); score += 20;
    }

    if (dmarcMatch) {
        if (dmarcMatch[1].toLowerCase() === "pass") safeFlags.push("DMARC Authentication Passed");
        else { redFlags.push(`DMARC Authentication Failed (${dmarcMatch[1]})`); score += 20; }
    } else {
        redFlags.push("DMARC Authentication Missing"); score += 20;
    }

    // 3. Reply-To Mismatch Check
    if (replyToMatch && fromMatch) {
        const replyToDomain = replyToMatch[1].split('@')[1];
        const fromDomain = fromMatch[1].split('@')[1];
        if (replyToDomain && fromDomain && !replyToDomain.includes(fromDomain)) {
            redFlags.push(`Reply-To Mismatch: Sender is ${fromDomain} but replies go to ${replyToDomain}. Classic Phishing trick!`);
            score += 20;
        }
    }

    // 4. Scam Keywords Check (Extortion/Phishing)
    const scamKeywords = ["bitcoin", "webcam", "hacked", "trojan", "porn", "masturbating", "recorded", "pay", "wallet", "urgent", "threat"];
    let foundKeywords = [];
    scamKeywords.forEach(word => {
        if (headerText.toLowerCase().includes(word)) {
            foundKeywords.push(word);
        }
    });

    if (foundKeywords.length > 0) {
        redFlags.push(`Suspicious keywords found: ${foundKeywords.join(", ")}. (Possible Extortion/Phishing)`);
        score += 30;
    }

    // Final Risk Level
    let riskLevel = "";
    let color = "";
    
    // Max score cap at 100
    score = Math.min(score, 100);

    if (score >= 60) { riskLevel = "HIGH RISK (SCAM)"; color = "red"; }
    else if (score >= 30) { riskLevel = "SUSPICIOUS"; color = "orange"; }
    else { riskLevel = "LIKELY SAFE"; color = "green"; }

    // Update UI
    const scoreDiv = document.getElementById('scoreDiv');
    scoreDiv.textContent = `Risk Score: ${score}/100 (${riskLevel})`;
    scoreDiv.style.color = color;
    
    const resultBox = document.getElementById('resultBox');
    resultBox.style.display = "block";
    resultBox.style.borderLeftColor = color;

    const redList = document.getElementById('redFlagsList');
    redList.innerHTML = redFlags.length ? redFlags.map(f => `<li class="red-flag">❌ ${f}</li>`).join('') : '<li>None detected.</li>';

    const safeList = document.getElementById('safeFlagsList');
    safeList.innerHTML = safeFlags.length ? safeFlags.map(f => `<li class="safe-flag">✅ ${f}</li>`).join('') : '<li>None detected.</li>';
}
