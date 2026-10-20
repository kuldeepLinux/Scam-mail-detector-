from flask import Flask, render_template, request
import re

app = Flask(__name__)

def analyze_header(header_text):
    results = {
        "score": 0,
        "red_flags": [],
        "safe_flags": [],
        "sender": "Unknown",
        "subject": "Unknown"
    }

    from_match = re.search(r'^From:\s*(.*)$', header_text, re.MULTILINE | re.IGNORECASE)
    if from_match:
        results["sender"] = from_match.group(1).strip()

    subject_match = re.search(r'^Subject:\s*(.*)$', header_text, re.MULTILINE | re.IGNORECASE)
    if subject_match:
        results["subject"] = subject_match.group(1).strip()

    auth_match = re.search(r'^Authentication-Results:\s*(.*?)(?=\n\S)', header_text, re.MULTILINE | re.IGNORECASE | re.DOTALL)
    
    if auth_match:
        auth_text = auth_match.group(1).lower()
        
        if "spf=pass" in auth_text:
            results["safe_flags"].append("SPF Authentication Passed")
        else:
            results["red_flags"].append("SPF Authentication Failed/Missing (Sender may be forged)")
            results["score"] += 30

        if "dkim=pass" in auth_text:
            results["safe_flags"].append("DKIM Authentication Passed")
        else:
            results["red_flags"].append("DKIM Authentication Failed/Missing (Email may be tampered)")
            results["score"] += 30

        if "dmarc=pass" in auth_text:
            results["safe_flags"].append("DMARC Authentication Passed")
        else:
            results["red_flags"].append("DMARC Authentication Failed/Missing")
            results["score"] += 20
    else:
        results["red_flags"].append("No Authentication-Results found. Cannot verify sender.")
        results["score"] += 50

    return_path_match = re.search(r'^Return-Path:\s*<(.*?)>', header_text, re.MULTILINE | re.IGNORECASE)
    if return_path_match and results["sender"] != "Unknown":
        return_path = return_path_match.group(1).lower()
        if "@" in return_path and "@" in results["sender"]:
            rp_domain = return_path.split("@")[-1].replace(">", "")
            from_domain = results["sender"].split("@")[-1].split(">")[0]
            if rp_domain not in from_domain and from_domain not in rp_domain:
                results["red_flags"].append(f"Return-Path ({rp_domain}) does not match From ({from_domain}). High chance of Spoofing!")
                results["score"] += 20

    if results["score"] >= 70:
        results["risk_level"] = "HIGH RISK (SCAM)"
        results["color"] = "red"
    elif results["score"] >= 40:
        results["risk_level"] = "SUSPICIOUS"
        results["color"] = "orange"
    else:
        results["risk_level"] = "LIKELY SAFE"
        results["color"] = "green"

    return results

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        header_text = request.form.get('header_text', '')
        if header_text.strip():
            analysis = analyze_header(header_text)
            return render_template('index.html', analysis=analysis, raw_header=header_text)
    return render_template('index.html', analysis=None)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
