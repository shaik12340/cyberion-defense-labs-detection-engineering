from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(title="Cyberion Defense Labs Dashboard")

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return """
<!DOCTYPE html>
<html>
<head>
    <title>Cyberion Defense Labs</title>
    <style>
        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: #0b1220;
            color: white;
        }

        header {
            padding: 25px 40px;
            background: #111827;
            border-bottom: 1px solid #263244;
        }

        header h1 { margin: 0; }
        header p { color: #9ca3af; }

        .container {
            padding: 30px 40px;
        }

        .cards {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
        }

        .card, .section {
            background: #111827;
            border: 1px solid #263244;
            border-radius: 12px;
        }

        .card {
            padding: 25px;
        }

        .label {
            color: #9ca3af;
        }

        .number {
            font-size: 36px;
            font-weight: bold;
            margin-top: 10px;
        }

        .section {
            margin-top: 30px;
            padding: 25px;
        }

        .bar {
            height: 25px;
            background: #263244;
            border-radius: 20px;
            overflow: hidden;
        }

        .fill {
            width: 67%;
            height: 100%;
            background: #22c55e;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th, td {
            padding: 14px;
            text-align: left;
            border-bottom: 1px solid #263244;
        }

        .high { color: #f87171; }
        .medium { color: #fbbf24; }
        .low { color: #60a5fa; }
    </style>
</head>

<body>

<header>
    <h1>🛡️ Cyberion Defense Labs</h1>
    <p>Detection Engineering & Threat Hunting — DEMO Dashboard</p>
</header>

<div class="container">

    <div class="cards">

        <div class="card">
            <div class="label">Sigma Rules</div>
            <div class="number">21</div>
        </div>

        <div class="card">
            <div class="label">ATT&CK Techniques</div>
            <div class="number">16</div>
        </div>

        <div class="card">
            <div class="label">Threat Hunts</div>
            <div class="number">2</div>
        </div>

        <div class="card">
            <div class="label">Incident Cases</div>
            <div class="number">2</div>
        </div>

    </div>

    <div class="section">
        <h2>MITRE ATT&CK Coverage</h2>
        <p>16 of 24 assessed techniques covered</p>

        <div class="bar">
            <div class="fill"></div>
        </div>
    </div>

    <div class="section">
        <h2>Detection Severity</h2>
        <p>🔴 High: 6</p>
        <p>🟡 Medium: 9</p>
        <p>🔵 Low: 4</p>
        <p>⚪ Informational: 2</p>
    </div>

    <div class="section">
        <h2>Recent Detections</h2>

        <table>
            <tr>
                <th>Detection</th>
                <th>MITRE ATT&CK</th>
                <th>Severity</th>
            </tr>

            <tr>
                <td>LSASS Memory Access</td>
                <td>T1003.001</td>
                <td class="high">High</td>
            </tr>

            <tr>
                <td>PowerShell Obfuscation</td>
                <td>T1059.001</td>
                <td class="high">High</td>
            </tr>

            <tr>
                <td>Process Injection</td>
                <td>T1055</td>
                <td class="high">High</td>
            </tr>

            <tr>
                <td>RDP Remote Connection</td>
                <td>T1021.001</td>
                <td class="medium">Medium</td>
            </tr>

            <tr>
                <td>Account Discovery</td>
                <td>T1087</td>
                <td class="low">Low</td>
            </tr>
        </table>
    </div>

</div>

</body>
</html>
"""

@app.get("/health")
def health():
    return {"status": "ok"}
