from cpe import CPE
import requests
import time
import pdfkit
import matplotlib.pyplot as plt
from flask import Flask, request, render_template, send_file

app = Flask(__name__)
API = "https://services.nvd.nist.gov/rest/json/cves/1.0"
EXPORT_CSV_FILENAME = "result.csv"
EXPORT_PDF_FILENAME = "result.pdf"
lastresult = None

"""
format:
    {'cpe:/a:apache:tomcat:7.0.27': {
        'friendlyname': 'Tomcat 7.0.27',  # A human way to describe the porduct
        'total':15,                       # number of CVE concerning this CPE
        'highest': 9.8,                   # highest CVSS score in all the CVEs
        'remotelyExploitable': True       # True if there is an available exploit for a network vector
        'cve': {
            'CVE-2021-25329': {
                'score': 4.4,                           # The CVSSv2 or CVSSv3 score
                'vector': 'AV:L/AC:M/Au:N/C:P/I:P/A:P'  # The full CVSS vector
                'exploit': False                        # True if exploits are available
                }
        }
    }
"""

def cpe2cve(cpe, api):
    # Check the format upside to understand how the data are stored in the vulns dict
    vulns = {}
    for c in cpe:
        if c.cpe_str not in vulns:
            vulns[c.cpe_str] = {"total":0, "cve":{}, "highest":0.0, "remotelyExploitable":False, "friendlyname": f"{c.get_product()[0]} {c.get_version()[0]}"}
            # call to the NIST APÏ
            req = requests.get(f"{api}?cpeMatchString={c.cpe_str}&resultsPerPage=100")
            if req.status_code != 200:
                vulns['error'] = f"Une erreur s'est produite avec {c.cpe_str}: {req.text}"
                return vulns
            # Sleep to avoid blacklist by the NIST servers
            time.sleep(0.5)
            vulns[c.cpe_str]['total'] = req.json().get('totalResults')
            try:
                cves = req.json()['result'].get('CVE_Items')
                if cves:
                    for cve in cves:
                        cveid = cve['cve']['CVE_data_meta']['ID']
                        vulns[c.cpe_str]["cve"][cveid] = {"score": 0, "vector": '', "exploit": "Unknown"}
                        # manage the case depending on the CVSS to be V2 or V3
                        metric = "3" if "baseMetricV3" in cve['impact'] else "2"
                        cvss = cve['impact'][f"baseMetricV{metric}"][f"cvssV{metric}"]
                        vulns[c.cpe_str]["cve"][cveid]["score"] = cvss['baseScore']
                        vulns[c.cpe_str]["cve"][cveid]["vector"] = cvss['vectorString']
                        # check if vuln is exploitable from network
                        if "AV:N" in cvss['vectorString']:
                            vulns[c.cpe_str]["remotelyExploitable"] = True
                        # Update the highest risk if necessary
                        vulns[c.cpe_str]['highest'] = max(vulns[c.cpe_str]['highest'], cvss['baseScore'])
            except Exception as e:
                vulns['error'] = f"Une erreur s'est produite avec {c.cpe_str}: {e}"
                return vulns
    return vulns


def getCriticality(cvss):
    """ color convention fot the cells of the PDF """
    if cvss == 0.0:
        return ("none", "#00ff00", (0, 255, 0))
    if cvss < 3.1:
        return ("low", "#ffff00", (255, 255, 0))
    if cvss < 6.1:
        return ("medium", "#ffc800", (255, 200, 0))
    if cvss < 9.1:
        return ("high", "#ff6400", (255, 100, 0))
    return ("critical", "#cc0000", (200, 0, 0))

def export2csv(vulns, output):
    lines = ["cpe,highestrisk,remotelyexploitable,vulnerabilities,cve,score,remote,exploit,vector"]
    for cpe,details in vulns.items():
        # counter for each vulnerability associated with a unique cpe
        cpt = 0
        # if there is no vuln, we put a line with a risk of 0.0 and 0 vuln
        if details["total"] == 0:
            lines.append(f"{cpe},0.0,False,0/0,,,,")
        for cve, detailscve in details["cve"].items():
            cpt += 1
            lines.append(f"{cpe},{details['highest']},{details['remotelyExploitable']},{cpt}/{details['total']},{cve},{detailscve['score']},{'AV:N' in detailscve['vector']},{detailscve['exploit']},{detailscve['vector']}")
    if output:
        with open(output, "w") as f:
            for l in lines:
                f.write(l + '\n')
            

def export2pdf(vulns, output):
    html = "<h1 style='font-size:40px;'>Vulnerability report</h1>"
    html += f"<p>Date: {time.ctime(time.time())}<br/></p>"
    html += f"<p style='background-color:#f8f8f8;padding:10px 10px;'><strong>{len(vulns)}</strong> products were <strong>submited</strong><br/>"
    vulnproduct = sum([vulns[i]['total']>0 for i in vulns])
    html += f"<strong>{vulnproduct}</strong> of them are <strong>vulnerable</strong><br/>"
    sumvuln = sum([vulns[i]['total'] for i in vulns])
    html += f"A total of <strong>{sumvuln}</strong> vulnerabilities were found</p>"
    html += "<h2>Status by product</h2>"
    html += "<table><thead><tr><th>Product</th><th>CPE</th><th>CVE</th><th>Risk</th><th>Remotely exploitable</th></tr></thead><tbody>"
    fig, ax = plt.subplots()
    values = []
    labels = []
    colors = []
    maxgraph = 0
    for cpe,details in sorted(vulns.items(), reverse=True, key=lambda k_v: k_v[1]['highest']):
        crit = getCriticality(details['highest'])
        html += f"<tr><td>{details['friendlyname']}</td><td>{cpe}</td><td>{details['total']}</td><td style='background-color:{crit[1]};'>{details['highest']}</td><td>{details['remotelyExploitable']}</td></tr>"
        if sumvuln and details['total']/sumvuln > 0.02 and maxgraph < 11:
            maxgraph += 1
            values.append(details['total'])
            labels.append(details['friendlyname'])
            colors.append(crit[1])
    html += "</tbody></table>"
    ax.pie(values, labels=labels, colors=colors, autopct='%1i%%', wedgeprops={"edgecolor":"white",'linewidth': 1, 'linestyle': 'solid', 'antialiased': True} )
    plt.tight_layout()
    plt.savefig("/tmp/products.png", bbox_inches='tight', transparent=False)
    if sumvuln:
        html += "<h2>Main vulnerabilities distribution</h2>"
        html += f"<p><img src ='/tmp/products.png' width='65%' style='display:block;margin-left:auto;margin-right:auto;'/></p>"
    html += "<h2>Vulnerabilities details</h2>"
    html += "<table><thead><tr><th>CVE</th><th>Score</th><th>Remotely exploitable</th><th>Target</th><th>Vector</th></tr></thead><tbody>"
    for cpe, details in vulns.items():
        for cve, detailscve in details["cve"].items():
            crit = getCriticality(detailscve['score'])
            html += f"<tr><td>{cve}</td><td style='background-color:{crit[1]};'>{detailscve['score']}</td><td>{'AV:N' in detailscve['vector']}</td><td>{cpe}</td><td>{detailscve['vector']}</td></tr>"
    html += "</tbody></table>"
    pdfkit.from_string(html, output, css="static/css/github.css", options={"enable-local-file-access": ""})

def export(vulns, choice):
    global EXPORT_CSV_FILENAME
    global EXPORT_PDF_FILENAME
    if choice == 'csv':
        export2csv(vulns, EXPORT_CSV_FILENAME)
        return EXPORT_CSV_FILENAME
    if choice == 'pdf':
        export2pdf(vulns, EXPORT_PDF_FILENAME)
        return EXPORT_PDF_FILENAME


@app.route("/", methods=['POST', 'GET'])
def getcpe():
    global API
    if request.method == 'GET':
        lastresult = None
        return render_template('index.html')
    if request.method == 'POST':
        cots = request.form.get('cots')
        choice = request.form.get('choice')
        cpe =[]
        try:
            cots = cots.lower().split('\n')
            for c in cots:
                cpe.append(CPE(c.strip('\n\r')))
        except Exception as e:
            error = f"la ligne {cots.index(c)+1} est invalide"
            return render_template('index.html', cots=request.form.get('cots'), message=error)
        if len(cpe) == 0:
            error = "Aucun CPE valide soumis"
            return render_template('index.html', cots=request.form.get('cots'), message=error)
        vulns = cpe2cve(cpe, API)
        if 'error' in vulns:
            return render_template('index.html', cots=request.form.get('cots'), message=vulns['error'])
        filename = export(vulns, choice)
        return send_file(filename)


if __name__ == '__main__':
  app.run(host='0.0.0.0')
