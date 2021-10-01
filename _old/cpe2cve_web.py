from cpe import CPE
import vulners
from flask import Flask, flash, request, render_template, send_file

app = Flask(__name__)
app.secret_key = b'heroarhgorzhgporzhgpoerzaghroghroezghrozohourzhozihfpizfiif'

def cpe2cve(cpe, vulners_api, mode):
    vulns = {}
    if mode not in ('cpe', 'name'):
        return {'error':'invalid choice'}
    for c in cpe:
        soft = c.cpe_str if mode == 'cpe' else ' '.join(c)
        vulns[soft] = {"total":0, "cve":{}, "highest":0.0, "remotelyExploitable":False}
        try:
            if mode == 'cpe':
                res = vulners_api.cpeVulnerabilities(c.cpe_str)
            else:
                name, version = c
                res = vulners_api.softwareVulnerabilities(name, version)
        except Exception as e:
            print(f"Error with {c}: {e}")
            return{'error':"Les demandes vers vulners ont échoué (la license est peut être cramée)"}
        cves = res.get('NVD')
        if cves:
            vulns[soft]["total"] = len(cves)
            for cve in cves:
                vulns[soft]["cve"][cve['id']] = {"score": cve['cvss']['score'],
                                                      "vector": cve['cvss']['vector'], 
                                                      "exploit": "Unknown"}
                vulns[soft]['highest'] = max(vulns[soft]['highest'], cve['cvss']['score'])
    return vulns

def cve2exploit(vulns, vulners_api):
    for cpe in vulns:
        for cve,details in vulns[cpe]['cve'].items():
            try:
                exp = 'exploit' in [i['bulletinFamily'] for i in vulners_api.searchExploit(cve)]
            except Exception as e:
                return{'error':"Les demandes vers vulners ont échoué (la license est peut être cramée)"}
            vulns[cpe]['cve'][cve]['exploit'] = exp
            remotely = 'AV:N' in details['vector']
            vulns[cpe]['remotelyExploitable'] |= exp and remotely
    return vulns


def export(vulns, output=None):
    lines = ["cpe,vulnerabilities,cve,score,remote,exploit,vector"]
    for cpe,details in vulns.items():
        cpt = 0
        if details["total"] == 0:
            lines.append(f"{cpe},0/0,,,,")
        for cve,detailscve in details["cve"].items():
            cpt += 1
            lines.append(f"{cpe},{cpt}/{details['total']},{cve},{detailscve['score']},{'AV:N' in detailscve['vector']},{detailscve['exploit']},{detailscve['vector']}")
    if output:
        with open(output, "w") as f:
            for l in lines:
                f.write(l+'\n')
    return lines

def commonName(cots):
    part = cots.split()
    name = ' '.join(part[0:-1])
    version = part[-1]
    return (name, version)

def checkAPI(key):
    if key is None or len(key) != 64:
        return False
    if not key.isalnum():
        return False
    return True

@app.route("/", methods=['POST', 'GET'])
def getcpe():
    if request.method == 'GET':
        return render_template('index.html')
    if request.method == 'POST':
        if request.form.get('result'):
            return send_file("resultats.csv")
        APIKey = request.form.get('api')
        if not checkAPI(APIKey):
            flash("Mauvais format de clé API, voir vulners.com")
            return render_template('index.html', api=APIKey, cots=request.form.get('cots'))
        APIKey = APIKey.upper()
        choice = request.form.get('choice')
        cpe =[]
        try:
            cots = set(request.form.get('cots').lower().split('\n'))
            for c in cots:
                soft = CPE(c.strip('\n\r')) if choice == 'cpe' else commonName(c)
                cpe.append(soft)
        except Exception as e:
            pass
        if len(cpe) ==0:
            flash("Aucun logiciel au bon format n'a été reconnu")
            return render_template('index.html', api=APIKey, cots=request.form.get('cots'))
        try:
            vulners_api = vulners.Vulners(api_key=APIKey)
        except Exception as e:
            flash("La connexion au service vulners n'a pas fonctionné")
            return render_template('index.html', api=APIKey, cots=request.form.get('cots'))
        vulns = cpe2cve(cpe, vulners_api, choice)
        if 'error' in vulns:
            flash(vulns['error'])
            return render_template('index.html', api=APIKey, cots=request.form.get('cots'))
        vulns = cve2exploit(vulns, vulners_api)
        res = export(vulns, "resultats.csv")
        #return send_file("resultats.csv")
        return render_template('index.html', api=APIKey, cots=request.form.get('cots'), result=res)


if __name__ == '__main__':
  app.run(host='0.0.0.0')
