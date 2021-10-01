#!/usr/bin/python3

from cpe import CPE
import vulners
import argparse


APIKey = "DCOSR0ZU76SOUL3847B869N843SBCWHHJF2WTK4EO2FYFHDQ4RCG898CND5FZ4DL"

"""
format:
    {'cpe:/a:apache:tomcat:7.0.27': {
        'total':15,                   # number of CVE concerning this CPE
        'highest': 9.8,               # highest CVSS score in all the CVEs
        'remotelyExploitable': True   # True if there is an available exploit for a network vulnerability
        'cve': {
            'CVE-2021-25329': {
                'score': 4.4,                           # The CVSSv2 score
                'vector': 'AV:L/AC:M/Au:N/C:P/I:P/A:P'  # The full CVSSv2 vector
                'exploit': False                        # True if exploits are available
                }
        }
    }
"""

def cpe2cve(cpe, vulners_api):
    vulns = {}
    for c in cpe:
        vulns[c.cpe_str] = {"total":0, "cve":{}, "highest":0.0, "remotelyExploitable":False}
        try:
            res = vulners_api.cpeVulnerabilities(c.cpe_str)
        except Exception as e:
            print(f"[!] An error occured: maybe the license is burned")
            exit(1)
        cves = res.get('NVD')
        if cves:
            vulns[c.cpe_str]["total"] = len(cves)
            for cve in cves:
                vulns[c.cpe_str]["cve"][cve['id']] = {"score": cve['cvss']['score'],
                                                      "vector": cve['cvss']['vector'], 
                                                      "exploit": "Unknown"}
                vulns[c.cpe_str]['highest'] = max(vulns[c.cpe_str]['highest'], cve['cvss']['score'])
    return vulns

def cve2exploit(vulns, vulners_api):
    for cpe in vulns:
        for cve,details in vulns[cpe]['cve'].items():
            try:
                exp = 'exploit' in [i['bulletinFamily'] for i in vulners_api.searchExploit(cve)]
            except Exception as e:
                print(f"[!] An error occured: maybe the license is burned")
                exit(1)
            details['exploit'] = exp
            remotely = 'AV:N' in details['vector']
            vulns[cpe]['remotelyExploitable'] |= exp and remotely
    return vulns

def export(vulns, output):
    header = "cpe,vulnerabilities,cve,score,remote,exploit,vector"
    lines = []
    for cpe,details in vulns.items():
        cpt = 0
        if details["total"] == 0:
            lines.append(f"{cpe},0/0,,,,")
        for cve,detailscve in details["cve"].items():
            cpt += 1
            lines.append(f"{cpe},{cpt}/{details['total']},{cve},{detailscve['score']},{'AV:N' in detailscve['vector']},{detailscve['exploit']},{detailscve['vector']}")
    if output:
        with open(output, "w") as f:
            f.write(header + '\n')
            for l in lines:
                f.write(l + '\n')
    else:
        print('-'*20)
        print(header)
        print(*(lines), sep='\n')
        print('-'*20)

def main():
    global APIKey
    
    parser = argparse.ArgumentParser(description='Giving the CVEs that affect a given CPE', add_help=True)
    parser.add_argument('--cpe', '-c', action="store", default=None,
            help="Give one CPE string to the tool")
    parser.add_argument('--file', '-f', action="store", default=None,
            help="Import multiple CPE from a file (one per line)")
    parser.add_argument('--output', '-o', action="store", default=None, 
            help="Write results in an output file. The format is CSV")
    parser.add_argument('--noexploit', action="store_true", default=False, 
            help="Do not perform exploit verification (save many requests)")
    args = parser.parse_args()

    cpe = []
    print("[*] Check if CPE is well formed ...")
    try:
        if args.cpe:
            cpe.append(CPE(args.cpe))
        elif args.file:
            with open(args.file) as f:
                for line in f.readlines():
                    #remove space and newlines char from each line
                    l = line.lower().strip('\n\r')
                    cpe.append(CPE(l))
        else:
            print("[!] indicate at least a CPE (--cpe) or an input file with one CPE per line (--file)")
            exit(1)
    except Exception as e:
        print(f"[!] Bad CPE format: {e}")
        exit(1)
    print("[+] Valid CPE")
    print("[*] Connection to vulners API...")
    try:
        vulners_api = vulners.Vulners(api_key=APIKey)
    except Exception as e:
        print(f"[!] Problem during connection to vulners: {e}")
        exit(1)
    print("[+] Connection sucessful")
    print(f"[*] Searching vulnerabilities for the {len(cpe)} CPE given")
    vulns = cpe2cve(cpe, vulners_api)
    print("[+] Vulnerabilities computed")
    print("[*] Searching for available exploits (can take some time)")
    if not args.noexploit:
        vulns = cve2exploit(vulns, vulners_api)
    print(f"[*] Export to {args.output if args.output else 'stdout'}")
    export(vulns, args.output)
    print("[+] Export completed !")

if __name__ == '__main__':
    main()
