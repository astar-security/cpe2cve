# cpe2cve

Compute public vulnerabilities from a list of products in the CPE format.

This tool is dedicated to companies SecOp purpose.  
It is basically a 200 lines of python vulnerability scanner for low cost vulnerability management.  
It is free. Astar do not sell any product to avoid conflict of interest with our audit activity (the recommendation in our pentest report should not look like "you need a SIEM and you know what ? we actually sell a SIEM").

## requirement

```
pip install cpe
pip install pdfkit
apt install wkhtmltopdf
```

For the web based version, python flask is needed.

## usage

Get CVEs from a given CPE:
```
python3 cpe2cve.py --cpe cpe:/a:apache:tomcat:7.0.65
```

Get CVEs from a file with multiple CPEs (one per line):
```
python3 cpe2cve.py --file cpe.txt
```

Save the output in PDF format:
```
python3 cpe2cve.py --cpe cpe:/a:apache:tomcat:7.0.65 --output result.pdf
```

Save the output in CSV format:
```
python3 cpe2cve.py --cpe cpe:/a:apache:tomcat:7.0.65 --output result.csv
```
Actually if the ".pdf" extension is not recognized in the argument of the "--output", CSV is the default format.

The interface of the Web version is pretty straightforward :

![Screenshot from 2021-10-01 20-38-43](https://user-images.githubusercontent.com/42293505/135670681-3247b355-61b4-4c5b-b2cf-3c60e02cd9a5.png)


## Output

The PDF produced looks like this :

![Screenshot from 2021-10-01 20-37-02](https://user-images.githubusercontent.com/42293505/135670564-ebe4e938-c9a3-4a48-b2b3-0ab7575aa206.png)


## Note

* Vulners was used at the begining to perform this analysis. It permitted to know if an exploit is available for each CVE. But it had many false negative results compared to the NIST. So I archived the code in the old directory. But I lost the information about exploit availability
* This tool is a extract from a personnal set of automated scripts that I use for pentest purpose. You can find it here : [SubZero](https://github.com/astar-security/SubZero)
