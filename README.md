# Certificate Authority Audit Tool
Simple tool to check issuing certificate authority for a list of origin servers

## TL;DR
`./cert_audit.py -r target.roots`

## Why?
Someone asked me if people are accessing sites that have an cert signed by one of the Entrust authorities that Google Chrome is about to [stop trusting](https://security.googleblog.com/2024/06/sustaining-digital-certificate-security.html)

## How?
Run the script (./cert_audit.py). If you include `input.csv` in the directory you are running the script from you don't need to specify any command line options. It will produce an `output.csv` file in the same directory.

The default expectation is `input.csv` is a log file from a proxy (or similar service), or a syslog type service (e.g. splunk), that includes the headings `hostname` and `protocol` (headings are case sensitive). The default options will only evaluate servers where the `protocol` value is either `HTTPS` or `SSL` (case sensitive). The `hostname` field should be the FQDN of the destination WITHOUT any leading protocol information (i.e. http:// or https://) and WITHOUT any trailing path details (e.g. /index.html, /contact, /anyPath).

## I Don't Like Defaults
Here are the command line options:

#### --timeout TIMEOUT, -t TIMEOUT 
Set timeout in seconds for connection to origin servers
#### --input_file INPUT_FILE, -i INPUT_FILE
CSV formatted log data used as input
#### --output_file OUTPUT_FILE, -o OUTPUT_FILE
CSV formatted audit results to be output
#### --text_input TEXT_INPUT, -x TEXT_INPUT
Alternate input file formatted as a flat text file with fqdns only
#### --error_log ERROR_LOG, -e ERROR_LOG
Error log file
#### --target_roots TARGET_ROOTS, -r TARGET_ROOTS
Explicit root servers of interest
#### --target_file TARGET_FILE, -f TARGET_FILE
Output of servers that match with targeted roots

## Wait, What is the Formatting of Input Files?
If you are taking a log file in csv format you just need to make sure it has both `hostname` and `protocol` formatted specifically as previously described. Look at `input.csv.example` as a reference. You could run a test against this file using the following cli syntax `./cert_audit.py -i input.csv.example`

If you have already pre-parsed your logs and extracted the hostnames of interest then take a look at `input.txt.example` to verify your formatting. You could run a test against this file using the following cli syntax `./cert_audit.py -x input.txt.example`

## Didn't you say something about Entrust and Google Chrome
Yes. Thats why I've included the list of certificate authorities that are in question called `target.roots`. Ive also included an option to specifically evaluate against this list or your own list of interesting roots. Refer to command line options.