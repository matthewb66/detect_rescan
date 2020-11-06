# detect_rescan.sh 
Bash script to wrapper Synopsys Detect for Black Duck scanning to reduce duplicate scan uploads between runs for use in frequent automated scan processes.

# INTRODUCTION

This script is provided under an OSS license (specified in the LICENSE file) to allow users to report and manage unconfirmed snippets within a Black Duck project version.

It does not represent any extension of licensed functionality of Synopsys software itself and is provided as-is, without warranty or liability.

# OVERVIEW

The script is intended to address issues caused by frequently calling the Black Duck Detect scanner within a CI/CD pipleine or automated build environment which can result in repeated scans being submitted and performance issues on the Black Duck server.

It is used as a wrapper for the standard Synopsys Detect bash script on Linux or MacOS, and does the following:

- Processes supplied Synpsys Detect options to determine if a post-action is required
- Downloads and runs Detect offline with supplied options to perform standard scan
- Identifies the BOM and Signature scan files from offline run
- Looks for previous scan record in .bdprevscan file in scanned project folder
- Compares scanned BOM files and uploads if different/new to previous scan
- Checks last date/time for signature scan and uploads if more than 24 hours or new scan
- If post-action required:
  - Waits for server-side scan and BOM completion
  - Runs Detect to perform post-action with no rescan

# PREREQUISITES

The script requires a bash shell to run.

The following additional programs must be installed in the environment and the script will check for them:

- cksum (usually installed on MacOS & Linux)
- curl
- jq

Please refer to your platform documentation to install these.

The script uses Synopsys Detect to perform scans, and has the same prerequisites including internet connectivity to download the script, connection to Black Duck server to upload scans, access to package managers for dependency analysis etc.

The script writes a file `.bdprevscan` to the top-level folder of the project to be scanned which needs to be retained between runs.
If the project location is not persistent that the script should be modified to write to a persistent location to ensure the file is saved.

# INSTALLATION

The script can be downloaded and executed dynamically using the following command:

    bash <(curl -s -L https://raw.github.com/matthewb66/detect_rescan/main/detect_rescan.sh) DETECT_OPTIONS

where DETECT_OPTIONS are the standard Synopsys Detect options.

Alternatively the script can be downloaded and saved locally using:

    curl -s -L https://raw.github.com/matthewb66/detect_rescan/main/detect_rescan.sh > detect_rescan.sh
    chmod +x detect_rescan.sh

# USAGE

The script provides 2 options in addition to the standard Synopsys Detect options as follows:

    --quiet - Use to hide Synopsys Detect standard output and other script notifications
    --report - Use to extract summary values after the scan completions including number of policy violations and counts of component vulnerability, license and operational risks identified.
    
The example output of the `--report` option is shown below:

    BLACK DUCK OSS SUMMARY REPORT

    Component Policy Status:
    - In Violation Overidden:	0
    - Not In Violation:		97
    - In Violation:			1

    Component Risk:
          			CRIT	HIGH	MED 	LOW 	None
    Vulnerabilities		0	0	0	0	98
    Licenses		-	0	63	0	35
    Op Risk			-	10	39	12	37

    See Black Duck Project at:
    https://myserver.blackduck.synopsys.com/api/projects/c6fb44b7-9325-4b76-9a42-af1b6dda456f/versions/9afa1046-4a23-4621-9a26-19ae95d4fa89/components

# INTEGRATIONS & SUPPORT

The `detect_rescan.sh` script should be used in place of Synopsys Detect at the same integration points where a direct call is made to the detect.sh script.

It is not suitable for use with CI/CD plugins and other integrations which do not use the detect.sh script or which call the Detect jar directly.

Currently the script operates under Linux/MacOS via bash, but does not function correctly using the Bash task in Azure DevOps on Windows.
