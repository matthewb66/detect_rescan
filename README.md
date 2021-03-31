# detect_rescan.sh - v1.16
Bash script to wrapper Synopsys Detect for Black Duck scanning to reduce duplicate scan uploads between runs for use in frequent automated scan processes and optionally produce immediate project security summary reports.

# INTRODUCTION

This script is provided under an OSS license (specified in the LICENSE file) to allow users to report and manage unconfirmed snippets within a Black Duck project version.

It does not represent any extension of licensed functionality of Synopsys software itself and is provided as-is, without warranty or liability.

# OVERVIEW

The script is intended to address issues caused by frequently calling the Black Duck Detect scanner within a CI/CD pipleine or automated build environment which can result in repeated scans being submitted and performance issues on the Black Duck server. It can also produce console and other optional outputs of project status after analysis.

It is used as a wrapper for the standard Synopsys Detect bash script on Linux or MacOS, and does the following:

- Processes supplied Synpsys Detect options to determine if a post-action is required (also looks at environment variables and options in a .yml if specified)
- Downloads and runs Detect (detect.sh) offline with supplied options to perform a scan
- Identifies the BOM and Signature scan files from offline run (note the script should only be used for projects where 1 signature scan has been mapped)
- Looks for previous scan data (see below for location of this data) 
- Compares scanned BOM files and upload files if different/new to previous scan
- Checks last date/time for signature scan and uploads if more than specified period (24 hours by default) or new scan
- If post-action or report required:
  - Waits for server-side scan and BOM completion
  - Runs Detect to perform post-action with no rescan
- If `--report` or `--markdown` specified, produce summary reports (--markdown writes the file blackduck.md in MD format)
- If `--testxml` specified, produce junit XML test output files (policies.xml and vulns.xml)

# PREREQUISITES

* The script requires a bash shell to run.

* The following additional programs must be installed in the environment and the script will check for them:
    - cksum (usually installed on MacOS & Linux)
    - curl
  Please refer to your platform documentation to install these. The program jq is also required but will be downloaded dynamically if not available.

* The script uses a custom field (`prevScanData` of type `Text Area`) in Project Versions by default to store previous scan data. The API key used for scanning will require the `Bom Manager` permission within the projects to be scanned (or be the project creator) to read and update this custom field.

* Alternatively, if the `--file` option is specified, the script will write the file `.bdprevscan` to the top-level folder of the project to be scanned which needs to be retained between runs. If the project location is not persistent, then the .bdprevscan file should be copied to a permanent location (and copied back before subsequent runs) or the script could be modified to write to a persistent location to ensure the file is saved between runs.

* The script uses Synopsys Detect to perform scans, and has the same prerequisites including internet connectivity to download the script, connection to Black Duck server to upload scans, access to package managers for dependency analysis etc. 

* Detect_rescan should not be used for projects where more than 1 signature scan has been mapped.

* Detect_rescan does not support Snippet or Binary scan types (Dependency and Signature scans are supported).

# CUSTOM FIELD CREATION

The default script operation is to store scan data in a custom field within Project Versions (unless the `--file` option is specified which will cause the scan data to be stored in the `.bdprevscan` file in the project folder).

You will need to administer the server to create a new custom field within Project Version with the name `prevScanData` and type `TextArea`.

As an administrator, perform the following in the Black Duck Web UI:
1. Select the `Manage --> Custom Fields` option
1. Select the `Project Version` table
1. Select `Create`
1. Choose type `Text Area`
1. Enter the name `prevScanData` and click Save

Ensure the custom field is enabled before continuing.

# INSTALLATION/USAGE

The script can be downloaded and executed dynamically using the following command:

    bash <(curl -s -L https://raw.github.com/matthewb66/detect_rescan/main/detect_rescan.sh) ARGUMENTS DETECT_OPTIONS

where DETECT_OPTIONS are the standard Synopsys Detect options and ARGUMENTS are the additional detect_rescan arguments (see below).

Alternatively the script can be downloaded and saved locally using:

    curl -s -L https://raw.github.com/matthewb66/detect_rescan/main/detect_rescan.sh > detect_rescan.sh
    chmod +x detect_rescan.sh
    ./detect_rescan.sh ARGUMENTS DETECT_OPTIONS 

The Black Duck server URL and API token are required and can be specified either as environment variables (`BLACKDUCK_URL` and `BLACKDUCK_API_TOKEN`), in a project application-project.yml file (specified using `--spring.profiles.active`) or as command line arguments (`--blackduck.url` and `--blackduck.api.token`).

# ARGUMENTS

The script provides some options in addition to the standard Synopsys Detect arguments as follows:

    --quiet         - Hide Synopsys Detect standard output and other non-essential script notifications.
    --report        - Use to extract summary values after the scan completions including number of policy violations and counts of component vulnerability, license and operational risks identified.
    --markdown      - Write a project summary report to the blackduck.md file created in the project folder.
    --reset         - Force a scan irrespective of the previous scan data/time and then update the scan data.
    --testxml       - Produce output policies.xml and vulns.xml files containing test results in Junit format.
    --curlopts      - Add specified option to curl command (usually -k for insecure connections with self-signed certificate). The env var CURLOPTS can also be set to specify curl command options.
    --detectscript=mydetect.sh
                    - Use a local specified copy of the detect.sh script as opposed to downloading dynamically from https://detect.synopsys.com/detect.sh.
    --sigtime=XXXX  - Specify the time (in seconds) used to determine whether a Signature scan should be uploaded (default 86400 = 24 hours).

# REPORT OUTPUT

The example output of the `--report` option is shown below:

    ----------------------------------------------------------------------
    BLACK DUCK OSS SUMMARY REPORT
    Project: 'TP_test4' Version: 'AssemblyInfo.Version'

    Component Policy Status:
      - Not In Violation:	230
      - In Violation:		5
      - In Violation Overidden:	0

    Components in Violation:
		Component: 'AsyncIO/0.1.26' - Policies Violated: 'MPL2' (MAJOR) 
		Component: 'JetBrains dotMemoryUnit 2.3/null' - Policies Violated: 'License Unknown' (CRITICAL) 
		Component: 'Mono.Security/5.4.0.201' - Policies Violated: 'License Unknown' (CRITICAL) 
		Component: 'nrfxlib-sys/1.2.0' - Policies Violated: 'License Unknown' (CRITICAL) 
		Component: 'Strong Namer - Automatically Add Strong Names to References/0.2.5' - Policies Violated: 'License Unknown' (CRITICAL) 

    Component Risk:		CRIT	HIGH	MED 	LOW 	None
				----	----	--- 	--- 	----
	Vulnerabilities		0     	0	3	0	232
	Licenses		-	4	79	0	152
	Op Risk			-	27	91	42	75

    See Black Duck Project at:
    https://xxxx.blackduck.synopsys.com/api/projects/ec40e9fb-b792-495-a052-683409749a02/versions/bb370377-a5e-4da4-9239-d01fe5717f6a/components

    ----------------------------------------------------------------------

# DEBUG MODE

Set the environment variable `DEBUG` to any non-blank value to cause the script to output extra debug messages. Note this will also cause the Detect program to output additional information.

# INTEGRATIONS & SUPPORT

The `detect_rescan.sh` script should be used in place of Synopsys Detect at the same integration points where a direct call is made to the detect.sh script.

It is not suitable for use with Synopsys Detect CI/CD plugins and other integrations which do not call the detect.sh (bash) script or which call the Detect jar directly.

The script operates under Linux/MacOS via bash, but can also be used under the Bash task in Azure DevOps on Windows. The script may also operate under the Windows Linux subsystem although this has not been tested.

# AZURE DEVOPS EXAMPLE INTEGRATION

The following sample yml task shows how the detect_rescan.sh script can be used as a Bash step within an ADO pipeline. This would replace any other integration to call Synopsys Detect including the ADO plugin or direct call to detect.sh. This step can be used on either Linux, MacOS or Windows targets.

	- task: Bash@3
	  inputs:
	    targetType: 'inline'
	    script: |
	      bash <(curl -s -L https://raw.github.com/matthewb66/detect_rescan/main/detect_rescan.sh) --blackduck.api.token=MmEwZTdkNjAtNjU5MS00MWEwLThjZTgtZGI2MTFiNDA2ZDkxOjRhYzc2YTcyLTdiNjMtNGQxZC05ZTNhLTY0NDM0EwZjhjZg== --blackduck.trust.cert=true --blackduck.url=https://serverXX.blackduck.synopsys.com --detect.project.name=MYproject --detect.project.version.name=1.0  --detect.policy.check.fail.on.severities=ALL --quiet --report --testxml

For Windows targets, the Windows Bash is not 100% compliant and the following modified yml may be required:

	- task: Bash@3
	  inputs:
	    targetType: 'inline'
	    script: |
	      curl -s -L https://raw.github.com/matthewb66/detect_rescan/main/detect_rescan.sh > detect_rescan.sh
	      ./detect_rescan.sh --blackduck.api.token=MmEwZTdkNjAtNjU5MS00MWEwLThjZTgtZGI2MTFiNDA2ZDkxOjRhYYTcyLTdiNjMtNGQxZC05ZTNhLTY0NDM0MjEwZjhjZg== --blackduck.trust.cert=true --blackduck.url=https://server.blackduck.synopsys.com --detect.detector.search.depth=1 --detect.project.name=Myproject --detect.project.version.name=1.0 --detect.policy.check.fail.on.severities=ALL --quiet --report --testxml

# TESTXML OUTPUT

The `--testxml` option will cause detect_rescan.sh to generate output files `policies.xml` and `vulns.xml` which includes scan results in Junit format.
The `policies.xml` test data represents the OSS components identified in the Black Duck scan, with components which have 1 or more policy violation being marked as a failed test. Components without policy violation are shown as passed tests.
The `vulns.xml` test data represents the outstanding vulnerabilities from the Black Duck project (remediated/ignored vulnerabilities) with open vulnerabilities being marked as a failed test.

The json file can be imported as test results using the CI features for Junit test analysis.

For example, in Azure DevOps, the following yml fragment can be used to import the policies.xml (or vulns.xml) file:

	- task: PublishTestResults@2
	  displayName: 'Publish Test Results **/policies.xml'
	  inputs:
	    testResultsFiles: '**/policies.xml'
