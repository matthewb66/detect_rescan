#!/bin/bash

# Script to wrapper detect.sh to only upload changed bom files
#
# Description:
# 1. Processes supplied Synpsys Detect options to determine if a post-action is required
# 2. Downloads and runs Detect (detect.sh) offline with supplied options to perform a scan
# 3. Identifies the BOM and Signature scan files from offline run (note the script should only be used for projects where 1 signature scan has been mapped)
# 4. Looks for previous scan data (see below for location of this data)
# 5. Compares scanned BOM files and upload files if different/new to previous scan
# 6. Checks last date/time for signature scan and uploads if more than specified period (24 hours by default) or new scan
# 7. If post-action or report required:
#       - Waits for server-side scan and BOM completion
#       - Runs Detect to perform post-action with no rescan
# 8. If --report or --markdown specified, produce summary reports (--markdown writes the file blackduck.md in MD format)
# 
# Arguments:
#  --quiet         - Hide Synopsys Detect standard output and other non-essential script notifications.
#  --report        - Use to extract summary values after the scan completions including number of policy violations and counts of component vulnerability, license and operational risks identified.
#  --markdown      - Write a project summary report to the blackduck.md file created in the project folder.
#  --reset         - Force a scan irrespective of the previous scan data/time and then update the scan data.
#  --testxml       - Produce output vulns.xml and policies.xml files containing test results in Junit format.
#  --curlopts      - Add an option to curl (usually -k) to support insecure connections to a BD server without authorised certificate (alternatively set CURLOPTS env var)
#  --detectscript=mydetect.sh
#                  - Use a local specified copy of the detect.sh script as opposed to downloading dynamically from https://detect.synopsys.com/detect.sh.
#  --sigtime=XXXX  - Specify the time (in seconds) used to determine whether a Signature scan should be uploaded (default 86400 = 24 hours).#   Same as detect.sh
#

output() {
    echo "detect_rescan: $*"
}
 
output "Starting Detect Rescan wrapper v1.13d"

DETECT_TMP=$(mktemp -u)
TEMPFILE=$(mktemp -u)
TEMPFILE2=$(mktemp -u)
LOGFILE=$(mktemp -u)

# ACTION_ARGS=--blackduck.timeout=*|--detect.force.success=*|--detect.notices.report=*|--detect.policy.check.fail.on.severities=*|--detect.risk.report.pdf=*|--detect.wait.for.results=*
# UNSUPPORTED_ARGS='--detect.blackduck.signature.scanner.snippet.matching=*|--detect.blackduck.signature.scanner.upload.source.mode=*|--detect.blackduck.signature.scanner.copyright.search=*|--detect.blackduck.signature.scanner.license.search=*|--detect.binary.scan.*'

API_TOKEN=$BLACKDUCK_API_TOKEN
BD_URL=$BLACKDUCK_URL
YML=
DETARGS=
SCANLOC=.
RUNDIR=
PROJECT=
VERSION=
SIGFOLDER=
DETECT_ACTION=0
DETECT_PROJECT=0
DETECT_VERSION=0
MODE_QUIET=0
MODE_REPORT=0
MODE_MARKDOWN=0
MODE_PREVFILE=0
MODE_TESTXML=0
SIGTIME=86400
PREVSCANDATA=
PROJEXISTS=0
DETECT_SCRIPT=
MODE_RESET=0
JQTEMPDIR=
JQ=

UNSUPPORTED=0

BOM_FILES=()
BOM_HASHES=()
PREV_FILES=()
PREV_HASHES=()
UNMATCHED_BOMS=()

error() {
    echo "detect_rescan: ERROR: $*" >$LOGFILE
    cat $LOGFILE
    end 1
}

error2() {
    echo "detect_rescan: ERROR: $*" >$LOGFILE
    cat $LOGFILE
    end 2
}

end() {
    rm -f $TEMPFILE $TEMPFILE2 $DETECT_TMP $LOGFILE
    if [ ! -z "$JQTEMPDIR" ]
    then
        rm -f $JQTEMPDIR/jq
        rmdir $JQTEMPDIR
    fi
    exit $1
}

debug() {
    if [ ! -z "$DEBUG" ]
    then
        echo "detect_rescan: DEBUG - $*" >&2
    fi
}

msg() {
    if [ $MODE_QUIET -eq 0 ]
    then
        output "$*"
    fi
}

encode_url() {
    if [ ! -z "$1" ]
    then
        echo ${*} | sed -e 's:/:%2F:g' -e 's/ /%20/g' -e 's/\[/%5B/g' -e 's/\]/%5D/g' -e 's/{/%7B/g' -e 's/}/%7D/g' -e 's/(/%28/g' -e 's/)/%29/g' -e 's/"//g'
    else
        cat - | sed -e 's:/:%2F:g' -e 's/ /%20/g' -e 's/\[/%5B/g' -e 's/\]/%5D/g' -e 's/{/%7B/g' -e 's/}/%7D/g' -e 's/(/%28/g' -e 's/)/%29/g' -e 's/\"//g'
    fi
}

escape_string() {
    if [ ! -z "$1" ]
    then
        echo ${*} | sed -e 's/ /\\ /g' -e 's/"//g'
    else
        cat - | sed -e 's/ /\\ /g' -e 's/"//g'
    fi
}

install_jq() {
    JQPATH=$(mktemp -d)
    PLATFORM=$(uname -a 2>/dev/null| cut -f1 -d' ')
    debug "install_jq(): PLATFORM = $PLATFORM"
    if [ "$PLATFORM" == "Linux" ]
    then
        JQURL=https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64
    elif [ "$PLATFORM" == "Darwin" ]
    then
        JQURL=https://github.com/stedolan/jq/releases/download/jq-1.6/jq-osx-amd64
    else
        return 1
    fi
    curl -s -L $JQURL -o $JQPATH/jq >/dev/null 2>&1
    if [ $? -ne 0 ] || [ ! -r $JQPATH/jq ]
    then
        return 1
    fi
    chmod +x $JQPATH/jq
    echo $JQPATH/jq
    debug "install_jq(): jq downloaded from $JQURL and installed to $JQPATH/jq"
    JQTEMPDIR=$JQPATH
    return 0
}

prereqs() {
    local ret=0
    hash jq  >/dev/null 2>&1
    if [ $? -ne 0 ]
    then
        JQ=$(install_jq)
        if [ $? -ne 0 ]
        then
            output "ERROR: jq not available and unable to install"
            ret=1
        fi
    else
        JQ=jq
    fi
    debug "prereqs(): JQ set to $JQ"
    for prog in cksum curl java
    do
        hash $prog >/dev/null 2>&1
        if [ $? -ne 0 ]
        then
            output "ERROR: $prog program required"
            ret=1
        fi
    done
    debug "prereqs(): Returning $ret"
    return $ret
}

check_env() {
    #
    # Check Environment variables
    if [ "$DETECT_BLACKDUCK_SIGNATURE_SCANNER_SNIPPET_MATCHING" == "true" ]
    then
        debug "process_args(): UNSUPPORTED OPTION detect.blackduck.signature.scanner.snippet.matching option identified from environment variable"
        UNSUPPORTED=1
    fi
    if [ "$DETECT_BLACKDUCK_SIGNATURE_SCANNER_UPLOAD_SOURCE_MODE" == "true" ]
    then
        debug "process_args(): UNSUPPORTED OPTION detect.blackduck.signature.scanner.upload.source.mode option identified from environment variable"
        UNSUPPORTED=1
    fi
    if [ "$DETECT_BLACKDUCK_SIGNATURE_SCANNER_COPYRIGHT_SEARCH" == "true" ]
    then
        debug "process_args(): UNSUPPORTED OPTION detect.blackduck.signature.scanner.copyright.search option identified from environment variable"
        UNSUPPORTED=1
    fi
    if [ "$DETECT_BLACKDUCK_SIGNATURE_SCANNER_LICENSE_SEARCH" == "true" ]
    then
        debug "process_args(): UNSUPPORTED OPTION detect.blackduck.signature.scanner.license.search option identified from environment variable"
        UNSUPPORTED=1
    fi
    if [ ! -z "$DETECT_BINARY_SCAN_FILE_PATH" ]
    then
        debug "process_args(): UNSUPPORTED OPTION detect.binary.scan.file.path identified from environment variable"
        UNSUPPORTED=1
    fi
    if [ ! -z "$DETECT_BINARY_SCAN_FILE_NAME_PATTERNS" ]
    then
        debug "process_args(): UNSUPPORTED OPTION detect.binary.scan.file.name.patterns identified from environment variable"
        UNSUPPORTED=1
    fi
    if [ ! -z "$DETECT_SOURCE_PATH" ] && [ -d "$DETECT_SOURCE_PATH" ]
    then
        debug "process_args(): detect.source.path '$DETECT_SOURCE_PATH' identified from environment variable"
        SCANLOC=$(cd "$DETECT_SOURCE_PATH"; pwd)
    fi

    #
    # Check YML properties file
    if [ ! -z "$YML" ]
    then
        debug "process_args(): YML file $YML identified"
        local API=$(grep '^blackduck.api.token:' $YML| cut -f2 -d' ')
        if [ ! -z "API" ]
        then
            API_TOKEN=$API
            debug "process_args(): BLACKDUCK_API_TOKEN identified from $YML file"
        fi
        local URL=$(grep '^blackduck.url:' $YML | cut -f2 -d' ')
        if [ ! -z "URL" ]
        then
            BD_URL=$URL
            debug "process_args(): BLACKDUCK_URL identified from $YML file"
        fi
        local RES=$(grep '^detect.blackduck.signature.scanner.snippet.matching:' $YML| cut -f2 -d' ')
        if [ "$RES" == "true" ]
        then
            debug "process_args(): UNSUPPORTED OPTION detect.blackduck.signature.scanner.snippet.matching option identified from $YML"
            UNSUPPORTED=1
        fi
        local RES=$(grep '^detect.blackduck.signature.scanner.upload.source.mode:' $YML| cut -f2 -d' ')
        if [ "$RES" == "true" ]
        then
            debug "process_args(): UNSUPPORTED OPTION detect.blackduck.signature.scanner.upload.source.mode option identified from $YML"
            UNSUPPORTED=1
        fi
        local RES=$(grep '^detect.blackduck.signature.scanner.copyright.search:' $YML| cut -f2 -d' ')
        if [ "$RES" == "true" ]
        then
            debug "process_args(): UNSUPPORTED OPTION detect.blackduck.signature.scanner.copyright.search option identified from $YML"
            UNSUPPORTED=1
        fi
        local RES=$(grep '^detect.blackduck.signature.scanner.license.search:' $YML| cut -f2 -d' ')
        if [ "$RES" == "true" ]
        then
            debug "process_args(): UNSUPPORTED OPTION detect.blackduck.signature.scanner.license.search option identified from $YML"
            UNSUPPORTED=1
        fi
        local RES=$(grep '^detect.binary.scan.' $YML| cut -f2 -d' ')
        if [ "$RES" == "true" ]
        then
            debug "process_args(): UNSUPPORTED OPTION detect.binary.scan.* identified from $YML"
            UNSUPPORTED=1
        fi
        local RES=$(grep '^detect.source.path:' $YML| cut -f2 -d' ' | sed -e 's/"//g' -e "s/'//g")
        if [ ! -z "$RES" ] && [ -d "$RES" ]
        then
            debug "process_args(): detect.source.path '$RES' identified from $YML"
            SCANLOC=$(cd "$RES"; pwd)
        fi
    fi
    if [ $UNSUPPORTED -eq 1 ]
    then
        error "Unsupported Detect options specified (Snippet or Binary)"
    fi
}

get_token() {
    rm -f $TEMPFILE
    curl $CURLOPTS -s -X POST --header "Authorization: token ${API_TOKEN}" --header "Accept:application/json" ${BD_URL}/api/tokens/authenticate >$TEMPFILE 2>/dev/null
    if [ $? -ne 0 ] || [ ! -r "$TEMPFILE" ]
    then
        error "Cannot obtain auth token from BD Server"
    fi
    local TOKEN=$($JQ -r '.bearerToken' $TEMPFILE 2>/dev/null)
    if [ -z "$TOKEN" ]
    then
        error "Cannot obtain auth token from BD Server"
    fi
    debug "get_token(): Auth token obtained correctly"

    echo $TOKEN
}

run_detect_offline() {
    if [ -z "$DETECT_SCRIPT" ]
    then
        curl $CURLOPTS -s -L https://detect.synopsys.com/detect.sh > $DETECT_TMP 2>/dev/null
        if [ ! -r $DETECT_TMP ]
        then
            error "Unable to download detect.sh from https://detect.synopsys.com - use --detect=PATH_TO_DETECT.sh"
        fi
        chmod +x $DETECT_TMP
        DETECT_SCRIPT=$DETECT_TMP
        debug "run_detect_offline(): Detect script downloaded to $DETECT_SCRIPT"
    else
        debug "run_detect_offline(): Detect script $DETECT_SCRIPT will be used"
    fi

    rm -f $TEMPFILE
    if [ $MODE_QUIET -eq 0 ]
    then
        $DETECT_SCRIPT $DETARGS --detect.blackduck.signature.scanner.host.url=${BD_URL} --blackduck.offline.mode=true 2>/dev/null | tee $TEMPFILE
        RET=${PIPESTATUS[0]}
    else
        output "Running Detect offline ..."
        $DETECT_SCRIPT $DETARGS --detect.blackduck.signature.scanner.host.url=${BD_URL} --blackduck.offline.mode=true 2>/dev/null >$TEMPFILE
        RET=$?
        cat $TEMPFILE >>$LOGFILE
    fi
    if [ $RET -ne 0 ]
    then
        debug "run_detect_offline(): Detect returned code $RET"
        return $RET
    fi
    if [ ! -r $TEMPFILE ]
    then
        return 1
    fi
    RUNDIR=$(grep 'Run directory: ' $TEMPFILE | sed -e 's/^.*Run directory: //g')
    PROJECT=$(grep 'Project name: ' $TEMPFILE | sed -e 's/^.*Project name: //g')
    VERSION=$(grep 'Project version: ' $TEMPFILE | sed -e 's/^.*Project version: //g')
    if [ -z "$RUNDIR" -o ! -d "$RUNDIR" -o ! -d "$RUNDIR/bdio" -o -z "$PROJECT" -o -z "$VERSION" ]
    then
        return 1
    fi
    debug "run_detect_offline(): PROJECT=$PROJECT VERSION=$VERSION RUNDIR=$RUNDIR"
    SIGRUN=$(grep -c 'Starting the Black Duck Signature Scan' $TEMPFILE)
    if [ $SIGRUN -gt 0 ]
    then
        SIGFOLDER=$(grep 'You can view the logs at: ' $TEMPFILE | sed -e 's/^.*You can view the logs at: //g' -e "s/'//g")
    fi
    debug "run_detect_offline(): SIGFOLDER=$SIGFOLDER"
    return 0
}

proc_bom_files() {
    local CWD=$(pwd)
    cd "$RUNDIR"
    if [ ! -d bdio ]
    then
        debug "proc_bom_files(): $RUNDIR/bdio does not exist"
        cd "$CWD"
        return 1
    fi
    cd bdio
    local COUNT=0
    for bom in *.jsonld
    do
        if [ ! -r "$bom" ]
        then
            cd "$CWD"
            return 1
        fi
        CKSUM=$(cat $bom | grep -v 'spdx:created' | grep -v 'uuid:' | sort | cksum | cut -f1 -d' ')
        FILE=$(basename $bom)
        BOM_FILES+=("${FILE}")
        BOM_HASHES+=("${CKSUM}")
        ((COUNT++))
    done
    debug "proc_bom_files(): Processed $COUNT .jsonld files"
    cd "$CWD"
    return 0
}

proc_prev_bom_data() {
    if [ ! -z "$PREVSCANDATA" ]
    then
        local COUNT=0
        IFS='|'
        for item in $PREVSCANDATA
        do
            if [[ $item == VER:* ]]
            then
                PREV_PROJ=$(echo $item|cut -f2 -d:)
                PREV_VER=$(echo $item|cut -f3 -d:)
                if [ "$PROJECT" != "$PREV_PROJ" -o "$VERSION" != "$PREV_VER" ]
                then
                    break
                fi
            elif [[ $item == BOM:* ]]
            then
                PREV_FILES+=($(echo $item|cut -f2 -d:))
                PREV_HASHES+=($(echo $item|cut -f3 -d:))
                ((COUNT++))
            fi
        done
        IFS=
        debug "proc_prev_bom_data(): Found $COUNT BOM entries in previous scan data"
    fi
}

compare_boms() {
    local COUNT=0
    for index in ${!BOM_FILES[@]}
    do
        MATCHED=0
        for previndex in ${!PREV_FILES[@]}
        do
            if [ "${BOM_FILES[$index]}" == "${PREV_FILES[$previndex]}" ]
            then
                if [ "${BOM_HASHES[$index]}" == "${PREV_HASHES[$previndex]}" ]
                then
                    MATCHED=1
                fi
            fi
        done
        if [ $MATCHED -eq 0 ] || [ $MODE_RESET -eq 1 ]
        then
            UNMATCHED_BOMS+=($index)
        fi
        ((COUNT++))
    done
    debug "compare_boms(): $COUNT bomfiles processed, MATCHED=$MATCHED"
}

upload_boms() {
    echo -n "detect_rescan: BOM files - Uploading ${#UNMATCHED_BOMS[@]} out of ${#BOM_FILES[@]} total ..."
    local UPLOADED=0
    local FAILED=0
    for index in ${UNMATCHED_BOMS[@]}
    do
        echo -n '.'
        curl $CURLOPTS -s -X POST "${BD_URL}/api/scan/data/?mode=replace" \
        -H "Authorization: Bearer $TOKEN" \
        -H 'Content-Type: application/vnd.blackducksoftware.bdio+json' \
        -H 'cache-control: no-cache' \
        --data-binary "@$RUNDIR/bdio/${BOM_FILES[$index]}" >/dev/null 2>&1
        if [ $? -eq 0 ]
        then
            ((UPLOADED++))
        else
            debug "upload_boms(): Upload failed for $RUNDIR/bdio/${BOM_FILES[$index]}"
            ((FAILED++))
        fi
    done
    echo
    msg "$UPLOADED Modified/New Bom Files Uploaded successfully ($FAILED Failed)"
    if [ $FAILED -gt 0 ]
    then
        return 1
    fi
    return 0
}

run_detect_action() {
    output "Rerunning Detect to execute post-scan action"
    if [ $DETECT_PROJECT -eq 0 ]
    then
        DETARGS="$DETARGS '--detect.project.name=$PROJECT'"
    fi
    if [ $DETECT_VERSION -eq 0 ]
    then
        DETARGS="$DETARGS '--detect.project.version.name=$VERSION'"
    fi
    debug "run_detect_action(): Will call Detect with options $DETARGS --detect.tools=NONE"
    if [ $MODE_QUIET -eq 0 ]
    then
        $DETECT_SCRIPT $DETARGS --detect.tools=NONE
        RET=$?
    else
        $DETECT_SCRIPT $DETARGS --detect.tools=NONE >>$LOGFILE
        RET=$?
    fi
    debug "run_detect_action(): Return code $RET"
    return $RET
}

api_call() {
    if [ -z "$2" ]
    then
        HEADER="application/json"
    else
        HEADER="$2"
    fi
    rm -f $TEMPFILE
    curl $CURLOPTS -s -X GET --header "Authorization: Bearer $TOKEN" "$1" 2>/dev/null >$TEMPFILE
    RET=$?
    if [ $RET -ne 0 ] || [ ! -r $TEMPFILE ]
    then
        echo "detect_rescan: ERROR: API Error - Curl returned $RET" >&2
        debug "api_call(): API call failed: curl -s -X GET --header 'Authorization: Bearer $TOKEN' $1"
        return 1
    fi

    if [ $(grep -c 'failed authorization' $TEMPFILE) -gt 0 ]
    then 
        echo "detect_rescan: ERROR: Server or Project Authorization issue" >&2
        return 1
    fi
    if [ $(grep -c errorCode $TEMPFILE) -gt 0 ]
    then 
        echo "detect_rescan: ERROR: Other API error $($JQ '.errorCode' $TEMPFILE 2>/dev/null)" >&2
        return 1
    fi
    if [ $(grep -c totalCount $TEMPFILE) -gt 0 ]
    then 
        COUNT=$($JQ -r '.totalCount' $TEMPFILE 2>/dev/null)
        if [ -z "$COUNT" ]
        then
            debug "api_call(): totalCount field not found in API response - returning False"
            return 1
        fi
    fi
    #debug "api_call(): $COUNT records identified in API response"

    return 0
}

get_project() {
    #Get  projects $1=projectname
    debug "get_project(): ARG1=$1"
    #local SEARCHPROJ=$(echo ${1} | sed -e 's:/:%2F:g' -e 's/ /+/g')
    local SEARCHPROJ=$(encode_url ${1})
    local MYURL="${BD_URL}/api/projects?q=name:${SEARCHPROJ}"
    debug "get_project(): API_URL=$MYURL"

    api_call "$MYURL" 'application/vnd.blackducksoftware.project-detail-4+json'
    if [ $? -ne 0 ]
    then
        debug "get_project(): API error - returning early"
        return 1
    fi

    local PROJNAMES=$($JQ -r '[.items[].name]|@csv' $TEMPFILE 2>/dev/null| encode_url )
    local PROJURLS=$($JQ -r '[.items[]._meta.href]|@csv' $TEMPFILE 2>/dev/null| sed -e 's/\"//g' )
    debug "get_project(): PROJNAMES=$PROJNAMES"
    debug "get_project(): PROJURLS=$PROJURLS"

    local PROJNUM=1
    local FOUNDNUM=0
    local IFS=,
    for PROJ in $PROJNAMES
    do
        debug "get_project(): PROJ='$PROJ' SEARCHPROJ='$SEARCHPROJ'"

        if [ "$PROJ" == "$SEARCHPROJ" ]
        then
            FOUNDNUM=$PROJNUM
            break
        fi
        ((PROJNUM++))
    done
    IFS=

    debug "get_project(): Found $FOUNDNUM projects"
    if [ $FOUNDNUM -eq 0 ]
    then
        return 0
    fi

    debug "get_project(): PROJURLS is '$PROJURLS'"
    RETURL=$(echo $PROJURLS | cut -f $FOUNDNUM -d ,)
    debug "get_project(): returning project URL $RETURL"
    echo $RETURL
    return 0
}

get_version() {
    # Get Version  - $1 = PROJURL
    local VERNAME=$(encode_url ${2} )
    local API_URL="${1//\"}/versions?versionName%3A${VERNAME}"
    debug "get_version(): version URL is '$API_URL'"
    #local SEARCHVERSION="${2// /_}"
    #echo "get_version: SEARCHVERSION=$SEARCHVERSION" >&2
    api_call "${API_URL}" 'application/vnd.blackducksoftware.project-detail-4+json'
    if [ $? -ne 0 ]
    then
        debug "get_version(): API error"
        return 1
    fi

    local VERNAMES=$($JQ -r '[.items[].versionName]|@csv' $TEMPFILE 2>/dev/null | encode_url )
    local VERURLS=$($JQ -r '[.items[]._meta.href]|@csv' $TEMPFILE 2>/dev/null | sed -e 's/\"//g' )
    debug "get_version(): VERNAMES=$VERNAMES"
    debug "get_version(): VERURLS=$VERURLS"
    local VERNUM=1
    local FOUNDVERNUM=0
    local IFS=,
    for NAME in $VERNAMES
    do
        #echo "get_version: NAME=$NAME" >&2
        if [ "$NAME" == "$VERNAME" ]
        then
            FOUNDVERNUM=$VERNUM
            break
        fi
        ((VERNUM++))
    done
    IFS=
    
    if [ $FOUNDVERNUM -eq 0 ]
    then
        debug "get_version(): 0 versions found from project"
        return 0
    fi

    RETURL=$(echo $VERURLS | cut -f $FOUNDVERNUM -d ,)
    debug "get_version(): returning version URL $RETURL"
    echo $RETURL
    return 0
}

get_projver() {
# $1=projectname $2=versionname $3=number_of_10_sec_loops
    debug "get_projver(): ARG1=$1 ARG2=$2 ARG3=$3"
    local NUMLOOPS=${3:-0}
    local COUNT=0
    while [ $COUNT -le $NUMLOOPS ]
    do
        debug "get_projver(): Loop $COUNT"
        PURL=$(get_project "$1")
        if [ $? -ne 0 ]
        then
            return 1
        fi
        debug "get_projver(): PURL=$PURL"
        if [ ! -z "$PURL" ]
        then
            VURL=$(get_version "$PURL" "$2")
            if [ $? -ne 0 ]
            then
                return 1
            fi
            debug "get_projver(): VURL=$VURL"
        fi
        ((COUNT++))
        if [ -z "$VURL" ]
        then
            sleep 10
        else
            break
        fi
    done
    echo $VURL
    debug "get_projver(): Returning version URL $VURL"

    return 0
}

wait_for_bom_completion() {
    # Check job status

    local loop=0
    while [ $loop -lt 80 ]
    do
        debug "wait_for_bom_completion(): Waiting loop $loop"
        api_call "${1//\"}/bom-status" 'application/vnd.blackducksoftware.internal-1+json'
        if [ $? -ne 0 ]
        then
            debug "wait_for_bom_completion(): api_call() returned failure"
            return 1
        fi
        local STATUS=$($JQ -r '.upToDate' $TEMPFILE 2>/dev/null)

        if [ "$STATUS" == "true" ]
        then
            debug "wait_for_bom_completion(): upToDate status returned true"
            echo
            return 0
        fi
        echo -n '.'
        sleep 15
        ((loop++))
    done
    echo
    return 1
}

wait_for_scans() {
    local SCANURL=$(echo ${1//\"}| sed -e 's/ /%20/g')
    local loop=0
    while [ $loop -lt 80 ]
    do
        # Check scan status
        debug "wait_for_scans(): Waiting loop $loop"
        api_call "${SCANURL}" 'application/vnd.blackducksoftware.scan-4+json'
        if [ $? -ne 0 ]
        then
            debug "wait_for_scans(): api_call() returned failure"
            return 1
        fi
        local STATUSES=$($JQ -r '[.items[].status[].status]|@csv' $TEMPFILE 2>/dev/null)
        local OPCODES=$($JQ -r '[.items[].status[].operationNameCode]|@csv' $TEMPFILE 2>/dev/null)
        local DONE=1
        local index=1
        local IFS=,
        for stat in $STATUSES 
        do
            IFS=
            OPCODE=$(echo $OPCODES | cut -f$index -d,)
            ((index++))
            if [ $OPCODE != '"ServerScanning"' ]
            then
                continue
            fi
            if [ $stat != '"COMPLETED"' ]
            then
                DONE=0
            fi
        done
        if [ $DONE -eq 1 ]
        then
            debug "wait_for_scans(): ServerScanning field marked as COMPLETED"
            return 0
        fi
        ((loop++))
        echo -n '.'
        sleep 15
    done
    return 1
}

check_sigscan() {
    local DIFFTIME=$1
    local NOWDATE=$(date '+%Y%m%d%H%M%S')
    local SIGDATE=$NOWDATE
    local PROCSIGSCAN=0
    if [ $MODE_RESET -eq 1 ]
    then
        echo $NOWDATE
        return 1
    fi
    local PREV_SIGSCAN_DATE=
    local IFS='|'
    for item in $PREVSCANDATA
    do
        if [[ $item == VER:* ]]
        then
            local PREV_PROJ=$(echo $item|cut -f2 -d:)
            local PREV_VER=$(echo $item|cut -f3 -d:)
            if [ "$PROJECT" != "$PREV_PROJ" -o "$VERSION" != "$PREV_VER" ]
            then
                break
            fi
        fi
        if [[ $item == SIG:* ]]
        then
            PREV_SIGSCAN_DATE=$(echo $item|cut -f2 -d:)
            debug "check_sigscan(): PREV_SIGSCAN_DATE=$PREV_SIGSCAN_DATE NOW=$NOWDATE"
        fi
    done
    IFS=

    if [ ! -z "$PREV_SIGSCAN_DATE" ] && [ "$PREV_SIGSCAN_DATE" -gt 0 ]
    then
        DIFF=$((NOWDATE-PREV_SIGSCAN_DATE))
        if [ $DIFF -gt $DIFFTIME ]
        then
            PROCSIGSCAN=1
        else
            SIGDATE=$PREV_SIGSCAN_DATE
        fi
    else
        PROCSIGSCAN=1
    fi
    debug "check_sigscan(): Return value PROCSIGSCAN=$PROCSIGSCAN"

    echo $SIGDATE
    return $PROCSIGSCAN
}

proc_sigscan() {
    local CWD=$(pwd)
    cd "$SIGFOLDER"
    if [ ! -d data ]
    then
        debug "proc_sigscan(): $SIGFOLDER/data does not exist"
        cd "$CWD"
        return 0 #No Sig scan
    fi
    cd data
    for sig in *.json
    do
        if [ ! -r "$sig" ]
        then
            debug "proc_sigscan(): No sig scan found" 
            cd "$CWD"
            return 1 # No sig scan
        fi
        debug "proc_sigscan(): Processing sig scan file $SIGFOLDER/data/$sig"
#        output "Signature Scan - Uploading ..."
        curl $CURLOPTS -s -X POST "${BD_URL}/api/scan/data/?mode=replace" \
        -H "Authorization: Bearer $TOKEN" \
        -H 'Content-Type: application/ld+json' \
        -H 'cache-control: no-cache' \
        --data-binary "@$sig" >/dev/null 2>&1
        if [ $? -eq 0 ]
        then
            local SIGSCANNAME=$($JQ '.name' "$sig")
            if [ ! -z "$SIGSCANNAME" ]
            then
                echo $SIGSCANNAME
                debug "proc_sigscan(): Signature code location name = $SIGSCANNAME"
                cd "$CWD"
                return 0
            fi
        fi
        debug "proc_sigscan(): Returning error as no code location name found in sigscan file"
        cd "$CWD"
        return 1 # Unable to upload sig scan
    done
    cd "$CWD"
    debug "proc_sigscan(): No sig scan found"
    return 0 # No sig scan
}

cleanup() {
    if [ ! -z "$RUNDIR" ]
    then
        if [ -d "$RUNDIR/bdio" ]
        then
            rm -rf "$RUNDIR/bdio"
            msg "Deleting $RUNDIR/bdio"
        fi
        if [ -d "$RUNDIR/extractions" ]
        then
            rm -rf "$RUNDIR/extractions"
            msg "Deleting $RUNDIR/extractions"
        fi
        if [ -d "$RUNDIR/scan" ]
        then
            rm -rf "$RUNDIR/scan"
            msg "Deleting $RUNDIR/scan"
        fi
    fi
}

run_report() {
    local URL=$1
    if [ -z "$URL" ]
    then
        return 1
    fi

    api_call ${URL}/policy-status 'application/vnd.blackducksoftware.bill-of-materials-6+json'
    if [ $? -ne 0 ]
    then
        return 1
    fi
    
    local MARKDOWNFILE=$SCANLOC/blackduck.md

    if [ $MODE_MARKDOWN -eq 1 ]
    then
        PROJURL=$(echo $URL | sed -e 's!/versions.*$!!')
        ( echo
        echo "# BLACK DUCK OSS SUMMARY REPORT"
        echo "Project: '[$PROJECT]($PROJURL)' Version: '[$VERSION]($VERURL)'"
        echo ) >$MARKDOWNFILE
    fi
    if [ $MODE_REPORT -eq 1 ]
    then
        echo
        echo "----------------------------------------------------------------------"
        echo BLACK DUCK OSS SUMMARY REPORT
        echo "Project: '$PROJECT' Version: '$VERSION'"
        echo
    fi
    local POL_STATUS=$($JQ -r '.overallStatus' $TEMPFILE 2>/dev/null)
    if [ "$POL_STATUS" == "IN_VIOLATION" ]
    then
        POL_TYPES=$($JQ -r '.componentVersionStatusCounts[].name' $TEMPFILE 2>/dev/null | tr '\n' ',')
        POL_STATS=$($JQ -r '.componentVersionStatusCounts[].value' $TEMPFILE 2>/dev/null | tr '\n' ',')
        if [ $MODE_MARKDOWN -eq 1 ]
        then
            ( echo "## Component Policy Status:"
            echo
            echo "| Component Policy Status | Count |"
            echo "|-------------------------|-------:|" ) >>$MARKDOWNFILE
        fi
        if [ $MODE_REPORT -eq 1 ]
        then
            echo Component Policy Status:
        fi
        local IFS=,
        local INDEX=1
        local COMPCOUNT=0
        for type in ${POL_TYPES}
        do
            IFS=
            POL_STAT=$(echo $POL_STATS | cut -f$INDEX -d,)
            COMPCOUNT=$(($COMPCOUNT+$POL_STAT))
            if [ $MODE_MARKDOWN -eq 1 ]
            then
                if [ "$type" == "IN_VIOLATION_OVERRIDDEN" ]
                then
                    echo "| In Violation Overidden | [$POL_STAT]($URL/components?filter=bomPolicy%3Ain_violation_overridden) |" >>$MARKDOWNFILE
                elif [ "$type" == "NOT_IN_VIOLATION" ]
                then
                    echo "| Not In Violation | $POL_STAT |" >>$MARKDOWNFILE
                elif [ "$type" == "IN_VIOLATION" ]
                then
                    echo "| In Violation | [$POL_STAT]($URL/components?filter=bomPolicy%3Ain_violation) |" >>$MARKDOWNFILE
                fi
            fi
            if [ $MODE_REPORT -eq 1 ]
            then
                if [ "$type" == "IN_VIOLATION_OVERRIDDEN" ]
                then
                    echo "  - In Violation Overidden:	$POL_STAT"
                elif [ "$type" == "NOT_IN_VIOLATION" ]
                then
                    echo "  - Not In Violation:		$POL_STAT"
                elif [ "$type" == "IN_VIOLATION" ]
                then
                    echo "  - In Violation:		$POL_STAT"
                fi
            fi
            ((INDEX++))
        done
    fi
    
    XMLPOL='policies.xml'
    XMLVULN='vulns.xml'
    if [ "$POL_STATUS" == "IN_VIOLATION" ] || [ $MODE_TESTXML -eq 1 ]
    then
        if [ $MODE_REPORT -eq 1 ]
        then
            echo
            echo "Components in Violation:"
        fi
        if [ $MODE_TESTXML -eq 1 ]
        then
            ( echo '<?xml version="1.0" encoding="UTF-8"?>'
            echo '<testsuites disabled="" errors="" failures="" tests="" time="" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="junit.xsd">'
            echo '<testsuite disabled="" errors="" failures="" hostname="" id="" name="Black Duck policy status" package="" skipped="" tests="" time="" timestamp="">'
            echo '<properties><property name="" value=""/></properties>' ) >$XMLPOL
        fi

        api_call "${URL}/components?limit=5000" 'application/vnd.blackducksoftware.bill-of-materials-4+json'
        if [ $? -ne 0 ]
        then
            return 1
        fi

        rm -f $TEMPFILE2
        $JQ -r '.items[].componentName' $TEMPFILE 2>/dev/null >$TEMPFILE2
        local COMPPOLS=$($JQ -r '.items[].policyStatus' $TEMPFILE 2>/dev/null | tr '\n' ',')
        local COMPVERS=$($JQ -r '.items[].componentVersionName' $TEMPFILE 2>/dev/null | tr '\n' '|')
        local COMPURLS=$($JQ -r '.items[]._meta.href' $TEMPFILE 2>/dev/null | tr '\n' ',')
        local INDEX=1
        while read comp
        do
            local COMPPOL=$(echo $COMPPOLS | cut -f$INDEX -d,)
            local COMPURL=$(echo $COMPURLS | cut -f$INDEX -d,)
            local COMPNAME="$comp/$(echo $COMPVERS|cut -f$INDEX -d'|')"
            if [ "$COMPPOL" == "IN_VIOLATION" ]
            then
                if [ $MODE_REPORT -eq 1 ]
                then
                    echo -n "	Component: '$COMPNAME' Policies Violated: "
                fi
                if [ $MODE_TESTXML -eq 1 ]
                then
                    echo "<testcase name='$COMPNAME'>" >>$XMLPOL
                    echo -n "<error message='$COMPNAME violates the following policies: " >>$XMLPOL
                fi
                api_call ${COMPURL}/policy-rules
                if [ $? -ne 0 ]
                then
                    continue
                fi
            
                local POLNAMES=$($JQ -r '.items[].name' $TEMPFILE 2>/dev/null | tr '\n' '|' | escape_string )
                local POLSEVERITIES=$($JQ -r '.items[].severity' $TEMPFILE 2>/dev/null | tr '\n' ',' | escape_string )
                IFS='|'
                sevind=1
                for polname in $POLNAMES
                do
                    if [ $MODE_REPORT -eq 1 ]
                    then
                        echo -n "'$polname' ($(echo $POLSEVERITIES|cut -f$sevind -d,)) "
                    fi
                    if [ $MODE_TESTXML -eq 1 ]
                    then
                        echo -n "$polname ($(echo $POLSEVERITIES|cut -f$sevind -d,)), " >>$XMLPOL
                    fi
                    ((sevind++))
                done
                if [ $MODE_TESTXML -eq 1 ]
                then
                    echo "'></error></testcase>" >>$XMLPOL
                fi
                if [ $MODE_REPORT -eq 1 ]
                then
                    echo
                fi
                IFS=
            else
                if [ $MODE_TESTXML -eq 1 ]
                then
                    echo "<testcase name='$COMPNAME'></testcase>" >>$XMLPOL
                fi
            fi
            ((INDEX++))
        done <$TEMPFILE2
        if [ $MODE_TESTXML -eq 1 ]
        then
            ( echo '<system-out>system-out</system-out>'
            echo '    <system-err>system-err</system-err></testsuite>'
            echo '</testsuites>' ) >>$XMLPOL
        fi
    else
        if [ $MODE_REPORT -eq 1 ]
        then
            echo Component Policy Status:
            echo " - No policy violations"
        fi
        if [ $MODE_MARKDOWN -eq 1 ]
        then
            ( echo "## Component Policy Status:"
            echo"- No policy violations" ) >>$MARKDOWNFILE
        fi
    fi

    api_call ${URL}/risk-profile
    if [ $? -ne 0 ]
    then
        return 1
    fi

    local VULNS=$($JQ -r '.categories | [.VULNERABILITY.CRITICAL, .VULNERABILITY.HIGH, .VULNERABILITY.MEDIUM, .VULNERABILITY.LOW, .VULNERABILITY.OK] | @csv' $TEMPFILE 2>/dev/null)
    local LICS=$($JQ -r '.categories | [.LICENSE.HIGH, .LICENSE.MEDIUM, .LICENSE.LOW, .LICENSE.OK] | @csv' $TEMPFILE 2>/dev/null)
    local OPS=$($JQ -r '.categories | [.OPERATIONAL.HIGH, .OPERATIONAL.MEDIUM, .OPERATIONAL.LOW, .OPERATIONAL.OK] | @csv' $TEMPFILE 2>/dev/null)
    if [ $MODE_MARKDOWN -eq 1 ]
    then
        local NEWVULNS=$(echo $VULNS | sed -e 's/^/\[/' -e 's!,!\]('${URL}'/components?filter=securityRisk%3Acritical);\[!' -e 's!,!\]('${URL}'/components?filter=securityRisk%3Ahigh);\[!')
        local NEWLICS=$(echo $LICS | sed -e 's/^/\[/' -e 's!,!\]('${URL}'/components?filter=licenseRisk%3Ahigh);\[!')
        local NEWOPS=$(echo $OPS | sed -e 's/^/\[/' -e 's!,!\]('${URL}'/components?filter=operationalRisk%3Ahigh);\[!')

        ( echo
        echo "## Component Counts"
        echo "| CATEGORY | CRIT | HIGH | MED | LOW | None |"
        echo "|----------|------:|-------:|------:|------:|-------:|"
        echo "| Vulnerability | ${NEWVULNS//;/ | } |"
        echo "| License | - | ${NEWLICS//;/ | } |"
        echo "| Op Risk | - | ${NEWOPS//;/ | } |"
        echo )>>$MARKDOWNFILE
    fi
    if [ $MODE_REPORT -eq 1 ] || [ $MODE_TESTXML -eq 1 ]
    then
        api_call "${URL}/vulnerable-bom-components?limit=5000&sort=severity" 'application/vnd.blackducksoftware.bill-of-materials-6+json'
        if [ $? -ne 0 ]
        then
            debug "run_report(): API error trying to get vulnerable components"
            return 1
        fi
    fi
    if [ $MODE_REPORT -eq 1 ]
    then
        local VULN_LIST=$($JQ -r '.items[] | select(.vulnerabilityWithRemediation.severity == "CRITICAL" or .vulnerabilityWithRemediation.severity == "HIGH") | [.vulnerabilityWithRemediation.severity, .vulnerabilityWithRemediation.vulnerabilityName, .vulnerabilityWithRemediation.overallScore, .vulnerabilityWithRemediation.cweId, .vulnerabilityWithRemediation.remediationStatus, .componentName, .componentVersionName] | @csv' $TEMPFILE 2>/dev/null | sed -e 's/"//g' -e 's/,,/, ,/g' | sort -t , -n -k 3 -r)
        echo
        echo "Component Counts (Total = $COMPCOUNT):"
        ( echo " ,CRIT,HIGH,MED ,LOW ,None"
        echo " ,----,----,---,---,----"
        echo "Vulnerability,${VULNS}"
        echo "License,-,${LICS}"
        echo "Op Risk,-,${OPS}"
        echo ) | column -t -s ',' | sed -e 's/^/	/g'

        echo
        echo "Critical/High Vulnerabilities:"
        (echo "Vuln ID,Score,Severity,Weakness,Status,Component,Component Version"
        echo $VULN_LIST )| column -t -s ',' | sed -e 's/^/	/g'
        echo 
        echo "See Black Duck Project at:"
        echo "$URL/components"
        echo
        echo "----------------------------------------------------------------------"
    fi
    if [ $MODE_TESTXML -eq 1 ]
    then
        ( echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo '<testsuites disabled="" errors="" failures="" tests="" time="" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="junit.xsd">'
        echo '<testsuite disabled="" errors="" failures="" hostname="" id="" name="Black Duck vulnerability status" package="" skipped="" tests="" time="" timestamp="">'
        echo '<properties><property name="" value=""/></properties>' ) >$XMLVULN
        rm -f $TEMPFILE2
        $JQ -r '.items[] | [.vulnerabilityWithRemediation.vulnerabilityName, .vulnerabilityWithRemediation.severity, .vulnerabilityWithRemediation.overallScore, .vulnerabilityWithRemediation.remediationStatus, .componentName, .componentVersionName] | @csv' $TEMPFILE | sed -e 's/"//g' | sort -t , -n -k 3 -r > $TEMPFILE2 2>/dev/null
        while read line
        do
            local VULNNAME=$(echo $line | cut -f1 -d,)
            local VULNSEV=$(echo $line | cut -f2 -d,)
            local VULNSCORE=$(echo $line | cut -f3 -d,)
            local VULNSTAT=$(echo $line | cut -f4 -d,)
            local VULNCOMP=$(echo $line | cut -f5 -d,)
            local VULNCOMPVER=$(echo $line | cut -f6 -d,)

            (echo "<testcase name='$VULNSEV - $VULNNAME'><error message='Vulnerability $VULNNAME:"
            echo "- Severity = $VULNSEV"
            echo "- Score = $VULNSCORE"
            echo "- Status = $VULNSTAT"
            echo "- Component = $VULNCOMP/$VULNCOMPVER"
            echo "See ${BD_URL}/api/vulnerabilities/$VULNNAME/overview"
            echo "'></error></testcase>" ) >>$XMLVULN
        done < $TEMPFILE2

        ( echo '<system-out>system-out</system-out>'
        echo '    <system-err>system-err</system-err></testsuite>'
        echo '</testsuites>' ) >>$XMLVULN
   fi
}

get_prev_scandata() {
    if [ $MODE_PREVFILE -eq 0 ]
    then
        debug "get_prev_scandata(): Using prevScanData custom field"
        local VURL=$1
        api_call $VURL/custom-fields 'application/vnd.blackducksoftware.project-detail-5+json'
        if [ $? -ne 0 ]
        then
            return 1
        fi

        local FIELDS=$($JQ -r '[.items[].label]|@csv' $TEMPFILE 2>/dev/null)
        local DATAS=$($JQ -r '[.items[].values[0]]|@csv' $TEMPFILE 2>/dev/null)
        #URLS=$(jq -r '[.items[]._meta.href]|@csv' $TEMPFILE 2>/dev/null)
        local FNUM=1
        local IFS=,
        for FIELD in $FIELDS
        do
            if [ $FIELD == '"prevScanData"' ]
            then
                IFS=
                DATA=$(echo $DATAS | cut -f$FNUM -d,)
                #PREVSCANFIELDURL=$(echo $URLS | cut -f$FNUM -d,)
                echo ${DATA//\"/}
                debug "get_prev_scandata(): prevScanData custom field obtained from project"
                return 0
            fi
            ((FNUM++))
        done
        IFS=
    else
        if [ -r "$PREVSCANFILE" ]
        then
            debug "get_prev_scandata(): Using previous scan file $PREVSCANFILE"
            cat "$PREVSCANFILE" | tr '\n' '|'
        fi
        return 0
    fi
    debug "get_prev_scandata(): Returning fail (1)"
    return 1
}

update_prevscandata() {
    local URL=${2//\"}
    local SIGDATE=$1
    if [ $MODE_PREVFILE -eq 1 ]
    then
        debug "update_prevscandata(): Will update previous scan file $PREVSCANFILE"
        if [ -r "$PREVSCANFILE" ]
        then
            rm -f "$PREVSCANFILE"
        fi
        echo "VER:$PROJECT:$VERSION" >$PREVSCANFILE
        for index in ${!BOM_FILES[@]}
        do
            echo "BOM:${BOM_FILES[$index]}:${BOM_HASHES[$index]}" >>$PREVSCANFILE
        done
        if [ ! -z "$SIGDATE" ]
        then
            echo "SIG:$SIGDATE" >>$PREVSCANFILE
        fi
        if [ -r "$PREVSCANFILE" ]
        then
            error "Unable to write scan data to $PREVSCANFILE"
        else
            msg "Scan data stored in file $PREVSCANFILE"
        fi
    elif [ ! -z "$URL" ]
    then
        debug "update_prevscandata(): Will update previous scan file custom field"

        local SCANDATA="VER:$PROJECT:$VERSION"
        for index in ${!BOM_FILES[@]}
        do
            SCANDATA="${SCANDATA}|BOM:${BOM_FILES[$index]}:${BOM_HASHES[$index]}"
        done
        if [ ! -z "$SIGDATE" ]
        then
            SCANDATA="${SCANDATA}|SIG:$SIGDATE"
        fi
        VAL='{"values": [ "'$SCANDATA'"] }'
        #echo "update_prevscandata: VAL=$VAL" >&2
        #echo "update_prevscandata: URL=$URL" >&2 
        #echo "update_prevscandata: curl -X PUT --header \"Authorization: Bearer $TOKEN\" --header \"Content-Type: application/vnd.blackducksoftware.project-detail-5+json\" -d '$VAL' $URL"
        curl $CURLOPTS -s -X PUT --header "Authorization: Bearer $TOKEN" --header "Content-Type: application/vnd.blackducksoftware.project-detail-5+json" --header "Accept: application/vnd.blackducksoftware.project-detail-5+json" -d "$VAL" $URL >$TEMPFILE 2>&1 
        if [ $? -ne 0 ]
        then
            error "Unable to write scan data to Project Version custom field"
        fi
        local STATUS=$($JQ '.errorMessage' $TEMPFILE 2>/dev/null)
        if [ "$STATUS" != "null" ]
        then
            error "Unable to update custom scan field - $STATUS"
        fi
        msg "Scan data stored in Project Version custom field"
    fi
    return 0
}

get_scandata_url() {
    local VURL=${1//\"}
    api_call ${VURL}/custom-fields 'application/vnd.blackducksoftware.project-detail-5+json'
    if [ $? -ne 0 ]
    then
        debug "get_scandata_url(): API error returned"
        return 1
    fi

    local FIELDS=$($JQ -r '[.items[].label]|@csv' $TEMPFILE 2>/dev/null)
    local URLS=$($JQ -r '[.items[]._meta.href]|@csv' $TEMPFILE 2>/dev/null)
    local FNUM=1
    local IFS=,
    for FIELD in $FIELDS
    do
        if [ $FIELD == '"prevScanData"' ]
        then
            IFS=
            SDURL=$(echo $URLS | cut -f$FNUM -d,)
            echo $SDURL
            debug "get_scandata_url(): Found scan data URL $SDURL"
            return 0
        fi
        ((FNUM++))
    done
    IFS=
    debug "get_scandata_url(): Not able to identify scandata URL"
    return 1
}

##########################################################################################
# MAIN LOGIC

debug "Starting script"

prereqs
if [ $? -ne 0 ]
then
    end 1
fi

getargval() {
    local ARG=$(echo "$*" | cut -f2 -d=)
    ARG="${ARG#\'}"
    ARG="${ARG%\'}"
    if [ ! -z "$(echo $*|grep ' ')" ]
    then
        echo "'${ARG}'"
    else
        echo "${ARG}"
    fi
}

procarg() {
    local OPT=$(echo "$*" | cut -f1 -d=)
    echo "${OPT}=$(getargval $*)"
}

# Process arguments
while (( "$#" )); do
#     echo "processing '$1'"
    case "$1" in
# Ignored arguments
        --blackduck.offline.mode=*)
            shift; continue
            ;;
        --detect.blackduck.signature.scanner.host.url=*)
            shift; continue
            ;;
# Arguments NOT to be passed to detect.sh
        --report)
            debug "process_args(): MODE_REPORT set"
            MODE_REPORT=1
            shift; continue
            ;;
        --quiet)
            debug "process_args(): MODE_QUIET set"
            MODE_QUIET=1
            shift; continue
            ;;
        --markdown)
            debug "process_args(): MODE_MARKDOWN set"
            MODE_MARKDOWN=1
            shift; continue
            ;;
        --file)
            debug "process_args(): MODE_PREVFILE set"
            MODE_PREVFILE=1
            shift; continue
            ;;
        --testxml)
            debug "process_args(): MODE_TESTXML set"
            MODE_TESTXML=1
            shift; continue
            ;;
        --reset)
            debug "process_args(): MODE_RESET set"
            MODE_RESET=1
            shift; continue
            ;;
        --detectscript=*)
            DETECT_SCRIPT=$(getarg "$1")
            debug "process_args(): DETECT_SCRIPT set to $DETECT_SCRIPT"
            if [ ! -r "$DETECT_SCRIPT" ]
            then
                error "Detect script $DETECT_SCRIPT does not exist"
            fi
            shift; continue
            ;;
        --sigtime=*)
            SIGTIME=$(getarg "$1")
            debug "process_args(): SIGTIME set to $SIGTIME"
            shift; continue
            ;;
        --curlopts=*)
            CURLOPTS=$(getarg "$1")
            shift; continue
            ;;
# Unsupported arguments
        --detect.blackduck.signature.scanner.snippet.matching=*|--detect.blackduck.signature.scanner.upload.source.mode=*|--detect.blackduck.signature.scanner.copyright.search=*|--detect.blackduck.signature.scanner.license.search=*|--detect.binary.scan.*)
            debug "process_args(): unsupported option"
            UNSUPPORTED=1
            shift; continue
            ;;
# Arguments to be passed to detect.sh
        --blackduck.api.token=*)
            debug "process_args(): BLACKDUCK_API_TOKEN identified from command line option"
            API_TOKEN="$(getargval $1)=="
            ;;
        --blackduck.url=*)
            debug "process_args(): BLACKDUCK_URL identified from command line option"
            BD_URL=$(getargval "$1")
            ;;
        --detect.project.name=*)
            DETECT_PROJECT=1
            ;;
        --detect.project.version.name=*)
            DETECT_VERSION=1
            ;;
        --spring.profiles.active=*)
            local YML="application-$(getargval $1).yml"
            if [ ! -r $YML ]
            then
                YML=
            fi
            DETARGS="$DETARGS $(procarg $1)"
            ;;
        --blackduck.timeout=*|--detect.force.success=*|--detect.notices.report=*|--detect.policy.check.fail.on.severities=*|--detect.risk.report.pdf=*|--detect.wait.for.results=*)
            DETECT_ACTION=1
            msg "Detect Action identified - will rerun Detect after upload and scan completion"
            debug "process_args(): Identified action argument $arg"
            DETARGS="$DETARGS $(procarg $1)"
            ;;
        --detect.source.path=*)
            SCANLOC=$(getarg $1)
            SCANLOC=$(cd "$SCANLOC" 2>/dev/null; pwd)
            ;;
        --*)
            ;;
      esac
      DETARGS="$DETARGS $(procarg $1)"
      shift
done

# echo "DETARGS = '$DETARGS'"
debug "Args processed"

check_env()

if [ $UNSUPPORTED -eq 1 ]
then
    error "Unsupported Detect options specified (Snippet or Binary)"
fi

if [ -z "$API_TOKEN" -o -z "$BD_URL" ]
then
    error "No connection data for BD Server (BLACKDUCK_URL or BLACKDUCK_API_TOKEN)"
fi

TOKEN=$(get_token)

debug "Running Detect offline"

run_detect_offline
if [ $? -ne 0 ]
then
    error "Detect offline run returned an unexpected error"
fi
if [ -z "$RUNDIR" -o ! -d "$RUNDIR" ]
then
    error "Unable to determine project folder from Detect run"
fi

PREVSCANFILE="${SCANLOC}/.bdprevscan"

PREVSCANDATA=
msg "Checking for existing project version ..."
VERURL=$(get_projver "$PROJECT" "$VERSION" 0)
if [ $? -eq 0 ] && [ ! -z "$VERURL" ]
then
    PREVSCANDATA=$(get_prev_scandata $VERURL)
    if [ $? -ne 0 ]
    then
        error "prevScanData custom field does not exist in BD Server for project versions"
    fi
    if [ -z "$PREVSCANDATA" ]
    then
        msg "No previous scan data - all scans will be processed"
    else
        if [ $MODE_PREVFILE -eq 1 ]
        then
            msg "Previous scan data identified from .bdprevscan file"
        else
            msg "Previous scan data identified from prevScanData custom field"
        fi
        #echo "'$PREVSCANDATA'"
    fi
else
    msg "Project '$PROJECT' version '$VERSION' does not exist yet"
fi

UPDATE_PREVSCANDATA=0
msg "Checking for dependency scan files ..."
proc_bom_files
if [ $? -eq 0 ]
then
    proc_prev_bom_data
    compare_boms
    upload_boms
    if [ $? -ne 0 ]
    then
        error "Unable to upload BOM files"
    fi
    if [ ${#UNMATCHED_BOMS[@]} -gt 0 ]
    then
        UPDATE_PREVSCANDATA=1
    fi
else
    msg "No dependency scan files found"
fi

msg "Checking for signature scan ..."
SIGDATE=$(check_sigscan $SIGTIME)
if [ $? -eq 1 ]
then
    CLNAME=$(proc_sigscan | escape_string)
    if [ $? -ne 0 ]
    then
        msg "Unable to upload sig scan json"
    elif [ -z "$CLNAME" ]
    then
        debug "No sig scan found"
    else
        output "Signature Scan Uploaded"
        debug "Processed code location name = '$CLNAME'"
        UPDATE_PREVSCANDATA=1
    fi
else
    output "Not processing Signature scan as time since last scan not exceeded"
fi

if [ $UPDATE_PREVSCANDATA -eq 1 -a -z "$VERURL" -a $MODE_PREVFILE -eq 0 ] || [ $DETECT_ACTION -eq 1 ] || [ $MODE_REPORT -eq 1 ] || [ $MODE_MARKDOWN -eq 1 ] 
then
# Need to locate project after scan to update custom field
    msg "Checking for project version after scan"
    VERURL=$(get_projver "$PROJECT" "$VERSION" 6)
    if [ $? -ne 0 ] || [ -z "$VERURL" ]
    then
        error "Unable to locate project '$PROJECT' version '$VERSION'"
    fi
fi

RETURN=0
if [ $DETECT_ACTION -eq 1 ] || [ $MODE_REPORT -eq 1 ] || [ $MODE_MARKDOWN -eq 1 ]
then
    echo -n "detect_rescan: Waiting for BOM completion: ..."
    if [ ! -z "$CLNAME" ]
    then
        debug "Waiting for sig scan code location scan ..."
        wait_for_scans "${BD_URL}/api/codelocations?q=name:${CLNAME}"
        if [ $? -ne 0 ]
        then
            error2 "wait_for_scans() for sig scan returned error"
        fi
    fi
    debug "Waiting for version scans ..."
    wait_for_scans "${VERURL//\"}/codelocations"
    if [ $? -ne 0 ]
    then
        error2 "wait_for_scans() for version returned error"
    fi
    wait_for_bom_completion $VERURL
    if [ $? -ne 0 ]
    then
        error2 "wait_for_bom_completion() returned error"
    fi
    if [ $DETECT_ACTION -eq 1 ]
    then
        run_detect_action
        RETURN=$?
        if [ $RETURN -ne 0 ]
        then
            output "Detect returned code $RETURN"
        fi
    fi
fi

if [ $UPDATE_PREVSCANDATA -eq 1 ]
then
    msg "Updating scan data for next run ..."
    SCANFIELDURL=$(get_scandata_url $VERURL)
    update_prevscandata $SIGDATE $SCANFIELDURL
fi

if [ $MODE_REPORT -eq 1 ] || [ $MODE_MARKDOWN -eq 1 ] || [ $MODE_TESTXML -eq 1 ]
then
    run_report $VERURL
fi
cleanup
output "Done (Return code $RETURN)"

end $RETURN
