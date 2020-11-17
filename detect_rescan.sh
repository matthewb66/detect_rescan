#!/bin/bash

# Script to wrapper detect.sh to only upload changed bom files
#
# Description:
# 1. Extract URL & API key from options/env vars/yml files etc.
# 2. Download detect.sh
# 3. Run detect.sh with offline commands - offline scan - specify output folder
# 4. Create hashes on dependency output(s)
# 5. Check hashes against project version custom data
# 6. Upload only modified dependency scans
#
# Arguments:
#   --quiet - Quite mode - hide detect and other outputs
#   --report - Report vulnerability, license and policy counts
#   Same as detect.sh
#

output() {
    echo "detect_rescan: $*"
}

output "Starting Detect Rescan wrapper v1.4"

DETECT_TMP=$(mktemp -u)
TEMPFILE=$(mktemp -u)
TEMPFILE2=$(mktemp -u)
LOGFILE=$(mktemp -u)

ACTION_ARGS=( "--blackduck.timeout" "--detect.force.success" "--detect.notices.report" "--detect.policy.check.fail.on.severities" "--detect.risk.report.pdf" "--detect.wait.for.results" )
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
SIGTIME=86400
PREVSCANDATA=
PROJEXISTS=0
DETECT_SCRIPT=
MODE_RESET=0

BOM_FILES=()
BOM_HASHES=()
PREV_FILES=()
PREV_HASHES=()
UNMATCHED_BOMS=()

error() {
    echo "ERROR: detect_rescan: $*" >$LOGFILE
    cat $LOGFILE
    end 1
}

end() {
    rm -f $TEMPFILE $TEMPFILE2 $DETECT_TMP $LOGFILE
    exit $1
}

prereqs() {
    local ret=0
    for prog in cksum curl jq java
    do
        hash $prog >/dev/null 2>&1
        if [ $? -ne 0 ]
        then
            output "ERROR: $prog program required"
            ret=1
        fi
    done
    return $ret
}

process_args() {
    local prevarg=
    DETARGS=
    for arg in $*
    do
        if [[ $arg == --blackduck.offline.mode=* ]]
        then
            continue
        elif [[ $arg == --detect.blackduck.signature.scanner.host.url=* ]]
        then
            continue
        elif [[ $arg == --blackduck.api.token=* ]]
        then
            API_TOKEN=$(echo $arg | cut -f2 -d=)==
        elif [[ $arg == --blackduck.url=* ]]
        then
            BD_URL=$(echo $arg | cut -f2 -d=)
        elif [[ $arg == --detect.project.name=* ]]
        then
            DETECT_PROJECT=1
        elif [[ $arg == --detect.project.version.name=* ]]
        then
            DETECT_VERSION=1
        elif [[ $arg == --spring.profiles.active=* ]]
        then
            YML="application-$(echo $arg | cut -f2 -d=).yml"
            if [ ! -r $YML ]
            then
                YML=
            fi
        fi
        for opt in ${ACTION_ARGS[@]}
        do
            if [[ $arg == ${opt}* ]]
            then
                DETECT_ACTION=1
                msg "detect_rescan: Detect Action identified - will rerun Detect after upload and scan completion"
            fi
        done

        if [ "$arg" == "--report" ]
        then
            MODE_REPORT=1
        elif [ "$arg" == "--quiet" ]
        then
            MODE_QUIET=1
        elif [ "$arg" == "--markdown" ]
        then
            MODE_MARKDOWN=1
        elif [ "$arg" == "--file" ]
        then
            MODE_PREVFILE=1
        elif [ "$arg" == "--reset" ]
        then
            MODE_RESET=1
        elif [[ $arg == --detectscript=* ]]
        then
            DETECT_SCRIPT=$(echo $arg | cut -f2 -d=)
            if [ ! -r "$DETECT_SCRIPT" ]
            then
                error "Detect script $DETECT_SCRIPT does not exist"
            fi
        elif [[ $arg == --sigtime=* ]]
        then
            SIGTIME=$(echo $arg | cut -f2 -d=)
        elif [[ $arg == --* ]]
        then
            if [ ! -z "$prevarg" ]
            then
                DETARGS="$DETARGS '$prevarg'"
            fi
            prevarg=$arg
        else
            prevarg="$prevarg $arg"
        fi
        if [[ $prevarg == --detect.source.path=* ]]
        then
            SCANLOC=$(echo $prevarg | cut -f2 -d=)
            SCANLOC=$(cd "$SCANLOC" 2>/dev/null; pwd)
        fi
    done
    if [[ $prevarg == --detect.source.path=* ]]
    then
        SCANLOC=$(echo $prevarg | cut -f2 -d=)
        SCANLOC=$(cd $SCANLOC; pwd)
    fi
    DETARGS="$DETARGS '$prevarg'"
    if [ ! -z "$YML" ]
    then
        API=$(grep '^blackduck.api.token' $YML)
        if [ ! -z "API" ]
        then
            API_TOKEN=$(echo $API | cut -c2 -d' ')
        fi
        URL=$(grep '^blackduck.url' $YML)
        if [ ! -z "URL" ]
        then
            BD_URL=$(echo $URL | cut -c2 -d' ')
        fi
    fi
}

# echo $API_TOKEN
# echo $BD_URL
# echo ARGS=$ARGS

msg() {
    if [ $MODE_QUIET -eq 0 ]
    then
        output "$*"
    fi
}

get_token() {
    rm -f $TEMPFILE
    curl -s -X POST --header "Authorization: token ${API_TOKEN}" --header "Accept:application/json" ${BD_URL}/api/tokens/authenticate >$TEMPFILE 2>/dev/null
    if [ $? -ne 0 ] || [ ! -r "$TEMPFILE" ]
    then
        error "Cannot obtain auth token from BD Server"
    fi
    local TOKEN=$(jq -r '.bearerToken' $TEMPFILE 2>/dev/null)
    if [ -z "$TOKEN" ]
    then
        error "Cannot obtain auth token from BD Server"
    fi
    echo $TOKEN
}

run_detect_offline() {
    if [ -z "$DETECT_SCRIPT" ]
    then
        curl -s -L https://detect.synopsys.com/detect.sh > $DETECT_TMP 2>/dev/null
        if [ ! -r $DETECT_TMP ]
        then
            error "Unable to download detect.sh from https://detect.synopsys.com - use --detect=PATH_TO_DETECT.sh"
        fi
        chmod +x $DETECT_TMP
        DETECT_SCRIPT=$DETECT_TMP
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
    SIGRUN=$(grep -c 'Starting the Black Duck Signature Scan' $TEMPFILE)
    if [ $SIGRUN -gt 0 ]
    then
        SIGFOLDER=$(grep 'You can view the logs at: ' $TEMPFILE | sed -e 's/^.*You can view the logs at: //g' -e "s/'//g")
    fi
    return 0
}

proc_bom_files() {
    local CWD=$(pwd)
    cd "$RUNDIR"
    if [ ! -d bdio ]
    then
        cd $CWD
        return 1
    fi
    cd bdio
    for bom in *.jsonld
    do
        if [ ! -r "$bom" ]
        then
            cd $CWD
            return 1
        fi
        CKSUM=$(cat $bom | grep -v 'spdx:created' | grep -v 'uuid:' | sort | cksum | cut -f1 -d' ')
        FILE=$(basename $bom)
        BOM_FILES+=("${FILE}")
        BOM_HASHES+=("${CKSUM}")
    done
    cd $CWD
    return 0
}

proc_prev_bom_data() {
    if [ ! -z "$PREVSCANDATA" ]
    then
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
            fi
        done
        IFS=
    fi
}

compare_boms() {
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
    done
}

upload_boms() {
    echo -n "detect_rescan: BOM files - Uploading ${#UNMATCHED_BOMS[@]} out of ${#BOM_FILES[@]} total ..."
    local UPLOADED=0
    local FAILED=0
    for index in ${UNMATCHED_BOMS[@]}
    do
        echo -n '.'
        curl -s -X POST "${BD_URL}/api/scan/data/?mode=replace" \
        -H "Authorization: Bearer $TOKEN" \
        -H 'Content-Type: application/vnd.blackducksoftware.bdio+json' \
        -H 'cache-control: no-cache' \
        --data-binary "@$RUNDIR/bdio/${BOM_FILES[$index]}" >/dev/null 2>&1
        if [ $? -eq 0 ]
        then
            UPLOADED=$((UPLOADED+1))
        else
            FAILED=$((FAILED+1))
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
        ARGS="$DETARGS '--detect.project.name=$PROJECT'"
    fi
    if [ $DETECT_VERSION -eq 0 ]
    then
        ARGS="$DETARGS '--detect.project.version.name=$VERSION'"
    fi
    if [ $MODE_QUIET -eq 0 ]
    then
        $DETECT_SCRIPT $DETARGS --detect.tools=NONE
        RET=$?
    else
        $DETECT_SCRIPT $DETARGS --detect.tools=NONE >>$LOGFILE
        RET=$?
    fi
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
    curl -s -X GET --header "Authorization: Bearer $TOKEN" "$1" 2>/dev/null >$TEMPFILE
    RET=$?
    if [ $RET -ne 0 ] || [ ! -r $TEMPFILE ]
    then
        echo "API Error: Curl returned $RET" >&2
        return 1
    fi

    if [ $(grep -c 'failed authorization' $TEMPFILE) -gt 0 ]
    then 
        echo "Server or Project Authorization issue" >&2
        return 1
    fi
    if [ $(grep -c errorCode $TEMPFILE) -gt 0 ]
    then 
        echo "Other API error $(jq '.errorCode' $TEMPFILE 2>/dev/null)" >&2
        return 1
    fi
    if [ $(grep -c totalCount $TEMPFILE) -gt 0 ]
    then 
        COUNT=$(jq -r '.totalCount' $TEMPFILE 2>/dev/null)
        if [ -z "$COUNT" ]
        then
            return 1
        fi
    fi
    
    return 0
}

get_project() {
    #Get  projects $1=projectname

    #local SEARCHPROJ=$(echo ${1} | sed -e 's:/:%2F:g' -e 's/ /+/g')
    local SEARCHPROJ=$(echo ${1} | sed -e 's:/:%2F:g' -e 's/ /%20/g')
    local MYURL="${BD_URL}/api/projects?q=name:${SEARCHPROJ}"
    api_call "$MYURL" 'application/vnd.blackducksoftware.project-detail-4+json'
    if [ $? -ne 0 ]
    then
        return 1
    fi

    local PROJNAMES=$(jq -r '[.items[].name]|@csv' $TEMPFILE 2>/dev/null| sed -e 's/ /%20/g' -e 's/\"//g' -e 's:/:%2F:g')
    local PROJURLS=$(jq -r '[.items[]._meta.href]|@csv' $TEMPFILE 2>/dev/null| sed -e 's/\"//g')

    local PROJNUM=1
    local FOUNDNUM=0
    local IFS=,
    for PROJ in $PROJNAMES
    do
        if [ "$PROJ" == "$SEARCHPROJ" ]
        then
            FOUNDNUM=$PROJNUM
            break
        fi
        ((PROJNUM++))
    done
    IFS=

    if [ $FOUNDNUM -eq 0 ]
    then
        return 0
    fi

    echo $PROJURLS | cut -f $FOUNDNUM -d ,
    return 0
}

get_version() {
    # Get Version  - $1 = PROJURL
    local VERNAME=$(echo $2 | sed -e 's:/:%2F:g' -e 's/ /%20/g')
    local API_URL="${1//\"}/versions?versionName%3A${VERNAME}"
    #local SEARCHVERSION="${2// /_}"
    #echo "get_version: SEARCHVERSION=$SEARCHVERSION" >&2
    api_call "${API_URL}" 'application/vnd.blackducksoftware.project-detail-4+json'
    if [ $? -ne 0 ]
    then
        return 1
    fi

    local VERNAMES=$(jq -r '[.items[].versionName]|@csv' $TEMPFILE 2>/dev/null | sed -e 's/ /%20/g' -e 's/\"//g' -e 's:/:%2F:g')
    local VERURLS=$(jq -r '[.items[]._meta.href]|@csv' $TEMPFILE 2>/dev/null | sed -e 's/\"//g')
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
        return 0
    fi

    echo $VERURLS | cut -f $FOUNDVERNUM -d ,
    return 0
}

get_projver() {
# $1=projectname $2=versionname $3=number_of_10_sec_loops
    local NUMLOOPS=${3:-0}
    local COUNT=0
    while [ $COUNT -le $NUMLOOPS ]
    do
        PURL=$(get_project "$1")
        if [ $? -ne 0 ]
        then
            return 1
        fi
        #echo "get_projver: PURL=$PURL" >&2
        if [ ! -z "$PURL" ]
        then
            VURL=$(get_version "$PURL" "$2")
            if [ $? -ne 0 ]
            then
                return 1
            fi
            #echo "get_projver: VURL=$VURL" >&2
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
    return 0
}

wait_for_bom_completion() {
    # Check job status
    local loop=0
    while [ $loop -lt 80 ]
    do
        api_call "${1//\"}/bom-status" 'application/vnd.blackducksoftware.internal-1+json'
        if [ $? -ne 0 ]
        then
            return 1
        fi
        local STATUS=$(jq -r '.upToDate' $TEMPFILE 2>/dev/null)

        if [ "$STATUS" == "true" ]
        then
            break
        fi
        echo -n '.'
        sleep 15
        ((loop++))
    done
    echo
    return 0
}

wait_for_scans() {
    local loop=0
    while [ $loop -lt 80 ]
    do
        # Check scan status
        api_call "${1//\"}/codelocations" 'application/vnd.blackducksoftware.internal-1+json'
        if [ $? -ne 0 ]
        then
            return 1
        fi
        local STATUSES=$(jq -r '[.items[].status[].status]|@csv' $TEMPFILE 2>/dev/null)
        local OPCODES=$(jq -r '[.items[].status[].operationNameCode]|@csv' $TEMPFILE 2>/dev/null)
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
            return 0
        fi
        ((loop++))
        echo -n '.'
        sleep 15
    done
    return 0
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

    echo $SIGDATE
    return $PROCSIGSCAN
}

proc_sigscan() {
    local CWD=$(pwd)
    cd $SIGFOLDER
    if [ ! -d data ]
    then
        cd $CWD
        return 1
    fi
    cd data
    for sig in *.json
    do
        if [ ! -r "$sig" ]
        then
            cd $CWD
            return 1
        fi
        output "Signature Scan - Uploading ..."
        curl -s -X POST "${BD_URL}/api/scan/data/?mode=replace" \
        -H "Authorization: Bearer $TOKEN" \
        -H 'Content-Type: application/ld+json' \
        -H 'cache-control: no-cache' \
        --data-binary "@$sig" >/dev/null 2>&1
        RET=$?
        cd $CWD
        return $RET
    done
    cd $CWD
    return 1
}

cleanup() {
return
    if [ ! -z "$RUNDIR" ]
    then
        if [ -d "$RUNDIR/bdio" ]
        then
            rm -rf "$RUNDIR/bdio"
            msg "detect_rescan: Deleting $RUNDIR/bdio"
        fi
        if [ -d "$RUNDIR/extractions" ]
        then
            rm -rf "$RUNDIR/extractions"
            msg "detect_rescan: Deleting $RUNDIR/extractions"
        fi
        if [ -d "$RUNDIR/scan" ]
        then
            rm -rf "$RUNDIR/scan"
            msg "detect_rescan: Deleting $RUNDIR/scan"
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
    POL_STATUS=$(jq -r '.overallStatus' $TEMPFILE 2>/dev/null)
    if [ "$POL_STATUS" == "IN_VIOLATION" ]
    then
        POL_TYPES=$(jq -r '.componentVersionStatusCounts[].name' $TEMPFILE 2>/dev/null | tr '\n' ',')
        POL_STATS=$(jq -r '.componentVersionStatusCounts[].value' $TEMPFILE 2>/dev/null | tr '\n' ',')
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
        IFS=,
        INDEX=1
        for type in ${POL_TYPES}
        do
            IFS=
            if [ $MODE_MARKDOWN -eq 1 ]
            then
                if [ "$type" == "IN_VIOLATION_OVERRIDDEN" ]
                then
                    echo "| In Violation Overidden | [$(echo $POL_STATS | cut -f$INDEX -d,)]($URL/components?filter=bomPolicy%3Ain_violation_overridden) |" >>$MARKDOWNFILE
                elif [ "$type" == "NOT_IN_VIOLATION" ]
                then
                    echo "| Not In Violation | $(echo $POL_STATS | cut -f$INDEX -d,) |" >>$MARKDOWNFILE
                elif [ "$type" == "IN_VIOLATION" ]
                then
                    echo "| In Violation | [$(echo $POL_STATS | cut -f$INDEX -d,)]($URL/components?filter=bomPolicy%3Ain_violation) |" >>$MARKDOWNFILE
                fi
            fi
            if [ $MODE_REPORT -eq 1 ]
            then
                if [ "$type" == "IN_VIOLATION_OVERRIDDEN" ]
                then
                    echo "  - In Violation Overidden:	$(echo $POL_STATS | cut -f$INDEX -d,)"
                elif [ "$type" == "NOT_IN_VIOLATION" ]
                then
                    echo "  - Not In Violation:		$(echo $POL_STATS | cut -f$INDEX -d,)"
                elif [ "$type" == "IN_VIOLATION" ]
                then
                    echo "  - In Violation:		$(echo $POL_STATS | cut -f$INDEX -d,)"
                fi
            fi
            ((INDEX++))
        done
        
        echo
        echo "Components in Violation:"
        api_call "${URL}/components?limit=5000" 'application/vnd.blackducksoftware.bill-of-materials-4+json'
        if [ $? -ne 0 ]
        then
            return 1
        fi
    
        rm -f $TEMPFILE2
        jq -r '.items[].componentName' $TEMPFILE 2>/dev/null >$TEMPFILE2
        local COMPPOLS=$(jq -r '.items[].policyStatus' $TEMPFILE 2>/dev/null | tr '\n' ',')
        local COMPVERS=$(jq -r '.items[].componentVersionName' $TEMPFILE 2>/dev/null | tr '\n' '|')
        local COMPURLS=$(jq -r '.items[]._meta.href' $TEMPFILE 2>/dev/null | tr '\n' ',')
        local INDEX=1
        while read comp
        do
            COMPPOL=$(echo $COMPPOLS | cut -f$INDEX -d,)
            COMPURL=$(echo $COMPURLS | cut -f$INDEX -d,)
            if [ "$COMPPOL" == "IN_VIOLATION" ]
            then
                if [ $MODE_REPORT -eq 1 ]
                then
                    echo -n "	Component: '$comp/$(echo $COMPVERS|cut -f$INDEX -d'|')' Policies Violated: "
                fi
                api_call ${COMPURL}/policy-rules
                if [ $? -ne 0 ]
                then
                    continue
                fi
            
                POLNAMES=$(jq -r '.items[].name' $TEMPFILE 2>/dev/null | tr '\n' '|')
                POLSEVERITIES=$(jq -r '.items[].severity' $TEMPFILE 2>/dev/null | tr '\n' ',')
                IFS='|'
                sevind=1
                for polname in $POLNAMES
                do
                    if [ $MODE_REPORT -eq 1 ]
                    then
                        echo -n "'$polname' ($(echo $POLSEVERITIES|cut -f$sevind -d,)) "
                    fi
                    ((sevind++))
                done
                echo
                IFS=
            fi
            ((INDEX++))
        done <$TEMPFILE2
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

    VULNS=$(jq -r '.categories | [.VULNERABILITY.CRITICAL, .VULNERABILITY.HIGH, .VULNERABILITY.MEDIUM, .VULNERABILITY.LOW, .VULNERABILITY.OK] | @csv' $TEMPFILE 2>/dev/null)
    LICS=$(jq -r '.categories | [.LICENSE.HIGH, .LICENSE.MEDIUM, .LICENSE.LOW, .LICENSE.OK] | @csv' $TEMPFILE 2>/dev/null)
    OPS=$(jq -r '.categories | [.OPERATIONAL.HIGH, .OPERATIONAL.MEDIUM, .OPERATIONAL.LOW, .OPERATIONAL.OK] | @csv' $TEMPFILE 2>/dev/null)
    if [ $MODE_MARKDOWN -eq 1 ]
    then
        NEWVULNS=$(echo $VULNS | sed -e 's/^/\[/' -e 's!,!\]('${URL}'/components?filter=securityRisk%3Acritical);\[!' -e 's!,!\]('${URL}'/components?filter=securityRisk%3Ahigh);\[!' -e 's!,!\]('${URL}'/components?filter=securityRisk%3Amedium);\[!' -e 's!,!\]('${URL}'/components?filter=securityRisk%3Alow);!')
        NEWLICS=$(echo $LICS | sed -e 's/^/\[/' -e 's!,!\]('${URL}'/components?filter=licenseRisk%3Ahigh);\[!' -e 's!,!\]('${URL}'/components?filter=licenseRisk%3Amedium);\[!' -e 's!,!\]('${URL}'/components?filter=licenseRisk%3Alow);!')
        NEWOPS=$(echo $OPS | sed -e 's/^/\[/' -e 's!,!\]('${URL}'/components?filter=operationalRisk%3Ahigh);\[!' -e 's!,!\]('${URL}'/components?filter=operationalRisk%3Amedium);\[!' -e 's!,!\]('${URL}'/components?filter=operationalRisk%3Alow);!')

        ( echo
        echo "## Component Risk"
        echo "| CATEGORY | CRIT | HIGH | MED | LOW | None |"
        echo "|----------|------:|-------:|------:|------:|-------:|"
        echo "| Vulnerabilities | ${NEWVULNS//;/ | } |"
        echo "| Licenses | - | ${NEWLICS//;/ | } |"
        echo "| Op Risk | - | ${NEWOPS//;/ | } |"
        echo )>>$MARKDOWNFILE
    fi
    if [ $MODE_REPORT -eq 1 ]
    then
        (echo
        echo "Component Risk:			CRIT	HIGH	MED 	LOW 	None"
        echo "				----	----	--- 	--- 	----"
        echo "	Vulnerabilities,,${VULNS}"
        echo "	Licenses,,-,${LICS}"
        echo "	Op Risk,,,-,${OPS}"
        echo ) | sed -e 's/,/	/g' 
    
        echo "See Black Duck Project at:"
        echo "$URL/components"
        echo 
        echo "----------------------------------------------------------------------"
    fi

}

get_prev_scandata() {
    if [ $MODE_PREVFILE -eq 0 ]
    then
        local VURL=$1
        api_call $VURL/custom-fields 'application/vnd.blackducksoftware.project-detail-5+json'
        if [ $? -ne 0 ]
        then
            return 1
        fi

        local FIELDS=$(jq -r '[.items[].label]|@csv' $TEMPFILE 2>/dev/null)
        local DATAS=$(jq -r '[.items[].values[0]]|@csv' $TEMPFILE 2>/dev/null)
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
                return 0
            fi
            ((FNUM++))
        done
        IFS=
    else
        if [ -r "$PREVSCANFILE" ]
        then
            cat "$PREVSCANFILE" | tr '\n' '|'
        fi
        return 0
    fi
    return 1
}

update_prevscandata() {
    local URL=${2//\"}
    local SIGDATE=$1
    if [ $MODE_PREVFILE -eq 1 ]
    then
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
            msg "Unable to write scan data to $PREVSCANFILE"
        else
            msg "Scan data stored in file $PREVSCANFILE"
        fi
    elif [ ! -z "$URL" ]
    then
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
        curl -s -X PUT --header "Authorization: Bearer $TOKEN" --header "Content-Type: application/vnd.blackducksoftware.project-detail-5+json" --header "Accept: application/vnd.blackducksoftware.project-detail-5+json" -d "$VAL" $URL >$TEMPFILE 2>&1 
        if [ $? -ne 0 ]
        then
            error "Unable to write scan data to Project Version custom field"
        fi
        local STATUS=$(jq '.errorMessage' $TEMPFILE 2>/dev/null)
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
        return 1
    fi

    local FIELDS=$(jq -r '[.items[].label]|@csv' $TEMPFILE 2>/dev/null)
    local URLS=$(jq -r '[.items[]._meta.href]|@csv' $TEMPFILE 2>/dev/null)
    local FNUM=1
    local IFS=,
    for FIELD in $FIELDS
    do
        if [ $FIELD == '"prevScanData"' ]
        then
            IFS=
            echo $URLS | cut -f$FNUM -d,
            return 0
        fi
        ((FNUM++))
    done
    IFS=
    return 1
}

##########################################################################################
# MAIN LOGIC

prereqs
if [ $? -ne 0 ]
then
    end 1
fi

process_args $*
if [ -z "$API_TOKEN" -o -z "$BD_URL" ]
then
    error "No connection data for BD Server (BLACKDUCK_URL or BLACKDUCK_API_TOKEN)"
fi

TOKEN=$(get_token)

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
    proc_sigscan
    if [ $? -ne 0 ]
    then
        error "Unable to upload sig scan json"
    fi
    UPDATE_PREVSCANDATA=1
else
    output "Not uploading Signature scan as time since last scan not exceeded"
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
    wait_for_scans $VERURL
    if [ $? -ne 0 ]
    then
        error "wait_for_scans() returned error"
    fi
    wait_for_bom_completion $VERURL
    if [ $? -ne 0 ]
    then
        error "wait_for_bom_completion() returned error"
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

if [ $MODE_REPORT -eq 1 ] || [ $MODE_MARKDOWN -eq 1 ]
then
    run_report $VERURL
fi
cleanup
output "Done (Return code $RETURN)"

end $RETURN
