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

DETECT=$(mktemp -u)
TEMPFILE=$(mktemp -u)
LOGFILE=$(mktemp -u)

error () {
    echo "ERROR: detect_rescan.sh: $*" >$LOGFILE
    cat $LOGFILE
    end 1
}

end () {
    rm -f $TEMPFILE $DETECT $LOGFILE
    exit $1
}

prereqs() {
    ret=0
    for prog in cksum curl jq
    do
        hash $prog >/dev/null 2>&1
        if [ $? -ne 0 ]
        then
            echo ERROR: $prog program required
            ret=1
        fi
    done
    return $ret
}

prereqs
if [ $? -ne 0 ]
then
    end 1
fi

ACTION_ARGS=( "--blackduck.timeout" "--detect.force.success" "--detect.notices.report" "--detect.policy.check.fail.on.severities" "--detect.risk.report.pdf" "--detect.wait.for.results" )
API_TOKEN=$BLACKDUCK_API_TOKEN
BD_URL=$BLACKDUCK_URL
YML=
ARGS=
SCANLOC=.
DETECT_ACTION=0
DETECT_PROJECT=0
DETECT_VERSION=0
MODE_QUIET=0
MODE_REPORT=0
MARKDOWN=0
echo "detect_rescan.sh: Starting detect wrapper v1.1"

process_args() {
    prevarg=
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
            YML="application-`echo $arg | cut -f2 -d=`.yml"
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
                echo "detect_rescan.sh: Detect Action identified - will rerun Detect after upload and scan completion"
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
        elif [[ $arg == --* ]]
        then
            if [ ! -z "$prevarg" ]
            then
                ARGS="$ARGS '$prevarg'"
            fi
            prevarg=$arg
        else
            prevarg="$prevarg $arg"
        fi
        if [[ $prevarg == --detect.source.path=* ]]
        then
            SCANLOC=$(echo $prevarg | cut -f2 -d=)
            SCANLOC=$(cd $SCANLOC; pwd)
        fi
    done
    ARGS="$ARGS '$prevarg'"
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
    if [ -z "$BD_URL" -o -z "$API_TOKEN" ]
    then
        return -1
    fi
    return 0
}

process_args $*
if [ $? -ne 0 ]
then
    error "Blackduck.url or blackduck.api.token not set - unable to run detect_rescan"
fi

# echo $API_TOKEN
# echo $BD_URL
# echo ARGS=$ARGS

RUNDIR=
PROJECT=
VERSION=
SIGFOLDER=
run_detect_offline() {
    curl -s -L https://detect.synopsys.com/detect.sh > $DETECT 2>/dev/null
    if [ ! -r $DETECT ]
    then
        return -1
    fi
    chmod +x $DETECT

    if [ $MODE_QUIET -eq 0 ]
    then
        $DETECT $ARGS --detect.blackduck.signature.scanner.host.url=${BD_URL} --blackduck.offline.mode=true | tee $TEMPFILE
        RET=${PIPESTATUS[0]}
    else
        echo "detect_rescan.sh: Running Detect offline ..."
        $DETECT $ARGS --detect.blackduck.signature.scanner.host.url=${BD_URL} --blackduck.offline.mode=true >$TEMPFILE
        RET=$?
        cat $TEMPFILE >>$LOGFILE
    fi
    if [ $RET -ne 0 ]
    then
        return $RET
    fi
    if [ ! -r $TEMPFILE ]
    then
        return -1
    fi
    RUNDIR=$(grep 'Run directory: ' $TEMPFILE | sed -e 's/^.*Run directory: //g')
    PROJECT=$(grep 'Project name: ' $TEMPFILE | sed -e 's/^.*Project name: //g')
    VERSION=$(grep 'Project version: ' $TEMPFILE | sed -e 's/^.*Project version: //g')
    if [ -z "$RUNDIR" -o ! -d "$RUNDIR" -o ! -d "$RUNDIR/bdio" -o -z "$PROJECT" -o -z "$VERSION" ]
    then
        return -1
    fi
    SIGRUN=$(grep -c 'Starting the Black Duck Signature Scan' $TEMPFILE)
    if [ $SIGRUN -gt 0 ]
    then
        SIGFOLDER=$(grep 'You can view the logs at: ' $TEMPFILE | sed -e 's/^.*You can view the logs at: //g' -e "s/'//g")
    fi
    return 0
}

BOM_FILES=()
BOM_HASHES=()

proc_bom_files() {
    CWD=$(pwd)
    cd "$RUNDIR"
    if [ ! -d bdio ]
    then
        cd $CWD
        return -1
    fi
    cd bdio
    for bom in *.jsonld
    do
        if [ ! -r "$bom" ]
        then
            cd $CWD
            return -1
        fi
        CKSUM=$(cat $bom | grep -v 'spdx:created' | grep -v 'uuid:' | sort | cksum | cut -f1 -d' ')
        FILE=$(basename $bom)
        BOM_FILES+=("${FILE}")
        BOM_HASHES+=("${CKSUM}")
    done
    cd $CWD
    return 0
}

if [ -z "$API_TOKEN" -o -z "$BD_URL" ]
then
    error "No connection data for BD Server (BLACKDUCK_URL or BLACKDUCK_API_TOKEN)"
fi

curl -s -X POST --header "Authorization: token ${API_TOKEN}" --header "Accept:application/json" ${BD_URL}/api/tokens/authenticate >$TEMPFILE 2>/dev/null
TOKEN=$(cat $TEMPFILE | tr , '\n' | cut -f4 -d\")
if [ -z "$TOKEN" ]
then
    error "Cannot obtain auth token"
fi

PREVSCANFILE="$(echo ${SCANLOC}| sed -e 's/\/$//')/.bdprevscan"

PREV_FILES=()
PREV_HASHES=()
get_prev_boms() {
    if [ -r "$PREVSCANFILE" ]
    then
        while read myline
        do
            if [[ $myline == VER:* ]]
            then
                PREV_PROJ=$(echo $myline|cut -f2 -d:)
                PREV_VER=$(echo $myline|cut -f3 -d:)
                if [ "$PROJECT" != "$PREV_PROJ" -o "$VERSION" != "$PREV_VER" ]
                then
                    break
                fi
            fi
            if [[ $myline == BOM:* ]]
            then
                PREV_FILES+=($(echo $myline|cut -f2 -d:))
                PREV_HASHES+=($(echo $myline|cut -f3 -d:))
            fi
        done <"$PREVSCANFILE"
    fi
}

UNMATCHED_BOMS=()
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
        if [ $MATCHED -eq 0 ]
        then
            UNMATCHED_BOMS+=($index)
        fi
    done
}

write_prevscanfile() {
    SIGDATE=$1
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
}

upload_boms() {
    echo -n "detect_rescan.sh: BOM files - Uploading ${#UNMATCHED_BOMS[@]} out of ${#BOM_FILES[@]} total ..."
    UPLOADED=0
    FAILED=0
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
    #echo "detect_rescan.sh: - $UPLOADED Modified/New Bom Files Uploaded successfully ($FAILED Failed)"
    if [ $FAILED -gt 0 ]
    then
        return -1
    fi
    return 0
}

run_detect_action() {
    echo "detect_rescan.sh: Rerunning Detect to execute post-scan action"
    if [ $DETECT_PROJECT -eq 0 ]
    then
        ARGS="$ARGS '--detect.project.name=$PROJECT'"
    fi
    if [ $DETECT_VERSION -eq 0 ]
    then
        ARGS="$ARGS '--detect.project.version.name=$VERSION'"
    fi
    if [ $MODE_QUIET -eq 0 ]
    then
        $DETECT $ARGS --detect.tools=NONE
        RET=$?
    else
        $DETECT $ARGS --detect.tools=NONE >>$LOGFILE
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
	if [ $? -ne 0 ] || [ ! -r $TEMPFILE ]
	then
		( echo API Error:
		echo  curl -X GET --header "Authorization: Bearer $TOKEN" "$1" ) >&2
		return -1
	fi

	if [ $(grep -c totalCount $TEMPFILE) -gt 0 ]
	then 
		COUNT=$(cat $TEMPFILE | jq -r '.totalCount')
		if [ -z "$COUNT" ]
		then
			return -1
		fi
		return $COUNT
	fi
	
	return 1
}

get_project() {
    #Get  projects $1=projectname

    SEARCHPROJ=$(echo ${1} | sed -e 's:/:%2F:g' -e 's/ /+/g')
    MYURL="$BD_URL/api/projects?q=name:$SEARCHPROJ"
    api_call "$MYURL" 'application/vnd.blackducksoftware.project-detail-4+json'
    if [ $? -le 0 ]
    then
        return -1
    fi

    PROJNAMES=$(jq -r '[.items[].name]|@csv' $TEMPFILE | sed -e 's/ /+/g' -e 's/\"//g' -e 's:/:%2F:g' )
    PROJURLS=$(jq -r '[.items[]._meta.href]|@csv' $TEMPFILE | sed -e 's/ /+/g' -e 's/\"//g')

    PROJURL=
    PROJNUM=1
    FOUNDNUM=0
    IFS=,; for PROJ in $PROJNAMES
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
        return -1
    fi

    echo $PROJURLS | cut -f $FOUNDNUM -d ,
    return 0
}

get_version() {
    # Get Version
    API_URL="${1//[\"]}/versions?versionName%3A$2"
    SEARCHVERSION="${2// /_}"
    api_call "${API_URL// /%20}" 'application/vnd.blackducksoftware.project-detail-4+json'
    if [ $? -le 0 ]
    then
        return -1
    fi
    VERNAMES=($(jq -r '[.items[].versionName]|@tsv' $TEMPFILE | sed -e 's/ /_/g' -e 's/\"//g' -e 's/,//g'))
    VERURLS=$(jq -r '[.items[]._meta.href]|@tsv' $TEMPFILE)
    VERNUM=0
    FOUNDVERSIONURL=
    for URL in $VERURLS
    do
        VERNAME=${VERNAMES[$VERNUM]}
    
        if [ "$VERNAME" == "$SEARCHVERSION" ]
        then
            FOUNDVERSIONURL=$URL
            break
        fi
        ((VERNUM++))
    done

    if [ -z "$FOUNDVERSIONURL" ]
    then
        return -1
    fi

    echo $FOUNDVERSIONURL
    return 0
}

get_projver() {
# $1=projectname $2=versionname
    PURL=$(get_project "$1")
    if [ $? -lt 0 ] || [ -z "$PURL" ]
    then
        return -1
    fi

        
    VURL=$(get_version "$PURL" "$2")
    if [ $? -ne 0 ] || [ -z "$VURL" ]
    then
        return -1
    fi
  

    echo $VURL
    return 0
}

wait_for_bom_completion() {
    # Check job status
    api_call "${1//[\"]}/bom-status" 'application/vnd.blackducksoftware.internal-1+json'
    if [ $? -le 0 ]
    then
        return -1
    fi
    STATUS=$(jq -r '.upToDate' $TEMPFILE)

    loop=0
    while [ $loop -lt 80 ]
    do
        echo -n '.'
        if [ "$STATUS" == "true" ]
        then
            break
        fi
        sleep 15
        api_call "${1//[\"]}/bom-status" 'application/vnd.blackducksoftware.internal-1+json'
        if [ $? -le 0 ]
        then
            return -1
        fi
        STATUS=$(jq -r '.upToDate' $TEMPFILE)
        ((loop++))
    done
    echo
    return 0
}

wait_for_scans() {
    loop=0
    while [ $loop -gt 80 ]
    do
        echo -n '.'
        # Check scan status
        COMPLETE=1
        api_call "${1//[\"]}/codelocations" 'application/vnd.blackducksoftware.internal-1+json'
        if [ $? -le 0 ]
        then
            return -1
        fi
        STATUSES=($(jq -r '[.items[].status[].status]' ))
        index=0
        for stat in $(jq -r '[.items[].status[].operationNameCode]|@tsv' $TEMPFILE)
        do
            if [ $stat == 'ServerScanning' -a "${STATUSES[$index]}" != 'COMPLETED' ]
            then
                COMPLETE=0
            fi
            ((index++))
        done
        if [ $COMPLETE -eq 1 ]
        then
            break
        fi
    done
    return 0
}

check_sigscan() {
    DIFFTIME=$1
    SIGFOLDER=$2
    NOWDATE=`date '+%Y%m%d%H%M%S'`
    SIGDATE=$NOWDATE
    PROCSIGSCAN=0
    if [ ! -z "$SIGFOLDER" ]
    then
        if [ -r "$PREVSCANFILE" ]
        then
            while read myline
            do
                if [[ $myline == VER:* ]]
                then
                    PREV_PROJ=$(echo $myline|cut -f2 -d:)
                    PREV_VER=$(echo $myline|cut -f3 -d:)
                    if [ "$PROJECT" != "$PREV_PROJ" -o "$VERSION" != "$PREV_VER" ]
                    then
                        break
                    fi
                fi
                if [[ $myline == SIG:* ]]
                then
                    PREV_SIGSCAN_DATE=$(echo $myline|cut -f2 -d:)
                fi
            done < "$PREVSCANFILE"
            if [ ! -z "$PREV_SIGSCAN_DATE" ]
            then
                NOWDATE=$(date '+%Y%m%d%H%M%S')
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
        else
            PROCSIGSCAN=1
        fi
    fi
    echo $SIGDATE
    return $PROCSIGSCAN
}

proc_sigscan() {
    CWD=$(pwd)
    cd $SIGFOLDER
    if [ ! -d data ]
    then
        cd $CWD
        return -1
    fi
    cd data
    for sig in *.json
    do
        if [ ! -r "$sig" ]
        then
            cd $CWD
            return -1
        fi
        echo "detect_rescan.sh: Signature Scan - Uploading ..."
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
    return -1
}

cleanup() {
    if [ ! -z "$RUNDIR" ]
    then
        if [ -d "$RUNDIR/bdio" ]
        then
            rm -rf "$RUNDIR/bdio"
            #echo "detect_rescan.sh: Deleting $RUNDIR/bdio"
        fi
        if [ -d "$RUNDIR/extractions" ]
        then
            rm -rf "$RUNDIR/extractions"
            #echo "detect_rescan.sh: Deleting $RUNDIR/extractions"
        fi
        if [ -d "$RUNDIR/scan" ]
        then
            rm -rf "$RUNDIR/scan"
            #echo "detect_rescan.sh: Deleting $RUNDIR/scan"
        fi
    fi
}

run_report() {
    URL=$1
    if [ -z "$URL" ]
    then
        return -1
    fi

    api_call ${URL}/policy-status 'application/vnd.blackducksoftware.bill-of-materials-6+json'
    if [ $? -le 0 ]
    then
        return -1
    fi
    
    MARKDOWNFILE=$SCANLOC/blackduck.md

    if [ $MODE_MARKDOWN -eq 1 ]
    then
        ( echo
        echo "# BLACK DUCK OSS SUMMARY REPORT"
        echo "Project: '$PROJECT' Version: '$VERSION'"
        echo
        echo "## Component Policy Status:" ) >$MARKDOWNFILE
    fi
    if [ $MODE_REPORT -eq 1 ]
    then
        echo
        echo "----------------------------------------------------------------------"
        echo BLACK DUCK OSS SUMMARY REPORT
        echo "Project: '$PROJECT' Version: '$VERSION'"
        echo
    fi
    POL_STATUS=$(jq -r '.overallStatus' $TEMPFILE)
    if [ "$POL_STATUS" == "IN_VIOLATION" ]
    then
        POL_TYPES=($(jq -r '.componentVersionStatusCounts[].name' $TEMPFILE))
        POL_STATS=($(jq -r '.componentVersionStatusCounts[].value' $TEMPFILE))
        if [ $MODE_MARKDOWN -eq 1 ]
        then
            ( echo "| Component Policy Status | Count |"
            echo "|-------------------------|-------:|" ) >>$MARKDOWNFILE
        fi
        if [ $MODE_REPORT -eq 1 ]
        then
            echo Component Policy Status:
        fi
        for ind in ${!POL_TYPES[@]}
        do
            if [ $MODE_MARKDOWN -eq 1 ]
            then
                if [ "${POL_TYPES[$ind]}" == "IN_VIOLATION_OVERRIDDEN" ]
                then
                    echo "| In Violation Overidden | ${POL_STATS[$ind]} |" >>$MARKDOWNFILE
                elif [ "${POL_TYPES[$ind]}" == "NOT_IN_VIOLATION" ]
                then
                    echo "| Not In Violation | ${POL_STATS[$ind]} |" >>$MARKDOWNFILE
                elif [ "${POL_TYPES[$ind]}" == "IN_VIOLATION" ]
                then
                    echo "| In Violation | ${POL_STATS[$ind]} |" >>$MARKDOWNFILE
                fi
            fi
            if [ $MODE_REPORT -eq 1 ]
            then
                if [ "${POL_TYPES[$ind]}" == "IN_VIOLATION_OVERRIDDEN" ]
                then
                    echo "	- In Violation Overidden:	${POL_STATS[$ind]}"
                elif [ "${POL_TYPES[$ind]}" == "NOT_IN_VIOLATION" ]
                then
                    echo "	- Not In Violation:		${POL_STATS[$ind]}"
                elif [ "${POL_TYPES[$ind]}" == "IN_VIOLATION" ]
                then
                    echo "	- In Violation:			${POL_STATS[$ind]}"
                fi
            fi
        done
    else
        echo "No policy violations"
    fi
    
    api_call ${URL}/risk-profile
    if [ $? -le 0 ]
    then
        return -1
    fi

    VULNS=$(jq -r '.categories | [.VULNERABILITY.CRITICAL, .VULNERABILITY.HIGH, .VULNERABILITY.MEDIUM, .VULNERABILITY.LOW, .VULNERABILITY.OK] | @csv' $TEMPFILE)
    LICS=$(jq -r '.categories | [.LICENSE.HIGH, .LICENSE.MEDIUM, .LICENSE.LOW, .LICENSE.OK] | @csv' $TEMPFILE)
    OPS=$(jq -r '.categories | [.OPERATIONAL.HIGH, .OPERATIONAL.MEDIUM, .OPERATIONAL.LOW, .OPERATIONAL.OK] | @csv' $TEMPFILE)
    if [ $MODE_MARKDOWN -eq 1 ]
    then
        ( echo
        echo "## Component Risk"
        echo "| CATEGORY | CRIT | HIGH | MED | LOW | None |"
        echo "|----------|------:|-------:|------:|------:|-------:|"
        echo "| Vulnerabilities | ${VULNS//,/ | } |"
        echo "| Licenses | - | ${LICS//,/ | } |"
        echo "| Op Risk | - | ${OPS//,/ | } |"
        echo    
        echo "See the scanned Black Duck Project [here]($URL/components)" )>>$MARKDOWNFILE
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

run_detect_offline
if [ $? -ne 0 ]
then
    error "Detect returned error code"
fi
if [ -z "$RUNDIR" -o ! -d "$RUNDIR" ]
then
    error "Unable to determine project folder from Detect run"
fi

proc_bom_files
if [ $? -eq 0 ]
then
    get_prev_boms
    compare_boms
    upload_boms
    if [ $? -ne 0 ]
    then
        error "Unable to upload BOM files"
    fi
fi

SIGDATE=$(check_sigscan 86400 $SIGFOLDER)
PROCSIGSCAN=$?

if [ $PROCSIGSCAN -eq 1 ]
then
    proc_sigscan
    if [ $? -ne 0 ]
    then
        error "Unable to upload sig scan json"
    fi
else
    echo "detect_rescan.sh: Signature scan - NOT uploading as time since last scan not exceeded"
fi

RETURN=0
VERURL=
if [ $DETECT_ACTION -eq 1 ] || [ $MODE_REPORT -eq 1 ] || [ $MODE_MARKDOWN -eq 1 ]
then
    count=0
    while true
    do
        sleep 10
        VERURL=$(get_projver "$PROJECT" "$VERSION")
        if [ $? -lt 0 ]
        then
            error "Unable to locate project $PROJECT version $VERSION"
        fi
        ((count++))
        if [ $count -gt 12 ]
        then
            error "Unable to get Version URL for project"
        fi
        if [ ! -z "$VERURL" ]
        then
            break
        fi
    done

    echo -n "detect_rescan.sh: Waiting for BOM completion: ..."
    wait_for_scans $VERURL
    if [ $? -lt 0 ]
    then
        error "wait_for_scans() returned error"
    fi
    wait_for_bom_completion $VERURL
    if [ $? -lt 0 ]
    then
        error "wait_for_bom_completion() returned error"
    fi
    if [ $DETECT_ACTION -eq 1 ]
    then
        run_detect_action
        RETURN=$?
        if [ $RETURN -ne 0 ]
        then
            echo "detect_rescan.sh: Detect returned code $RETURN"
        fi
    fi
fi

write_prevscanfile $SIGDATE

if [ $MODE_REPORT -eq 1 ] || [ $MODE_MARKDOWN -eq 1 ]
then
    run_report $VERURL
fi
cleanup
echo "detect_rescan.sh: Done (Return code $RETURN)"

end $RETURN
