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
#   Same as detect.sh
#

DETECT=$(mktemp -u)
TEMPFILE=$(mktemp -u)

error () {
	echo "ERROR: detect_rescan.sh: $*"
	end 1
}

end () {
	rm -f $TEMPFILE $DETECT
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

echo "detect_rescan.sh: Starting detect wrapper v1.0"

process_args() {
    prevarg=
    for arg in $*
    do
        if [[ $arg == --blackduck.offline.mode=* ]]
        then
            continue
        fi
        if [[ $arg == --blackduck.api.token=* ]]
        then
            API_TOKEN=`echo $arg | cut -f2 -d=`==
        fi
        if [[ $arg == --blackduck.url=* ]]
        then
            BD_URL=`echo $arg | cut -f2 -d=`
        fi
        if [[ $arg == --detect.project.name=* ]]
        then
            DETECT_PROJECT=1
        fi
        if [[ $arg == --detect.project.version.name=* ]]
        then
            DETECT_VERSION=1
        fi
        if [[ $arg == --spring.profiles.active=* ]]
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
        if [[ $arg == --* ]]
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
            SCANLOC=""`echo $prevarg | cut -f2 -d=`""
        fi
    done
    ARGS="$ARGS '$prevarg'"
    if [ ! -z "$YML" ]
    then
        API="`grep '^blackduck.api.token' $YML`"
        if [ ! -z "API" ]
        then
            API_TOKEN="`echo $API | cut -c2 -d' '`"
        fi
        URL="`grep '^blackduck.url' $YML`"
        if [ ! -z "URL" ]
        then
            BD_URL="`echo $URL | cut -c2 -d' '`"
        fi
    fi
}

process_args $*

# echo $API_TOKEN
# echo $BD_URL
# echo ARGS=$ARGS

RUNDIR=
PROJECT=
VERSION=
SIGFOLDER=
run_detect_offline() {
    echo
    curl -s -L https://detect.synopsys.com/detect.sh > $DETECT
    if [ ! -r $DETECT ]
    then
        return -1
    fi
    chmod +x $DETECT

    $DETECT $ARGS --blackduck.offline.mode=true | tee $TEMPFILE
    RET=${PIPESTATUS[0]}
    if [ $RET -ne 0 ]
    then
        return $RET
    fi
    if [ ! -r $TEMPFILE ]
    then
        return -1
    fi
    RUNDIR="`grep 'Run directory: ' $TEMPFILE | sed -e 's/^.*Run directory: //g'`"
    PROJECT="`grep 'Project name: ' $TEMPFILE | sed -e 's/^.*Project name: //g'`"
    VERSION="`grep 'Project version: ' $TEMPFILE | sed -e 's/^.*Project version: //g'`"
    if [ -z "$RUNDIR" -o ! -d "$RUNDIR" -o ! -d "$RUNDIR/bdio" -o -z "$PROJECT" -o -z "$VERSION" ]
    then
        return -1
    fi
    SIGRUN=`grep -c 'Starting the Black Duck Signature Scan' $TEMPFILE`
    if [ $SIGRUN -gt 0 ]
    then
        SIGFOLDER=`grep 'You can view the logs at: ' $TEMPFILE | sed -e 's/^.*You can view the logs at: //g' -e "s/\'//g"`
    fi
    return 0
}

BOM_FILES=()
BOM_HASHES=()
proc_bom_files() {
    if stat --printf='' $RUNDIR/bdio/*.jsonld 2>/dev/null
    then
        return -1
    fi
    for bom in $RUNDIR/bdio/*.jsonld
    do
        CKSUM=`cat $bom | grep -v 'spdx:created' | grep -v 'uuid:' | cksum | cut -f1 -d' '`
        FILE="`basename $bom`"
        BOM_FILES+=("${FILE}")
        BOM_HASHES+=("${CKSUM}")
    done
    return 0
}

if [ -z "$API_TOKEN" -o -z "$BD_URL" ]
then
    error "No connection data for BD Server (BLACKDUCK_URL or BLACKDUCK_API_TOKEN)"
fi

curl -X POST --header "Authorization: token ${API_TOKEN}" --header "Accept:application/json" ${BD_URL}/api/tokens/authenticate >$TEMPFILE 2>/dev/null
TOKEN=`cat $TEMPFILE | tr , '\n' | cut -f4 -d\"`
if [ -z "$TOKEN" ]
then
    error "Cannot obtain auth token"
fi

PREVSCANFILE="$SCANLOC/.bdprevscan"

PREV_FILES=()
PREV_HASHES=()
get_prev_boms() {
    if [ -r "$PREVSCANFILE" ]
    then
        while read myline
        do
            if [[ $myline == VER:* ]]
            then
                PREV_PROJ="`echo $myline|cut -f2 -d:`"
                PREV_VER="`echo $myline|cut -f3 -d:`"
                if [ "$PROJECT" != "$PREV_PROJ" -o "$VERSION" != "$PREV_VER" ]
                then
                    break
                fi
            fi
            if [[ $myline == BOM:* ]]
            then
                PREV_FILES+=("`echo $myline|cut -f2 -d:`")
                PREV_HASHES+=("`echo $myline|cut -f3 -d:`")
            fi
        done < "$PREVSCANFILE"
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
    rm -f "$PREVSCANFILE"
    ( echo "VER:$PROJECT:$VERSION"
    for index in ${!BOM_FILES[@]}
    do
        echo "BOM:${BOM_FILES[$index]}:${BOM_HASHES[$index]}"
    done
    if [ ! -z "$SIGDATE" ]
    then
        echo "SIG:$SIGDATE"
    fi ) > "$PREVSCANFILE"
    
}

upload_boms() {
    echo
    echo -n "detect_rescan.sh: Uploading Bom files ..."
    UPLOADED=0
    FAILED=0
    for index in ${UNMATCHED_BOMS[@]}
    do
        echo -n '.'
        curl $CURLOPTS -X POST "${BD_URL}/api/scan/data/?mode=replace" \
        -H "Authorization: Bearer $TOKEN" \
        -H 'Content-Type: application/vnd.blackducksoftware.bdio+json' \
        -H 'cache-control: no-cache' \
        --data-binary "@$RUNDIR/bdio/${BOM_FILES[$index]}"
        if [ $? -eq 0 ]
        then
            UPLOADED=$((UPLOADED+1))
        else
            FAILED=$((FAILED+1))
        fi
    done
    echo
    echo "detect_rescan.sh: ${#UNMATCHED_BOMS[@]} Modified Bom Files to Upload: $UPLOADED Uploaded - $FAILED Failed"
    echo
}

run_detect_action() {
    echo
    echo "detect_rescan.sh: Rerunning Detect to execute action or wait for project"
    if [ $DETECT_PROJECT -eq 0 ]
    then
        ARGS="$ARGS '--detect.project.name=$PROJECT'"
    fi
    if [ $DETECT_VERSION -eq 0 ]
    then
        ARGS="$ARGS '--detect.project.version.name=$VERSION'"
    fi
    $DETECT $ARGS --detect.tools=NONE
    RET=${PIPESTATUS[0]}
    if [ $RET -ne 0 ]
    then
        return $RET
    fi
}

api_call() {
    if [ -z "$2" ]
    then
        HEADER="application/json"
    else
        HEADER="$2"
    fi
	rm -f $TEMPFILE
	curl -X GET --header "Authorization: Bearer $TOKEN" --header "Accept:$HEADER" "$1" 2>/dev/null >$TEMPFILE
	if [ $? -ne 0 ] || [ ! -r $TEMPFILE ]
	then
		( echo API Error:
		echo  curl -X GET --header "Authorization: Bearer $TOKEN" --header "Accept:$HEADER" "$1" ) >&2
		return -1
	fi
    COUNT=`cat $TEMPFILE | tr , '\n' | grep 'totalCount' | cut -f2 -d:`
	if [ -z "$COUNT" ]
	then
		return -1
	fi

	return $COUNT
}

get_project() {
	#Get  projects
	SEARCHPROJ="${1// /+}"
	api_call "$BD_URL/api/projects?q=name:$SEARCHPROJ" 'application/vnd.blackducksoftware.project-detail-4+json'
	if [ $? -le 0 ]
	then
		return -1
	fi

	FOUND=false
	SEARCHPROJ="${1// /_}"
	PROJNAMES="`jq -r '[.items[].name]|@tsv' $TEMPFILE | sed -e 's/ /_/g' -e 's/\"//g' -e 's/,//g'`"
	PROJURLS=(`jq -r '[.items[]._meta.href]|@tsv' $TEMPFILE | sed -e 's/ /_/g' -e 's/\"//g' -e 's/,//g'`)
	PROJURL=
	PROJNUM=0
	for PROJ in $PROJNAMES
	do
#		echo DEBUG: PROJ=$PROJ SEARCHPROJ=$SEARCHPROJ >&2
		if [ "$PROJ" == "$SEARCHPROJ" ]
		then
			FOUND=true
			PROJURL="${PROJURLS[$PROJNUM]}"
			break
		fi
		((PROJNUM++))
	done

	if [ $FOUND == false ]
	then
		return -1
	fi

	echo "detect_rescan.sh: Project '$PROJ' found ..." >&2
	echo $PROJURL
	return 0
}

get_version() {
	# Get Version
	api_call "${1//[\"]}/versions" 'application/vnd.blackducksoftware.project-detail-4+json'
	if [ $? -le 0 ]
	then
		return -1
	fi
	
	SEARCHVERSION="${2// /_}"
	VERNAMES=(`jq -r '[.items[].versionName]|@tsv' $TEMPFILE | sed -e 's/ /_/g' -e 's/\"//g' -e 's/,//g'`)
	VERURLS="`jq -r '[.items[]._meta.href]|@tsv' $TEMPFILE`"
	VERNUM=0
	local FOUNDVERSIONURL=
	for VERURL in $VERURLS
	do
		VERNAME=${VERNAMES[$VERNUM]}
	
		if [ "$VERNAME" == "$SEARCHVERSION" ]
		then
			FOUNDVERSIONURL=$VERURL
			break 2
		fi
		((VERNUM++))
	done

	if [ -z "$FOUNDVERSIONURL" ]
	then
		return -1
	fi

	echo "detect_rescan.sh: Version '$VERSION' found ..." >&2
	echo $FOUNDVERSIONURL
	return 0
}

get_projver() {
	PROJURL=$(get_project "$1")
	if [ $? -lt 0 ]
	then
		return -1
	fi
		
	VERURL=$(get_version "$PROJURL" "$2")
	if [ $? -ne 0 ]
	then
		return -1
	fi
	
	echo $VERURL
	return 0
}

wait_for_bom_completion() {
    # Check job status
    api_call "${1//[\"]}/bom-status" 'application/vnd.blackducksoftware.internal-1+json'
    if [ $? -le 0 ]
    then
        return -1
    fi
    STATUS="`jq -r '.upToDate' $TEMPFILE`"

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
        STATUS="`jq -r '.upToDate' $TEMPFILE`"
        ((loop++))
    done
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
        STATUSES=(`jq -r '[.items[].status[].status]' `)
        index=0
        for stat in `jq -r '[.items[].status[].operationNameCode]|@tsv' $TEMPFILE`
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
                    PREV_PROJ="`echo $myline|cut -f2 -d:`"
                    PREV_VER="`echo $myline|cut -f3 -d:`"
                    if [ "$PROJECT" != "$PREV_PROJ" -o "$VERSION" != "$PREV_VER" ]
                    then
                        break
                    fi
                fi
                if [[ $myline == SIG:* ]]
                then
                    PREV_SIGSCAN_DATE="`echo $myline|cut -f2 -d:`"
                fi
            done < "$PREVSCANFILE"
            if [ ! -z "$PREV_SIGSCAN_DATE" ]
            then
                NOWDATE=`date '+%Y%m%d%H%M%S'`
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
    echo
    echo "detect_rescan.sh: Uploading Sig scan ..."
    if stat --printf='' $SIGFOLDER/data/*.json 2>/dev/null
    then
        for sigfile in $SIGFOLDER/data/*.json
        do
            curl $CURLOPTS -X POST "${BD_URL}/api/scan/data/?mode=replace" \
            -H "Authorization: Bearer $TOKEN" \
            -H 'Content-Type: application/ld+json' \
            -H 'cache-control: no-cache' \
            --data-binary "@$sigfile"
            return $?
        done
    fi
    return 0
}

cleanup() {
    if [ ! -z "$RUNDIR" ]
    then
        if [ -d "$RUNDIR/bdio" ]
        then
            rm -rf "$RUNDIR/bdio"
            echo "detect_rescan.sh: Deleting $RUNDIR/bdio"
        fi
        if [ -d "$RUNDIR/extractions" ]
        then
            rm -rf "$RUNDIR/extractions"
            echo "detect_rescan.sh: Deleting $RUNDIR/extractions"
        fi
        if [ -d "$RUNDIR/scan" ]
        then
            rm -rf "$RUNDIR/scan"
            echo "detect_rescan.sh: Deleting $RUNDIR/scan"
        fi
    fi
}

run_detect_offline
if [ $? -ne 0 ]
then
    error "Detect returned error code"
fi

proc_bom_files
if [ $? -eq 0 ]
then
    get_prev_boms
    compare_boms
    upload_boms
fi

SIGDATE=`check_sigscan 86400 $SIGFOLDER`
PROCSIGSCAN=$?

if [ $PROCSIGSCAN -eq 1 ]
then
    proc_sigscan
    if [ $? -ne 0 ]
    then
        error "Unable to upload sig scan json"
    fi
else
    echo
    echo "detect_rescan.sh: NOT uploading sig scan as time since last scan not exceeded"
fi

if [ $DETECT_ACTION -eq 1 ]
then
    VERURL=$(get_projver "$PROJECT" "$VERSION")
    if [ $? -lt 0 ]
    then
        error "Unable to locate project $PROJECT version $VERSION"
    fi
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
    echo
    run_detect_action 
fi

write_prevscanfile $SIGDATE

cleanup
echo "detect_rescan.sh: Done"
end 0
