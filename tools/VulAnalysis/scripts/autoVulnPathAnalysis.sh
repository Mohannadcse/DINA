#!/bin/bash
: '
	the location of senderApps, receiverApps and file (where is the CSV file that contains a set of vulnerable paths) should be defined 
	before running this script	
'


senderApps=
receiverApps=
pairNo=1
mkdir logcat
#Read the vuln_paths.CSV file and extract: S_App(1), ref_DCL_CN(3), D_App(14)
file=`cat vuln_paths.csv | tail -n +2`

#Go over records in the file
for f in $file
do
	S_App=`echo $f | cut -d ',' -f1`
	pkgName=`echo $f | cut -d ',' -f2`
	ref_DCL_CN=`echo $f | cut -d ',' -f3 | sed 's/\//./g' | sed 's/;//' | sed 's/L//'`
	ref_type=`echo $f | cut -d ',' -f4`
	D_App=`echo $f | cut -d ',' -f14`
	strAct=`echo $f | cut -d ',' -f16`
	echo $S_App, $ref_DCL_CN, $D_App


	#Install sender and receiver Apps then check if both apps have been installed
	snd_flag=1
	rec_flag=1

	#sender app
	adb shell pm list packages -3 | awk -F ":" '{print $2}' > output/beforeInstall.txt
	echo Install Sender App "$S_App"...
	adb install $senderApps/$S_App
	adb shell pm list packages -3 | awk -F ":" '{print $2}' > output/afterInstall.txt
	if diff output/beforeInstall.txt output/afterInstall.txt > /dev/null ; then
	    echo App has not been installed
	    snd_flag=0
	else
		echo Sender App has been installed


	#reciever app
	adb shell pm list packages -3 | awk -F ":" '{print $2}' > output/beforeInstall.txt
	echo Install Sender App "$D_App"...
	adb install $receiverApps/$D_App
	adb shell pm list packages -3 | awk -F ":" '{print $2}' > output/afterInstall.txt
	if diff output/beforeInstall.txt output/afterInstall.txt > /dev/null ; then
	    echo App has not been installed
	    rec_flag=0
	else
		echo Receiver App has been installed

	echo "$pairNo,$S_App,$snd_flag,$D_App,$rec_flag,$strAct" >> installationReport.csv


	#If yes, then run the ref_DCL_CN of the sender app
	if (( $snd_flag == 1 && $rec_flag == 1 )); then
		#run the component
		if [ $ref_type == "ActivityComponent" ]; then
			adb shell am start -S -n $pkgName/$ref_DCL_CN
		fi
		
		#Record adb log
		adb logcat | grep -F "`adb shell ps | grep $pkgName  | tr -s [:space:] ' ' | cut -d' ' -f2`" > logcat/$pairNo.txt

		#Uninstall both apps
		gtimeout 40 adb shell pm uninstall $pkgName
		gtimeout 40 adb shell pm uninstall $D_App
	fi

	if (( $snd_flag == 1 )); then
		gtimeout 40 adb shell pm uninstall $pkgName
	fi

	if (( $rec_flag == 1 )); then
		gtimeout 40 adb shell pm uninstall $D_App
	fi

	pairNo=$((pairNo+1))

done
