adb shell "cd /system/xbin/;  /system/xbin/pcapcovert"

adb pull /system/xbin/capture.pcap
adb pull /system/xbin/captures.pcap
adb pull /system/xbin/sslkeys.txt
adb pull /system/xbin/ip_key.dat
adb shell "rm /system/xbin/ip_key.dat"

pause