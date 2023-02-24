start adb shell "kill -9 $(lsof |grep :8888 | awk '{print $2}')"
pause

start adb shell "sslproxy"
start adb shell "tcpdump -i any -w /system/xbin/capture.pcap -vv"