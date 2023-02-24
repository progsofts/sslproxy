copy \\wsl$\Friendlywrt\root\Android\sslproxy\libs\arm64-v8a\sslproxy sslproxy
copy \\wsl$\Friendlywrt\root\Android\sslproxy\libs\arm64-v8a\pcapcovert pcapcovert
adb remount
adb push sslproxy /system/xbin/sslproxy
adb shell "chmod 777 /system/xbin/sslproxy"
adb push pcapcovert /system/xbin/pcapcovert
adb shell "chmod 777 /system/xbin/pcapcovert"

:::::adb shell "iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner 10023 --sport 32768:61000 --dport 443 -j DNAT --to 127.0.0.1:8888"
pause
