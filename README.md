
&nbsp;
<h3 align="center">EXYNEX</h3>

<p align="center">
  cli tool for static and dynamic analysis of android apk. 
</p>

</p>

<hr />

<p align="center">
<a target="_blank" href="LICENSE"><img src="https://github.com/vmprog/exynex/blob/exynex_dev/badges/pylint.svg"></a>
</p>

<p>This command line utility allows you to perform static and dynamic analysis of android apk files.</p>

<p>Static analysis allows you to obtain the following data:</p>

- Application name
- App package
- App version
- Version code
- APK checksum
	- android_id
	- advertising_id
	- imei
	- google_account
	- wifi_ssid
	- geo: (latitude, longitude)
- urls - strings that look like URLs
- domains - strings that look like domain names
- libraries - list of .so libraries from the APK
- classes - list of Java/Kotlin classes from the binary
- permissions - set of permissions from the app manifest
- activities - list of registered activities from the app manifest
		
<p>Dynamic analysis allows you to obtain the following data:</p>

- network_activity:
	- requests
		- timestamp - Time from the app startup (ms)
		- proto (HTTP/TLS/TCP/UDP)
		- remote_ip
		- tls_sni
		- http_request_url
		- http_request_method
		- http_request_body_length
		- http_response_status
		- http_response_body_length
		
	- requested_permissions

* [Getting Started](#getting-started)
	* [Prerequisites for Linux](#prerequisites)
	* [Preparing a device](#preparing-device)
	* [Preparing an emulator](#preparing-emulator)	
	* [Usage](#usage)
	* [Other](#other)

<a id="getting-started"></a>
## Getting Started

```
git clone https://github.com/vmprog/exynex.git
```

The use of the utility is possible in two ways:

1. Install all dependencies on local Linux host machine.
2. Using docker image.

Target device:

The analysis can be carried out both on a real device and on an emulator.

<a id="prerequisites"></a>
## Prerequisites for Linux

- [Android Studio/Android Sdk](https://developer.android.com/studio) is installed (tested with Version 4.1.3 for Linux 64-bit)]

<p align="center">
<a target="_blank" href="LICENSE"><img src="https://github.com/vmprog/exynex/blob/exynex_dev/badges/sdk_set.jpg"></a>
</p>

* Emulator and adb executables from Android Sdk have been added to $PATH variable

   	* emulator usually located at `/home/<your_user_name>/Android/Sdk/emulator/emulator`
   	* adb usually located at `/home/<your_user_name>/Android/Sdk/platform-tools/adb` 
	
       * You need to add these lines to .bashrc
        
```
export PATH=$PATH:$HOME/Android/Sdk/platform-tools
export PATH=$PATH:$HOME/Android/Sdk/emulator
export PATH=$PATH:/path/to/jre/bin
```
Check environment variable:

`set ANDROID_SDK_ROOT=path_to_sdk`

#### If Linux environment (Install these packages):

- [python v3.8.8 or later](https://www.python.org/)
- adb
- aapt
- android-tools-adb
- [mitmproxy](https://mitmproxy.org/)
- iptables
- procps
- apksigner
- xxd
- [jadx v1.3.1 or later](https://github.com/skylot/jadx)

Install local python dependencies by running:
```
pip install -r requirements.txt
```

#### If Docker environment:

- [Docker version v20.10.8 or later](https://www.docker.com/)

Install local docker image by running:
```
sudo docker build -t python-img:5.1 .
```
<a id="preparing-device"></a>
## Preparing a device

- Developer mode must be enabled on the emulator.

- The emulator must be rooted.

>**Note:** There are different approaches to getting root on the device. It depends on the android version.

To capture and decrypt traffic, you need to install mitmproxy certificates on the device System CA.

* Install mitmproxy certificates (tested on Android 10 API 29).
	
	* CAcert system trusted certificates
```
mitmproxy (exit with [q yes])
cd ~/.mitmproxy/ 
hashed_name=`openssl x509 -inform PEM -subject_hash_old -in mitmproxy-ca-cert.cer | head -1` && cp mitmproxy-ca-cert.cer $hashed_name.0 

adb push c8750f0d.0 /sdcard (file name from the previous command) 
adb shell 
su 
mount -o rw,remount / 
cp /sdcard/c8750f0d.0 /system/etc/security/cacerts/ 
cd /system/etc/security/cacerts/ 
chmod 644 c8750f0d.0 
ls -al –Z 
mount -o ro,remount /
 
```
   * CAcert user trusted certificates

#### Configuring network

Before using, you must change the ip address of the gateway to host ip with mitmdump.

Before using, you must disable IPv6 protocol.
If you are using mobile internet, you should find the following setting: Access Point Names
->APN protocol and set IPv4 only.

If you are using WIFI, you should find the protocol selection setting in the settings menu of your access point and set IPv4 only.

<a id="preparing-emulator"></a>
## Preparing an emulator

To capture and decrypt traffic, you need to [install mitmproxy certificates on the emulator System CA](https://docs.mitmproxy.org/stable/howto-install-system-trusted-ca-android/). The installation approaches depend on the Android version.

<a id="usage"></a>
## Usage

The script also accepts some options:
```
positional arguments:
  analyze               Command to analyze.
  PATH_TO_APK           Path to APK file.
  device_ip             IP address of the device or emulator.
  su_pass               Superuser password.

optional arguments:
  -h, --help            show this help message and exit
  --output OUTPUT       Path to report.
  --activity_time ACTIVITY_TIME
                        Time to activity.
  --allow_permissions   Allow to any permissions requests.
  --verbose             Produces debugging output.
```

#### Run on local Linux
```
python3 -O exynex.py analyze some.apk 192.168.1.5 SUpass --allow_permissions --verbose
```

#### Run on Docker
Starting the container:

```
sudo docker run -it --net=host --privileged \
-v /dev/bus/usb:/dev/bus/usb \
-v /folder/with/apk:/home/researcher/APK \
--mount src="$(pwd)",target=/home/researcher/app_src,type=bind \
--mount src="/home/mitmproxyuser/.mitmproxy",target=/home/mitmproxyuser/.mitmproxy,type=bind  \
python-img:5.1 /bin/bash
```
 >**Note:** Where /folder/with/apk - is the folder on host where the apk file for research is located.

```
python3 -O exynex.py analyze ~/APK/some.apk 192.168.1.5 SUpass --allow_permissions --verbose
```

<a id="other"></a>
## Other

<a id="reporting-issues"></a>
### Report issues

If you run into any problem or have a suggestion, head to [this page](https://github.com/vmprog/exynex/issues) and click on the `New issue` button.

