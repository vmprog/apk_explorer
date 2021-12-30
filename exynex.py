#!/usr/bin/env python3

"""This command line utility allows you to perform static and dynamic
analysis of android apk files.
Project page:
https://github.com/vmprog/exynex/blob/main/README.md
"""

import sys
import os.path
import logging
import subprocess
import argparse
import json
import tempfile
from datetime import datetime
import time
import xmltodict

stdout = sys.stdout

# Configuring the logger object

logger = logging.getLogger('')
if logger.hasHandlers():
    logger.handlers.clear()
logger.setLevel(logging.INFO)
fh = logging.FileHandler('exynex.log')
sh = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter(
    '[%(asctime)s] %(levelname)s [%(filename)s.%(funcName)s:%(lineno)d] '
    '%(message)s', datefmt='%a, %d %b %Y %H:%M:%S')
fh.setFormatter(formatter)
sh.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(sh)


def check_command_line(path_to_apk, output):
    """Checks the correctness of the command line.

    Args:
      path_to_apk: Absolute path of apk placement.
      output: Absolute path of report placement.

    Returns:
      Nothing.

    Raises:
      SystemExit: If no path to apk  is found.
      OSError: If error creating the report file.
    """

    logger.debug('Entering the function: "check_command_line"')

    check_path_to_apk = os.path.exists(path_to_apk)
    if not check_path_to_apk:
        logger.error('There is no apk on the specified path: %s', path_to_apk)
        raise SystemExit(1)

    try:
        with open(output, 'w+') as output_report:
            output_report.close()
    except OSError as error_rep:
        logger.error('Could not write output (reason: %r): %r',
                     error_rep, output)
        sys.exit(1)

    logger.debug('Exiting the function: "check_command_line"')


def start_jadx(path_to_apk, tempdir):
    """Start JADX decompiler.

    Args:
      path_to_apk: Absolute path of apk placement.
      tempdir: Absolute path for temp files.

    Returns:
      Nothing.

    Raises:
      OSError: If JADX runtime error.
    """

    logger.debug('Entering the function: "start_jadx"')

    jadx_dir = f'{tempdir}/resources'
    if not os.path.exists(jadx_dir):
        jadx = f'jadx {path_to_apk} -d {tempdir}'
        logger.info('Starting Jadx: %s', jadx)
        try:
            os.popen(jadx).read()
        except OSError as error_jd:
            logger.warning('Jadx runtime error (reason: %r):',
                           error_jd)
            sys.exit(1)

    logger.debug('Exiting the function: "start_jadx"')


def check_device():
    """Checking the device connection.

    Args:
      Nothing.

    Returns:
      Nothing.

    Raises:
      SystemExit: If the device is not connected.
    """

    logger.debug('Entering the function: "check_device"')

    get_devices = 'adb devices | grep device$'
    ret_val = os.popen(get_devices).read()
    if not ret_val:
        logger.error('Error checking devices!: %s', ret_val)
        raise SystemExit(1)

    logger.debug('Exiting the function: "check_device"')


def get_badging(path_to_apk):
    """Get dump from apk with aapt dump badging.

    Args:
      path_to_apk: Absolute path of apk placement.

    Returns:
      Nothing.

    Raises:
      SystemExit: If error getting badging.
      SystemExit: If error getting the package name.
      SystemExit: If error getting the application name.
      SystemExit: If error getting the version.
      SystemExit: If error getting the version_code.
    """

    logger.debug('Entering the function: "get_badging"')

    get_badging_cmd = f'aapt dump badging {path_to_apk}'
    badging = os.popen(get_badging_cmd).read()
    if not badging:
        logger.error('Error getting the badging.')
        raise SystemExit(1)

    awk_cmd = 'awk \'/package/{gsub("name=|\'"\'"\'",""); printf $2}\''
    package_cmd = f'echo "{badging}" | {awk_cmd}'
    logger.info('Getting the package name!')
    package = os.popen(package_cmd).read()
    if not package:
        logger.error('Error getting the package name!')
        raise SystemExit(1)

    cmd = 'grep "application-label:" | sed \'s/^.*://\' | tr -d \'\\n\''
    app_name_cmd = f'echo "{badging}" | {cmd}'
    logger.info('Getting the application name.')
    app_name = os.popen(app_name_cmd).read()
    if not app_name:
        logger.error('Error getting the application name!')
        raise SystemExit(1)

    cmd1 = 'grep "versionName"'
    cmd2 = 'sed -e "s/.*versionName=\'//" -e "s/\' .*//" | tr -d \'\\n\''
    version_cmd = f'echo "{badging}" | {cmd1} | {cmd2}'
    logger.info('Getting the version.')
    version = os.popen(version_cmd).read()
    if not version:
        logger.error('Error getting the version!')
        raise SystemExit(1)

    cmd1 = 'grep "versionCode"'
    cmd2 = 'sed -e "s/.*versionCode=\'//" -e "s/\' .*//" | tr -d \'\\n\''
    version_code_cmd = f'echo "{badging}" | {cmd1} | {cmd2}'
    logger.info('Getting the version_code.')
    version_code = os.popen(version_code_cmd).read()
    if not version_code:
        logger.error('Error getting the version_code!')
        raise SystemExit(1)

    logger.debug('Exiting the function: "get_badging"')

    return{'package': package, 'app_name': app_name, 'version': version,
           'version_code': version_code}


def perform_static_analysis(badging, tempdir):
    """Main SAST function.

    Args:
      badging: Aapt output.
      output: Absolute path of report placement.
      tempdir: Absolute path for temp files.

    Returns:
      SAST dataset.

    Raises:
      Nothing.
    """
    logger.debug('Entering the function: "perform_static_analysis"')

    logger.info('Preparing the report...')

    manifest_path = '%s/resources/AndroidManifest.xml' % (tempdir)
    with open(manifest_path) as fd:
        manifest = xmltodict.parse(fd.read())

    data = {}

    data['app_name'] = badging['app_name']
    data['package_name'] = manifest['manifest']['@package']
    data['version'] = badging['version']
    data['version_code'] = badging['version_code']

    cmd1 = f'keytool -printcert -file {tempdir}/resources/META-INF/*.RSA'
    cmd2 = 'grep -Po "(?<=SHA256:) .*"'
    cmd3 = 'xxd -r -p | openssl base64'
    cmd4 = 'tr -- \'+/=\' \'-_\' | tr -d \'\\n\''
    checksum_cmd = f'{cmd1} | {cmd2} | {cmd3} | {cmd4}'
    checksum = os.popen(checksum_cmd).read()
    if len(checksum):
        data['checksum'] = checksum
    else:
        logger.error('Error getting checksum.')

    data['analysis'] = []
    device = {}
    device['os_build'] = ''

    cmd1 = 'adb shell settings get secure android_id'
    cmd2 = 'tr -d \'\\n\''
    android_id_cmd = f'{cmd1} | {cmd2}'
    android_id = os.popen(android_id_cmd).read()
    if len(android_id):
        device['android_id'] = android_id
    else:
        logger.error('Error getting android_id.')

    device['advertising_id'] = ''

    cmd1 = 'adb shell service call iphonesubinfo 1'
    cmd2 = ('awk -F"\'" \'NR>1 { gsub(/\\./,"",$2); imei=imei $2 } '
            'END {printf imei}\'')
    cmd3 = 'tr -d \' \\t\\n\\r\\f\''
    imei_cmd = f'{cmd1} | {cmd2} | {cmd3}'
    imei = os.popen(imei_cmd).read()
    if len(imei):
        device['imei'] = imei
    else:
        device['imei'] = ''
        logger.error('Error getting imei.')

    device['google_account'] = ''
    device['wifi_ssid'] = ''
    geo_data = {}
    geo_data['lat'] = ''
    geo_data['lon'] = ''
    device['geo'] = geo_data

    data['analysis'].append({
        'device': device
    })

    static_analysis = {}

    cmd1 = ('grep -r -Eo "(http|https)://[a-zA-Z0-9./?=_%:-]*" '
            f'{tempdir}/sources/')
    cmd2 = 'sort -u'
    urls_cmd = f'{cmd1} | {cmd2}'
    urls = os.popen(urls_cmd).read()
    if len(urls):
        static_analysis['urls'] = urls.split('\n')
    else:
        logger.error('Error getting urls.')

    cmd1 = f'grep -r -Po ".*?//\\K.*?(?=/)" {tempdir}/sources/ | sort -u'
    domains_cmd = f'{cmd1}'
    domains = os.popen(domains_cmd).read()
    if len(domains):
        static_analysis['domains'] = domains.split('\n')
    else:
        logger.error('Error getting domains.')

    libraries_cmd = f'find {tempdir} -name *.so'
    libraries = os.popen(libraries_cmd).read()
    if len(libraries):
        static_analysis['libraries'] = libraries.split('\n')
    else:
        logger.error('Error getting libraries.')

    cmd1 = f'grep -r "public class" {tempdir}/sources/'
    cmd2 = 'sed \'s/\\(class [^ ]*\\).*/\\1/\''
    classes_cmd = f'{cmd1} | {cmd2}'
    classes = os.popen(classes_cmd).read()
    if len(classes):
        static_analysis['classes'] = classes.split('\n')
    else:
        logger.error('Error getting classes.')

    permissions = []
    for item in manifest['manifest']['uses-permission']:
        permissions.append(item['@android:name'])
    static_analysis['permissions'] = permissions

    activities = []
    for item in manifest['manifest']['application']['activity']:
        activities.append(item['@android:name'])
    static_analysis['activities'] = activities

    data['analysis'].append({
        'static_analysis': static_analysis
    })

    logger.debug('Exiting the function: "perform_static_analysis"')

    return data


def get_uid(package):
    """Retrieves the UID of the application user.

    Args:
      package: Package name of apk.

    Returns:
      uid: UID of the application user.

    Raises:
      SystemExit: If error getting the uid.
    """

    logger.debug('Entering the function: "get_uid"')

    get_uid_cmd = (f'adb shell dumpsys package {package} '
                   '| grep -o "userId=\\S*"')
    uid = os.popen(get_uid_cmd).read()
    uid = uid[uid.index('=')+1:-1]
    if uid:
        logger.info('The application uid is: %s', uid)
    else:
        logger.error('Error getting the uid!')
        raise SystemExit(1)

    logger.debug('Exiting the function: "get_uid"')

    return uid


def is_magisk():
    """Checking the use of magisk.

    Args:
      Nothing.

    Returns:
      bool: True if magisk used.

    Raises:
      Nothing.
    """

    logger.debug('Entering the function: "is_magisk"')

    get_magisk = 'adb shell pm list packages | grep magisk'
    magisk = os.popen(get_magisk).read()

    logger.debug('Exiting the function: "is_magisk"')

    return bool(magisk)


def set_iptables(uid, magisk, device_ip, su_pass):
    """Configuring iptables for host and device.

    Args:
      Nothing.

    Returns:
      bool: True if magisk used.

    Raises:
      Device setup error.
    """

    logger.debug('Entering the function: "set_iptables"')

    # Setup device
    if magisk:
        dev_drop = 'adb shell su -c "iptables -P OUTPUT DROP"'
        dev_accept = 'adb shell su -c "iptables -P OUTPUT ACCEPT '\
            '-m owner --uid-owner '+uid+'"'
    else:
        dev_drop = 'adb shell "su 0 iptables -P OUTPUT DROP"'
        dev_accept = 'adb shell "su 0 iptables -P OUTPUT ACCEPT '\
            '-m owner --uid-owner '+uid+'"'
    ret_drop = os.popen(dev_drop).read()
    ret_accept = os.popen(dev_accept).read()
    if ret_drop or ret_accept:
        error_str = f'Device setup error! {ret_drop} {ret_accept}'
        logger.error(error_str)
        raise SystemExit(1)

    # Setup host
    ipt1_host = 'echo '+su_pass+' | sudo -S iptables -t nat -F'
    ret_ipt1 = os.popen(ipt1_host).read()
    ipt2_host = 'echo '+su_pass+' | sudo -S sysctl -w '\
        'net.ipv4.ip_forward=1'
    ret_ipt2 = os.popen(ipt2_host).read()
    ipt3_host = 'echo '+su_pass+' | sudo sysctl -w '\
        'net.ipv6.conf.all.forwarding=1'
    ret_ipt3 = os.popen(ipt3_host).read()
    ipt4_host = 'echo '+su_pass+' | sudo sysctl -w '\
        'net.ipv4.conf.all.send_redirects=0'
    ret_ipt4 = os.popen(ipt4_host).read()

    ipt5_host = 'echo '+su_pass + \
        ' | sudo iptables -t nat -A PREROUTING -s '+device_ip + \
        ' -p tcp -j REDIRECT --to-port 8080'
    ret_ipt5 = os.popen(ipt5_host).read()

    if ret_ipt1 or ret_ipt2 or ret_ipt3 or ret_ipt4 or ret_ipt5:
        error_str = (f'Host setup error! {ret_ipt1} {ret_ipt2} {ret_ipt3} '
                     '{ret_ipt4} {ret_ipt5}')
        logger.error(error_str)
        raise SystemExit(1)

    logger.debug('Exiting the function: "set_iptables"')


def perform_dynamic_analysis(data, package, activity_time, device_ip, su_pass):
    """Main DAST function.

    Args:
      package: Package name of apk.
      activity_time: Application activity timer.

    Returns:
      DAST dataset.

    Raises:
      Nothing.
    """

    logger.debug('Entering the function: "perform_dynamic_analysis"')

    uid = get_uid(package)
    magisk = is_magisk()

    set_iptables(uid, magisk, device_ip, su_pass)
    runtime_data = start_application(package)
    activity(runtime_data['start_timestamp'], activity_time)
    stop_application(package, runtime_data['pid'])

    dynamic_analysis = {}
    network_activity = {}
    requests = []
    network_activity['requests'] = requests
    requested_permissions = []
    dynamic_analysis['network_activity'] = network_activity
    dynamic_analysis['requested_permissions'] = requested_permissions
    data['analysis'].append({
        'dynamic_analysis': dynamic_analysis
    })

    logger.debug('Exiting the function: "perform_dynamic_analysis"')

    return data


def install_apk(package, path_to_apk):
    """Installing the apk on a device or emulator.

    Args:
      path_to_apk: Absolute path of apk placement.

    Returns:
      Nothing.

    Raises:
      SystemExit: If APK installation error.
    """

    logger.debug('Entering the function: "install_apk"')

    get_install_status = f'adb shell pm list packages | grep {package}'
    logger.info('Getting package status: %s', get_install_status)
    package_presents = os.popen(get_install_status).read()
    if not package_presents:
        logger.info('The package %s is not installed.', package)
        install_package = f'adb install {path_to_apk}'
        logger.info('Installing the APK: %s', path_to_apk)
        installaation = os.popen(install_package).read()
        if 'Success' in installaation:
            logger.info('The apk is installed: %s', path_to_apk)
        else:
            logger.error('APK installation error!: %s', path_to_apk)
            raise SystemExit(1)
    else:
        logger.info('The package %s is already installed.', package)

    logger.debug('Exiting the function: "install_apk"')


def start_application(package):
    """Start application on the device or emulator.

    Args:
      package: Package name of apk.

    Returns:
      start_ts: Application launch timestamp.
      pid: Pid of application.

    Raises:
      SystemExit: If runtime error.
    """

    logger.debug('Entering the function: "start_app"')

    start_app_w = (f'adb shell monkey -p {package} -c '
                   'android.intent.category.LAUNCHER 1')
    logger.info('Starting the package: %s', start_app_w)
    # proc = subprocess.Popen(start_app_w, shell=True)
    with subprocess.Popen(start_app_w, shell=True) as proc:
        pid = str(proc.pid)
        proc.wait()
    get_running_status = f'adb shell ps | grep {package}'
    logger.info('Getting the application status: %s', package)
    app_status = os.popen(get_running_status).read()
    if len(app_status):
        logger.info('The app is running: %s', package)
    else:
        logger.error('Runtime error!: %s', package)
        raise SystemExit(1)

    now = datetime.now()
    start_ts = datetime.timestamp(now)

    logger.debug('Exiting the function: "start_app"')

    return{'start_timestamp': start_ts, 'pid': pid}


def activity(start_timestamp, activity_time):
    """Emulation of working with the application.

    Args:
      start_timestamp: Application launch timestamp.

    Returns:
      Nothing.

    Raises:
      Nothing.
    """

    logger.debug('Entering the function: "activity"')

    logger.info('Start of activities: %s sec.', activity_time)

    # TODO: Activity 1
    # TODO: Activity 2

    now = datetime.now()
    now_timestamp = datetime.timestamp(now)
    passed_time = now_timestamp - start_timestamp
    while passed_time <= activity_time:
        time.sleep(2)
        now = datetime.now()
        now_timestamp = datetime.timestamp(now)
        passed_time = now_timestamp - start_timestamp

    logger.debug('Exiting the function: "activity"')


def stop_application(package, pid):
    """Stop application on the device or emulator.

    Args:
      package: Package name of apk.
      pid: Pid of application.

    Returns:
      Nothing.

    Raises:
      SystemExit: If error stopping the application.
    """

    logger.debug('Entering the function: "stop_app"')

    stop_app = f'adb shell am force-stop {package}'
    logger.info('Stopping the app: %s', package)
    os.popen(stop_app).read()

    check_app = f'adb shell ps -p {pid} | grep {pid}'
    app_status = os.popen(check_app).read()
    if not app_status:
        logger.info('The application is stopped: %s', package)
    else:
        logger.error('Error stopping the application!: %s', package)
        raise SystemExit(1)

    logger.debug('Exiting the function: "stop_app"')


def remove_apk(package):
    """Removing the apk from the device or emulator.

    Args:
      package: Package name of apk.

    Returns:
      Nothing.

    Raises:
      SystemExit: If package uninstallation error.
    """

    logger.debug('Entering the function: "remove_apk"')

    uninstall_package = f'adb shell pm uninstall {package}'
    logger.info('Uninstalling the package: %s', uninstall_package)
    result = os.popen(uninstall_package).read()
    if 'Success' in result:
        logger.info('The apk is uninstalled: %s', package)
    else:
        logger.error('Package uninstallation error!: %s', package)
        raise SystemExit(1)

    logger.debug('Exiting the function: "remove_apk"')


def make_report(output, report_data):
    """Creates a report based on the results of the analysis.

    Args:
      output: Absolute path of report placement.
      sast_data: A set of static analysis data.
      dast_data: A set of dynamic analysis data.

    Returns:
      Nothing.

    Raises:
      Nothing.
    """

    logger.debug('Entering the function: "make_report"')

    with open(output, 'w') as outfile:
        json.dump(report_data, outfile, indent=4, ensure_ascii=False)

    logger.info('The report has been prepared: %s', output)

    logger.debug('Exiting the function: "make_report"')


def main(path_to_apk, device_ip, su_pass, output, activity_time,
         allow_permissions, tempdir):

    check_command_line(path_to_apk, output)
    start_jadx(path_to_apk, tempdir)
    check_device()
    badging = get_badging(path_to_apk)
    install_apk(badging['package'], path_to_apk)
    report_data = perform_static_analysis(badging, tempdir)
    report_data = perform_dynamic_analysis(report_data, badging['package'],
                                           activity_time, device_ip, su_pass)
    remove_apk(badging['package'])
    make_report(output, report_data)


if __name__ == '__main__':

    with tempfile.TemporaryDirectory() as app_tempdir:
        if __debug__:
            app_tempdir = './research'
        logger.info('The temp directory is %s', app_tempdir)
        default_output = '%s/exynex_output.json' % (app_tempdir)

        parser = argparse.ArgumentParser(
            description=__doc__,
            formatter_class=argparse.RawDescriptionHelpFormatter)

        parser.add_argument('analyze', help='Command to analyze.')
        parser.add_argument('PATH_TO_APK', help='Path to APK file.')
        parser.add_argument('device_ip', help='IP address of the device or '
                            'emulator.')
        parser.add_argument('su_pass', help='Superuser password.')
        parser.add_argument('--output', type=str, default=default_output,
                            help='Path to report.')
        parser.add_argument('--activity_time', type=int, default=5,
                            help='Time to activity.')
        parser.add_argument('--allow_permissions',
                            help='Allow to any permissions requests.',
                            action='store_true')
        parser.add_argument('--verbose',
                            help='Produces debugging output.',
                            action='store_true')

        args = parser.parse_args()

        if args.verbose:
            logger.setLevel(logging.DEBUG)

        main(args.PATH_TO_APK, args.device_ip, args.su_pass, args.output,
             args.activity_time, args.allow_permissions, app_tempdir)
