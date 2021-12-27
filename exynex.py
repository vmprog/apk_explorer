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
import yaml

stdout = sys.stdout

# Configuring the logger object

logger = logging.getLogger('')
if logger.hasHandlers():
    logger.handlers.clear()
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('exynex.log')
sh = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter(
    '[%(asctime)s] %(levelname)s [%(filename)s.%(funcName)s:%(lineno)d] '
    '%(message)s', datefmt='%a, %d %b %Y %H:%M:%S')
fh.setFormatter(formatter)
sh.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(sh)

# Reading the configuration file

try:
    with open('config.yaml', 'r') as cfgfh:
        cfg = yaml.safe_load(cfgfh)
except OSError as error:
    logger.warning('Could not read config.yaml (reason: %r):',
                   error)
    sys.exit(1)


def check_command_line(path_to_apk, output, verbose):
    """Checks the correctness of the command line.

    Args:
      path_to_apk: Absolute path of apk placement.
      output: Absolute path of report placement.
      verbose: Verbose mode flag.

    Returns:
      Nothing.

    Raises:
      SystemExit: If no path to apk  is found.
      OSError: If error creating the report file.
    """
    if verbose:
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

    if verbose:
        logger.debug('Exiting the function: "check_command_line"')


def start_jadx(path_to_apk, tempdir, verbose):
    """Start JADX decompiler.

    Args:
      path_to_apk: Absolute path of apk placement.
      tempdir: Absolute path for temp files.
      verbose: Verbose mode flag.

    Returns:
      Nothing.

    Raises:
      OSError: If JADX runtime error.
    """
    if verbose:
        logger.debug('Entering the function: "start_jadx"')

    jadx_dir = '%s/resources' % (tempdir)
    if not os.path.exists(jadx_dir):
        jadx = cfg[0]['Apk']['jadx']
        jadx = jadx.replace('%apk', path_to_apk)
        jadx = jadx.replace('%tempdir', tempdir)
        logger.info('Starting Jadx: %s', jadx)
        try:
            os.popen(jadx).read()
        except OSError as error_jd:
            logger.warning('Jadx runtime error (reason: %r):',
                           error_jd)
            sys.exit(1)

    if verbose:
        logger.debug('Exiting the function: "start_jadx"')


def check_device(verbose):
    """Checking the device connection.

    Args:
      verbose: Verbose mode flag.

    Returns:
      Nothing.

    Raises:
      SystemExit: If the device is not connected.
    """
    if verbose:
        logger.debug('Entering the function: "check_device"')

    get_devices = cfg[0]['Apk']['check_device']
    ret_val = os.popen(get_devices).read()
    if not ret_val:
        logger.error('Error checking devices!: %s', ret_val)
        raise SystemExit(1)

    if verbose:
        logger.debug('Exiting the function: "check_device"')


def install_apk(path_to_apk, tempdir, verbose):
    """Installing the apk on a device or emulator.

    Args:
      path_to_apk: Absolute path of apk placement.
      tempdir: Absolute path for temp files.
      verbose: Verbose mode flag.

    Returns:
      APK package name.

    Raises:
      SystemExit: If error getting badging.
      SystemExit: If error getting data from aapt.
      SystemExit: If APK installation error.
    """
    if verbose:
        logger.debug('Entering the function: "install_apk"')

    get_badging = cfg[0]['Apk']['get_badging']
    get_badging = get_badging.replace('%p', path_to_apk)
    get_badging = get_badging.replace('%tempdir', tempdir)
    os.popen(get_badging).read()
    badging_path = '%s/badging_output.txt' % (tempdir)
    check_badging = os.path.exists(badging_path)
    if not check_badging:
        logger.error('There is no badging_output.txt on the specified '
                     'path: %s', {tempdir})
        raise SystemExit(1)

    get_package = cfg[0]['Apk']['get_package']
    get_package = get_package.replace('%tempdir', tempdir)
    logger.info('Getting the package name: %s', get_package)
    package = os.popen(get_package).read()
    if not package:
        logger.error('Error getting data from aapt!: %s', package)
        raise SystemExit(1)
    else:
        logger.info('The package name is: %s', package)

    get_install_status = cfg[0]['Apk']['get_install_status']
    get_install_status = get_install_status.replace('%p', package)
    logger.info('Getting package status: %s', get_install_status)
    package_presents = os.popen(get_install_status).read()
    if not package_presents:
        logger.info('The package %s is not installed.', package)
        install_package = cfg[0]['Apk']['install_package']
        install_package = install_package.replace('%p', path_to_apk)
        logger.info('Installing the APK: %s', path_to_apk)
        installaation = os.popen(install_package).read()
        if 'Success' in installaation:
            logger.info('The apk is installed: %s', path_to_apk)
        else:
            logger.error('APK installation error!: %s', path_to_apk)
            raise SystemExit(1)
    else:
        logger.info('The package %s is already installed.', package)

    if verbose:
        logger.debug('Exiting the function: "install_apk"')

    return package


def remove_apk(package, verbose):
    """Removing the apk from the device or emulator.

    Args:
      package: Package name of apk.
      verbose: Verbose mode flag.

    Returns:
      Nothing.

    Raises:
      SystemExit: If package uninstallation error.
    """
    if verbose:
        logger.debug('Entering the function: "remove_apk"')

    uninstall_package = cfg[0]['Apk']['uninstall_package']
    uninstall_package = uninstall_package.replace('%p', package)
    logger.info('Uninstalling the package: %s', uninstall_package)
    result = os.popen(uninstall_package).read()
    if 'Success' in result:
        logger.info('The apk is uninstalled: %s', package)
    else:
        logger.error('Package uninstallation error!: %s', package)
        raise SystemExit(1)

    if verbose:
        logger.debug('Exiting the function: "remove_apk"')


def start_application(package, verbose):
    """Start application on the device or emulator.

    Args:
      package: Package name of apk.
      verbose: Verbose mode flag.

    Returns:
      start_ts: Application launch timestamp.
      pid: Pid of application.

    Raises:
      SystemExit: If runtime error.
    """
    if verbose:
        logger.debug('Entering the function: "start_app"')

    start_app_w = cfg[0]['Apk']['start_app']
    start_app_w = start_app_w.replace('%p', package)
    logger.info('Starting the package: %s', start_app_w)
    # proc = subprocess.Popen(start_app_w, shell=True)
    with subprocess.Popen(start_app_w, shell=True) as proc:
        pid = proc.pid
        proc.wait()
    get_running_status = cfg[0]['Apk']['get_running_status']
    get_running_status = get_running_status.replace('%p', package)
    logger.info('Getting the application status: %s', package)
    app_status = os.popen(get_running_status).read()
    if len(app_status):
        logger.info('The app is running: %s', package)
    else:
        logger.error('Runtime error!: %s', package)
        raise SystemExit(1)

    now = datetime.now()
    start_ts = datetime.timestamp(now)

    if verbose:
        logger.debug('Exiting the function: "start_app"')

    return (start_ts, pid)


def activity(start_timestamp, verbose):
    """Emulation of working with the application.

    Args:
      start_timestamp: Application launch timestamp.
      verbose: Verbose mode flag.

    Returns:
      Nothing.

    Raises:
      Nothing.
    """
    if verbose:
        logger.debug('Entering the function: "activity"')

    activity_time = cfg[2]['Activity']['activity_time']
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

    if verbose:
        logger.debug('Exiting the function: "activity"')


def stop_application(package, pid, verbose):
    """Stop application on the device or emulator.

    Args:
      package: Package name of apk.
      pid: Pid of application.
      verbose: Verbose mode flag.

    Returns:
      Nothing.

    Raises:
      SystemExit: If error stopping the application.
    """
    if verbose:
        logger.debug('Entering the function: "stop_app"')

    stop_app = cfg[0]['Apk']['stop_app']
    stop_app = stop_app.replace('%p', package)
    logger.info('Stopping the app: %s', package)
    os.popen(stop_app).read()

    check_app = cfg[0]['Apk']['check_app']
    check_app = check_app.replace('%p', str(pid))
    app_status = os.popen(check_app).read()
    if not app_status:
        logger.info('The application is stopped: %s', package)
    else:
        logger.error('Error stopping the application!: %s', package)
        raise SystemExit(1)

    if verbose:
        logger.debug('Exiting the function: "stop_app"')


def make_report(output, tempdir, verbose):
    """Creates a report based on the results of the analysis.

    Args:
      output: Absolute path of report placement.
      path_to_apk: Absolute path of apk placement.
      tempdir: Absolute path for temp files.
      verbose: Verbose mode flag.

    Returns:
      Nothing.

    Raises:
      Nothing.
    """
    if verbose:
        logger.debug('Entering the function: "make_report"')

    logger.info('Preparing the report...')

    manifest_path = '%s/resources/AndroidManifest.xml' % (tempdir)
    with open(manifest_path) as fd:
        manifest = xmltodict.parse(fd.read())

    data = {}

    app_name_cmd = cfg[1]['Sast']['app_name']
    app_name_cmd = app_name_cmd.replace('%tempdir', tempdir)
    app_name = os.popen(app_name_cmd).read()
    if len(app_name):
        data['app_name'] = app_name
    else:
        logger.error('Error getting app_name.')

    data['package_name'] = manifest['manifest']['@package']

    version_cmd = cfg[1]['Sast']['version']
    version_cmd = version_cmd.replace('%tempdir', tempdir)
    version = os.popen(version_cmd).read()
    if len(version):
        data['version'] = version
    else:
        logger.error('Error getting version.')

    version_code_cmd = cfg[1]['Sast']['version_code']
    version_code_cmd = version_code_cmd.replace('%tempdir', tempdir)
    version_code = os.popen(version_code_cmd).read()
    if len(version_code):
        data['version_code'] = version_code
    else:
        logger.error('Error getting version_code.')

    checksum_cmd = cfg[1]['Sast']['checksum']
    checksum_cmd = checksum_cmd.replace('%p', tempdir)
    checksum = os.popen(checksum_cmd).read()
    if len(checksum):
        data['checksum'] = checksum
    else:
        logger.error('Error getting checksum.')

    data['analysis'] = []
    device = {}
    device['os_build'] = ''

    android_id_cmd = cfg[1]['Sast']['android_id']
    android_id = os.popen(android_id_cmd).read()
    if len(android_id):
        device['android_id'] = android_id
    else:
        logger.error('Error getting android_id.')

    device['advertising_id'] = ''

    imei_cmd = cfg[1]['Sast']['imei']
    imei = os.popen(imei_cmd).read()
    if len(imei):
        device['imei'] = imei
    else:
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

    urls_cmd = cfg[1]['Sast']['urls']
    urls_cmd = urls_cmd.replace('%p', tempdir)
    urls = os.popen(urls_cmd).read()
    if len(urls):
        static_analysis['urls'] = urls.split('\n')
    else:
        logger.error('Error getting urls.')

    domains_cmd = cfg[1]['Sast']['domains']
    domains_cmd = domains_cmd.replace('%p', tempdir)
    domains = os.popen(domains_cmd).read()
    if len(domains):
        static_analysis['domains'] = domains.split('\n')
    else:
        logger.error('Error getting domains.')

    libraries_cmd = cfg[1]['Sast']['libraries']
    libraries_cmd = libraries_cmd.replace('%p', tempdir)
    libraries = os.popen(libraries_cmd).read()
    if len(libraries):
        static_analysis['libraries'] = libraries.split('\n')
    else:
        logger.error('Error getting libraries.')

    classes_cmd = cfg[1]['Sast']['classes']
    classes_cmd = classes_cmd.replace('%p', tempdir)
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

    dynamic_analysis = {}

    network_activity = {}
    requests = []
    network_activity['requests'] = requests

    requested_permissions = []

    dynamic_analysis['network_activity'] = network_activity
    dynamic_analysis['requested_permissions'] = requested_permissions

    data['analysis'].append({
        'static_analysis': static_analysis,
        'dynamic_analysis': dynamic_analysis
    })

    with open(output, 'w') as outfile:
        json.dump(data, outfile, indent=4, ensure_ascii=False)

    logger.info('The report has been prepared: %s', output)

    if verbose:
        logger.debug('Exiting the function: "make_report"')


def main(path_to_apk, output, allow_permissions, verbose,
         tempdir):

    check_command_line(path_to_apk, output, verbose)
    start_jadx(path_to_apk, tempdir, verbose)
    check_device(verbose)
    package = install_apk(path_to_apk, tempdir, verbose)
    runtime_data = start_application(package, verbose)
    activity(runtime_data[0], verbose)
    stop_application(package, runtime_data[1], verbose)
    remove_apk(package, verbose)
    make_report(output, tempdir, verbose)


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
        parser.add_argument('--output', type=str, default=default_output,
                            help='Path to report.')
        parser.add_argument('--allow_permissions',
                            help='Allow to any permissions requests.',
                            action='store_true')
        parser.add_argument('--verbose',
                            help='Produces debugging output.',
                            action='store_true')

        args = parser.parse_args()

        main(args.PATH_TO_APK, args.output,
             args.allow_permissions, args.verbose, app_tempdir)
