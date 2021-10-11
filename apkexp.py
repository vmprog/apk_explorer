#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import sys
import getopt
import time
import xmltodict
import json


def open_apk_jadx(apk_file):
    """Декомпилирует APK-файл при помощи jadx
    в папку по имени apk файла
    Возвращает имя пакета и UID при успешном завершении
    """
    write = False
    package = ''
    def_path = './'+apk_file[:-4]
    jadx_cmd = "jadx -d "+def_path+" "+apk_file
    # Проверка пустая ли папка jadx_out
    if os.path.exists(def_path):  # Если папка есть и она не пустая,
        # то очищаем ее.
        if len(os.listdir(def_path)) == 0:
            # Папка есть, но пустая.
            write = True
        else:  # Папка есть, но не путая.
            #  os.system('rm -rf %s/*' % def_path)
            write = False  # True Возможный вариант реализации
    else:  # Папки нет. Надо запустить jadx
        write = True
    if write:
        try:
            print('Starting: '+jadx_cmd)
            ret_val = os.popen(jadx_cmd).read()
            print(ret_val)
        except Exception:
            print('Jadx application error. '+ret_val)

    manifest_path = def_path+'/resources/AndroidManifest.xml'
    with open(manifest_path) as fd:
        manifest = xmltodict.parse(fd.read())
    package = manifest['manifest']['@package']
    print('Package: '+package)
    # Переименовываем папку по умолчанию в папку с названием пакета
    # Проблема этого решения в том, что при повторном запуске
    # папки с именем файла всегда не будет и постоянно будет
    # запускаться jadx
    # os.system('mv %s %s' % (def_path, package))

    # # Определение uid пользователя APK. Вынес в отдельную функцию т.к.
    # если приложение не установлено, но uid получить не можем
    # try:
    #     get_uid = 'adb shell dumpsys package ' + package +\
    #         r' | grep -o "userId=\S*"'
    #     uid = os.popen(get_uid).read()
    #     uid = uid[uid.index("=")+1:-1]
    #     print('UID:='+uid)
    # except Exception:
    #     print('Error when getting the uid. '+uid)
    #     raise SystemExit
    return(package, manifest, def_path)


def read_manifest(manifest):
    """Обработка OrderedDict AndroidManifest.xml
    Читаем нужные метаданные.
    """
    try:
        print('Uses-permissions:')
        for item in manifest['manifest']['uses-permission']:
            print(item['@android:name'])
        if '@android:debuggable' in manifest['manifest']['application']:
            print('Debuggable: '+manifest['manifest']
                  ['application']['@android:debuggable'])
        else:
            print('Debuggable: False')
    except Exception:
        print('Error reading the manifest.')


def get_frameworks_json(def_path):
    """Анализирует файлы APK и детектирует
    используемые фреймворки. Настройки детектирования делаются в файле
    frameworks.json
    """
    fw_list = []
    print('Defining frameworks!')
    with open('frameworks.json', 'r', encoding='utf-8') as f:
        framework_patterns = json.load(f)
        for item in framework_patterns['frameworks']:
            try:
                find_cmd = 'grep -rn "'+item['code_signature'] + \
                    '" '+def_path+'/sources | head -1'
                ret_val = os.popen(find_cmd).read()
                if len(ret_val) != 0:
                    fw_list.append(item['name'])
            except Exception:
                print('Error checking patterns!')
    print(fw_list)


def device_present():
    """Проверяет подключено ли устройство или эмулятор
    """
    get_devices = "adb devices | grep device$"
    try:
        ret_val = os.popen(get_devices).read()
        if len(ret_val) != 0:
            return True
        else:
            return False
    except Exception:
        print('Error checking connected devices!')


def install_apk(apk_file, package):
    """Проверяет устновлен ли переданны в параметрах APK
    Если APK нет в списке установленных, то устанавливает.
    """
    get_install_status = 'adb shell pm list packages | grep '+package
    install_package = 'adb install '+apk_file
    try:
        ret_val = os.popen(get_install_status).read()
        if len(ret_val) != 0:
            print('The package '+package+' is already installed.')
        else:
            print('Installing the package: '+package+'.')
            try:
                ret_val = os.popen(install_package).read()
                print(ret_val)
            except Exception:
                print('Package Installation error!')
    except Exception:
        print('Error when getting installed applications!')


def get_uid(package):
    """Получает uid пользователя приложения
    """
    # Определение uid пользователя APK
    uid = ''
    try:
        get_uid = 'adb shell dumpsys package ' + package +\
            r' | grep -o "userId=\S*"'
        uid = os.popen(get_uid).read()
        uid = uid[uid.index("=")+1:-1]
        print('UID:='+uid)
    except Exception:
        print('Error when getting the uid. '+uid)
        raise SystemExit
    return uid


def get_magisk_su():
    """Проверяем установелн ли magisk
    от этого зависит с какими аргументами запускать adb shell su -c
    или su 0
    """
    try:
        get_magisk = 'adb shell pm list packages | grep magisk'
        ret_val = os.popen(get_magisk).read()
        if len(ret_val) != 0:
            return True
    except Exception:
        print('Error when getting Magisk is presents!')
        raise SystemExit
    return False


def set_iptables(uid, su_pass, device_ip, magisk, type_p):
    """Настройка iptables на устройстве и на
    компьютере с mitmproxy
    На устройств:
    Запрещаем весь исходящий трафик. Разрешаем исходящий трафик от конкретного
    UID
    На хост машине:
    Весь трафик с device IP направляем в порт прокси 8080
    """
    try:  # Настраиваем устройство
        if magisk:
            ipt1_device = 'adb shell su -c "iptables -P OUTPUT DROP"'
            ipt2_device = 'adb shell su -c "iptables -P OUTPUT ACCEPT '\
                '-m owner --uid-owner '+uid+'"'
        else:
            ipt1_device = 'adb shell "su 0 iptables -P OUTPUT DROP"'
            ipt2_device = 'adb shell "su 0 iptables -P OUTPUT ACCEPT '\
                '-m owner --uid-owner '+uid+'"'
        ret_vald = os.popen(ipt1_device).read()
        ret_vald = os.popen(ipt2_device).read()

        # Вариант перенаправлять прямо на телефоне
        # ipt5_device = 'adb shell su -c "iptables -t nat -A OUTPUT -p tcp '\
        # '--dport 80 -j DNAT --to-destination 192.168.1.68:8080"'
        # ret_val = os.popen(ipt5_device).read()
        # ipt6_device = 'adb shell su -c "iptables -t nat -A OUTPUT -p tcp '\
        # '--dport 443 -j DNAT --to-destination 192.168.1.68:8080"'
        # ret_val = os.popen(ipt6_device).read()

        try:  # Настраиваем host
            ipt1_host = 'echo '+su_pass+' | sudo -S iptables -t nat -F'
            ret_val = os.popen(ipt1_host).read()
            ipt2_host = 'echo '+su_pass+' | sudo -S sysctl -w '\
                'net.ipv4.ip_forward=1'
            ret_val = os.popen(ipt2_host).read()
            ipt3_host = 'echo '+su_pass+' | sudo sysctl -w '\
                'net.ipv6.conf.all.forwarding=1'
            ret_val = os.popen(ipt3_host).read()
            ipt4_host = 'echo '+su_pass+' | sudo sysctl -w '\
                'net.ipv4.conf.all.send_redirects=0'
            ret_val = os.popen(ipt4_host).read()
            if type_p == 'd':  # настройка для device
                ipt5_host = 'echo '+su_pass + \
                    ' | sudo iptables -t nat -A PREROUTING -s '+device_ip + \
                    ' -p tcp -j REDIRECT --to-port 8080'
                ret_val = os.popen(ipt5_host).read()
            elif type_p == 'e':  # настройка для avd emulator
                ipt5_host = 'echo '+su_pass + \
                    ' | sudo iptables -t nat -A OUTPUT -p tcp -m owner '\
                    '! --uid-owner mitmproxyuser --dport 80 -j REDIRECT '\
                            '--to-port 8080'
                ret_val = os.popen(ipt5_host).read()
                ipt6_host = 'echo '+su_pass + \
                    ' | sudo iptables -t nat -A OUTPUT -p tcp -m owner '\
                    '! --uid-owner mitmproxyuser --dport 443 -j REDIRECT '\
                            '--to-port 8080'
                ret_val = os.popen(ipt6_host).read()
        except Exception:
            print('Error applying the rules on the host! '+ret_val)
    except Exception:
        print('Error applying the rules on the device! '+ret_vald)


def start_mitm():
    """Запуск proxydump в прозрачном режиме
    """
    try:
        # mitm_cmd = 'mitmdump --mode transparent
        # --showhost -w '+package+'.trf'
        # mitm_cmd = 'mitmdump --mode transparent --showhost '\
        #    '--set confdir=./serts -w '+package+'.trf'
        mitm_postfix = "'/usr/bin/mitmdump --mode transparent --showhost '\
            '--set block_global=false'"
        mitm_cmd = 'echo '+su_pass + \
            ' | sudo -u mitmproxyuser -H bash -c '+mitm_postfix
        print('Starting the mitm: '+mitm_cmd)
        return subprocess.Popen(mitm_cmd, shell=True)
    except Exception:
        print('Error starting mitm!')


def unset_ipt_app(su_pass, magisk):
    """Отключение правил iptables
    """
    try:
        if magisk:
            ipt2_device = 'adb shell su -c "iptables -P OUTPUT ACCEPT"'
            ipt1_device = 'adb shell su -c "iptables -t nat -F"'
        else:
            ipt2_device = 'adb shell "su 0 iptables -P OUTPUT ACCEPT"'
            ipt1_device = 'adb shell "su 0 iptables -t nat -F"'
        ret_val = os.popen(ipt2_device).read()
        ret_val = os.popen(ipt1_device).read()
        try:
            ipt1_host = 'echo '+su_pass+' | sudo -S iptables -t nat -F'
            ret_val = os.popen(ipt1_host).read()
        except Exception:
            print('Error applying the rules on the host! '+ret_val)
    except Exception:
        print('Error applying the rules on the device! '+ret_val)


def run_apk(package, pause_sec):
    """Запускает основную активность ислледуемого APK
    """
    print('Starting: '+package)
    start_apk_cmd = "adb shell monkey -p " + package + \
        " -c android.intent.category.LAUNCHER 1"
    try:
        subprocess.Popen(start_apk_cmd, shell=True).communicate()
        time.sleep(pause_sec)
    except Exception:
        print('APK launch error!')


def stop_app(package):
    """Завершение приложения APK.
    """
    print('Stopping the apk.')
    try:
        stop_app = 'adb shell am force-stop '+package
        ret_val = os.popen(stop_app).read()
    except Exception:
        print('Error stopping the application! '+ret_val)


def stop_mitm(process):
    """Завершение приложения mitmdump.
    """
    print('Stopping the mitmdump.')
    try:
        get_pid = 'pgrep mitmdump'
        pid = os.popen(get_pid).read()
        try:
            if len(pid) != 0:
                print('Найденные pid: '+pid)
                stop_app = 'echo '+su_pass+' | sudo -S kill '+pid
                ret_val = os.popen(stop_app).read()
        except Exception:
            print('Error stopping the mitmdump! '+ret_val)
        process.kill()
    except Exception:
        print('The mitmdump pid was not found! '+ret_val)


if __name__ == '__main__':
    package = ''
    uid = ''
    type_p = None
    apk_file = None
    su_pass = None
    device_ip = None
    args = sys.argv[1:]
    optlist, args = getopt.getopt(
        args, 't:a:p:i:d:', ['type=', 'apk=', 'pass=', 'dev_ip=', 'delay='])
    try:
        type_p = next(filter(lambda x: x[0] == '--type', optlist), None)[1]
    except Exception:
        print('The --type parameter must be present!')
        raise SystemExit
    try:
        apk_file = next(filter(lambda x: x[0] == '--apk', optlist), None)[1]
    except Exception:
        print('The --apk parameter must be present!')
        raise SystemExit
    try:
        su_pass = next(filter(lambda x: x[0] == '--pass', optlist), None)[1]
    except Exception:
        print('The --pass parameter must be present!')
        raise SystemExit
    if type_p == 'd':
        try:
            device_ip = next(
                filter(lambda x: x[0] == '--dev_ip', optlist), None)[1]
        except Exception:
            if type_p == 'd':
                print('The --dev_ip parameter must be present!')
                raise SystemExit
    try:
        pause_sec = int(
            next(filter(lambda x: x[0] == '--delay', optlist), None)[1])
    except Exception:
        pause_sec = 10

    tdata = open_apk_jadx(apk_file)
    package = tdata[0]
    manifest = tdata[1]
    def_path = tdata[2]
    if len(package) != 0:
        read_manifest(manifest)
        get_frameworks_json(def_path)
        if device_present():
            install_apk(apk_file, package)
            uid = get_uid(package)
            magisk = get_magisk_su()
            set_iptables(uid, su_pass, device_ip, magisk, type_p)
            process = start_mitm()
            run_apk(package, pause_sec)
            stop_app(package)
            stop_mitm(process)
            unset_ipt_app(su_pass, magisk)
        else:
            print("No connected devices were detected!")
    else:
        print("Usage: python3 apkexp --type --apk --pass --dev_ip --delay")
