#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import sys
import getpass
import time


def open_apk(apk_file):
    """Разархивирует APK-файл и достает
    из него package name и версии сборки и SDK.
    Возвращает имя пакета и UID при успешном завершении
    """
    write = 0
    package = ''
    uid = ''
    get_versions = 'aapt dump badging '+apk_file+' | grep "package: name="'
    get_package_name = 'aapt dump badging ' + \
        apk_file+' | grep -o "package: name=\S*"'
    try:
        ret_val = os.popen(get_versions).read()
        print(ret_val)
        package = os.popen(get_package_name).read()
        package = package[package.index("'")+1:-2]
        try:
            get_uid = "adb shell dumpsys  package  " + package + " | grep -o 'userId=\S*'"
            uid = os.popen(get_uid).read()
            uid = uid[uid.index("=")+1:-1]
            print('UID:='+uid)
        except Exception:
            print('Error when getting the uid. '+uid)
    except Exception:
        print('Aapt application error. '+package)
    if os.path.exists('./'+package):  # Проверка существует ли папка.
        if len(os.listdir('./'+package+'/')) == 0:
            write = 1  # Папка пустая. Можно записывать.
        else:
            print('The folder is not empty. Overwrite it? Y(Yes),N(No).')
            answer = str(input())
            if answer == 'Y':
                write = 1
            elif answer == 'N':
                write = 0
    else:
        write = 1  # Папки не существует. Записываем.

    if write == 1:
        space_cmd = "apktool d -o ./"+package+" -f "+apk_file
        try:
            ret_val = os.popen(space_cmd).read()
            print(ret_val)
        except Exception:
            print('Apktool application error. '+ret_val)
    return(package, uid)


def read_manifest(package):
    """Читает AndroidManifest.xml и извлекает
    из него метаданные.
    """
    # aapt dump badging base.apk | grep "package"
    # Вариант как можно получить название пакета
    # Get_compileSdkVersion = "grep -o 'compileSdkVersion=\S*' ./apk/AndroidManifest.xml"
    # Get_package = "grep -o 'package\S*' ./apk/AndroidManifest.xml"
    get_debuggable = "grep -o 'debuggable=\S*' ./"+package+"/AndroidManifest.xml"
    get_uses_permission = "grep 'uses-permission' ./"+package+"/AndroidManifest.xml"
    try:
        ret_val = os.popen(get_debuggable).read()
        print(ret_val)
        ret_val = os.popen(get_uses_permission).read()
        print(ret_val)
    except Exception:
        print('Error reading the manifest. '+ret_val)


def get_frameworks(package):
    """Анализирует файлы APK и детектирует
    используемые фреймворки.
    """
    fw_list = []
    print('Defining frameworks!')

    # Godot
    ret_framework = ""
    test1_godot = 'find ./'+package+'/ -name "libgodot_android.so"'
    try:
        ret_val = os.popen(test1_godot).read()
        if len(ret_val) != 0:
            ret_framework = "Godot"
    except Exception:
        ret_framework = ""
    if ret_framework != "":
        fw_list.append(ret_framework)

    # Unity_3D
    ret_framework = ""
    test1_unity_3d = 'find ./'+package+'/ -name "libunity.so"'
    test2_unity_3d = 'find ./'+package+'/ -name "libmono.so"'
    test3_unity_3d = 'find ./'+package+'/ -name "libil2cpp.so"'
    try:
        ret_val = os.popen(test1_unity_3d).read()
        if len(ret_val) != 0:
            ret_framework = "Unity_3D"
        ret_val = os.popen(test2_unity_3d).read()
        if ret_framework == "" and len(ret_val) != 0:
            ret_framework = "Unity_3D"
        ret_val = os.popen(test3_unity_3d).read()
        if ret_framework == "" and len(ret_val) != 0:
            ret_framework = "Unity_3D"
    except Exception:
        ret_framework = ""
    if ret_framework != "":
        fw_list.append(ret_framework)

    # Apache_Cordova
    ret_framework = ""
    test1_apache_cordova = 'find ./'+package+'/ -name "cordova.js"'
    test2_apache_cordova = 'find ./'+package+'/ -name "index.html"'
    try:
        ret_val1 = os.popen(test1_apache_cordova).read()
        ret_val2 = os.popen(test2_apache_cordova).read()
        if len(ret_val1) != 0 and len(ret_val2) != 0:
            ret_framework = "Apache_Cordova"
    except Exception:
        ret_framework = ""
    if ret_framework != "":
        fw_list.append(ret_framework)

    # Ionic_Framework
    ret_framework = ""
    test1_ionic_framework = 'grep -rn "<ion-side-menus>" ./'+package+'/'
    test2_ionic_framework = 'grep -rn "<ion-nav-bar>" ./'+package+'/'
    test3_ionic_framework = 'grep -rn "<ion-nav-buttons>" ./'+package+'/'
    try:
        ret_val = os.popen(test1_ionic_framework).read()
        if len(ret_val) != 0:
            ret_framework = "Ionic_Framework"
        ret_val = os.popen(test2_ionic_framework).read()
        if ret_framework == "" and len(ret_val) != 0:
            ret_framework = "Ionic_Framework"
        ret_val = os.popen(test3_ionic_framework).read()
        if ret_framework == "" and len(ret_val) != 0:
            ret_framework = "Ionic_Framework"
    except Exception:
        ret_framework = ""
    if ret_framework != "":
        fw_list.append(ret_framework)

    # Cocos2d
    ret_framework = ""
    test1_cocos2d = 'grep -rn "Cocos2dx" ./'+package+'/'
    try:
        ret_val = os.popen(test1_cocos2d).read()
        if len(ret_val) != 0:
            ret_framework = "Cocos2d"
    except Exception:
        ret_framework = ""
    if ret_framework != "":
        fw_list.append(ret_framework)

    # React Native (facebook) #https://stackoverflow.com/questions/44302269/how-do-i-detect-if-the-app-uses-react-native-given-apk-file
    ret_framework = ""
    test1_react_native = 'find ./'+package+'/ -type d -name "react"'
    test2_react_native = 'find ./'+package+'/ -name "libreactnativejni.so"'
    try:
        ret_val = os.popen(test1_react_native).read()
        if len(ret_val) != 0:
            ret_framework = "React Native"
        else:
            ret_val = os.popen(test2_react_native).read()
            if len(ret_val) != 0:
                ret_framework = "React Native"
    except Exception:
        ret_framework = ""
    if ret_framework != "":
        fw_list.append(ret_framework)

    # Flutter (google) #https://stackoverflow.com/questions/58181186/how-to-determine-if-an-app-is-native-or-flutter
    # https://www.reddit.com/r/FlutterDev/comments/cmxqlx/how_to_know_if_an_app_is_made_with_flutter/
    # libapp.so
    # Примеры на Flutter https://www.thedroidsonroids.com/blog/apps-made-with-flutter
    ret_framework = ""
    test1_flutter = 'find ./'+package+'/ -type d -name "flutter"'
    test2_flutter = 'find ./'+package+'/ -name "libflutter.so"'
    try:
        ret_val = os.popen(test1_flutter).read()
        if len(ret_val) != 0:
            ret_framework = "Flutter"
        else:
            ret_val = os.popen(test2_flutter).read()
            if len(ret_val) != 0:
                ret_framework = "Flutter"
    except Exception:
        ret_framework = ""
    if ret_framework != "":
        fw_list.append(ret_framework)

    # Xamarin
    # PhoneGap
    # Framework 7
    # Monaca
    # Mobile Angular UI
    # jQuery Mobile
    # Appcelerator Titanium
    # Corona SDK
    # Onsen UI
    # NativeScript
    # Sencha Ext JS

    print(fw_list)
    return ret_framework


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


def set_iptables(uid, su_pass):
    """Настройка iptables на устройстве и на
    компьютере с mitmproxy
    """
    try:  # Настраиваем устройство
        ipt1_device = 'adb shell su -c "iptables -P OUTPUT DROP"'
        ret_vald = os.popen(ipt1_device).read()
        ipt2_device = 'adb shell su -c "iptables -P OUTPUT ACCEPT -m owner --uid-owner '+uid+'"'
        ret_vald = os.popen(ipt2_device).read()
        try:  # Настраиваем host
            ipt1_host = 'echo '+su_pass+' | sudo -S iptables -t nat -F'
            ret_val = os.popen(ipt1_host).read()
            ipt2_host = 'echo '+su_pass+' | sudo -S sysctl -w net.ipv4.ip_forward=1'
            ret_val = os.popen(ipt2_host).read()
            ipt3_host = 'echo '+su_pass+' | sudo sysctl -w net.ipv6.conf.all.forwarding=1'
            ret_val = os.popen(ipt3_host).read()
            ipt4_host = 'echo '+su_pass+' | sudo sysctl -w net.ipv4.conf.all.send_redirects=0'
            ret_val = os.popen(ipt4_host).read()
            ipt5_host = 'echo '+su_pass + \
                ' | sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080'
            ret_val = os.popen(ipt5_host).read()
            ipt6_host = 'echo '+su_pass + \
                ' | sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080'
            ret_val = os.popen(ipt6_host).read()
            # ipt7_host = 'echo '+su_pass + \
            #    ' | sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 8080'
            # ret_val = os.popen(ipt7_host).read()
        except Exception:
            print('Error applying the rules on the host! '+ret_val)
    except Exception:
        print('Error applying the rules on the device! '+ret_vald)


def start_mitm():
    """Запуск proxydump в прозрачном режиме
    """
    try:
        mitm_cmd = 'mitmdump --mode transparent --showhost -w '+package+'.trf'
        print('Starting the mitm: '+mitm_cmd)
        proc_mitm = subprocess.Popen(mitm_cmd, shell=True)
    except Exception:
        print('Error starting mitm! '+ret_val)


def unset_ipt_app(su_pass):
    """Отключение правил iptables
    """
    try:
        ipt2_device = 'adb shell su -c "iptables -P OUTPUT ACCEPT"'
        ret_val = os.popen(ipt2_device).read()
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
        proc_apk = subprocess.Popen(start_apk_cmd, shell=True).communicate()
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


def stop_mitm():
    """Завершение приложения mitmdump.
    """
    print('Stopping the mitmdump.')
    try:
        get_pid = 'pgrep mitmdump'
        pid = os.popen(get_pid).read()
        try:
            if len(pid) != 0:
                stop_app = 'kill '+pid
                ret_val = os.popen(stop_app).read()
        except Exception:
            print('Error stopping the mitmdump! '+ret_val)
    except Exception:
        print('The mitmdump pid was not found! '+ret_val)


if __name__ == '__main__':
    package = ''
    uid = ''
    if len(sys.argv) >= 3:
        apk_file = sys.argv[1]
        su_pass = sys.argv[2]
        pause_sec = 10
        if len(sys.argv) == 4:  # Передан параметр ожидания после запуска приложения
            pause_sec = int(sys.argv[3])
        tdata = open_apk(apk_file)
        package = tdata[0]
        uid = tdata[1]
        if len(package) != 0:
            read_manifest(package)
            # get_frameworks(package)
            if device_present():
                install_apk(apk_file, package)
                set_iptables(uid, su_pass)
                start_mitm()
                run_apk(package, pause_sec)
                stop_app(package)
                stop_mitm()
                unset_ipt_app(su_pass)
            else:
                print("No connected devices were detected!")
    else:
        print("Usage: python3 apkexp some.apk su_pass puse_sec")
