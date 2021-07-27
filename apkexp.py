#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import sys
import getpass
from pynput import keyboard

package = ""
user_app = ""
proc_mitm = 0

def open_apk(apk_file):
    ret   = 1
    write = 0
    global package
    Get_versions = 'aapt dump badging '+apk_file+' | grep "package: name="'
    Get_package_name = 'aapt dump badging '+apk_file+' | grep -o "package: name=\S*"'
    try:
        ret_val = os.popen(Get_versions).read()
        print(ret_val)
        
        package = os.popen(Get_package_name).read()
        package = package[package.index("'")+1:-2]
    except Exception:
        print('Aapt application error. '+package)
        ret = 0
    # Проверка на то, что папка не пустая. Вопрос. Перезаписать?
    if os.path.exists('./'+package):
        if len(os.listdir('./'+package+'/')) == 0:
            write = 0 #Временно            
        else:
            print('The folder is not empty. Overwrite it? Y(Yes),N(No).')
            answer=str(input())
            if answer == 'Y': 
                write = 1
            elif answer == 'N':
                write = 0
    else:
        write = 1 #Папки не существует. Записываем.
    
    if write == 1:
        SpaceCMD = "apktool d -o ./"+package+" -f "+apk_file
        try:
            ret_val = os.popen(SpaceCMD).read()
            print(ret_val)
        except Exception:
            print('Apktool application error. '+ret_val)
            ret = 0    
           
    return ret

def read_manifest():
    # Проверка на то, что папка не пустая. Вопрос. Перезаписать?
    # aapt dump badging base.apk | grep "package" #Вариант как можно получить название пакета
    ret = 1
    global package
    #Get_compileSdkVersion = "grep -o 'compileSdkVersion=\S*' ./apk/AndroidManifest.xml"
    #Get_package = "grep -o 'package\S*' ./apk/AndroidManifest.xml"
    Get_debuggable = "grep -o 'debuggable=\S*' ./"+package+"/AndroidManifest.xml"
    Get_uses_permission = "grep 'uses-permission' ./"+package+"/AndroidManifest.xml"     
    
    try:
        #package = os.popen(Get_package).read()
        #package = package[package.index('"')+1:-2]
        #print('App: '+package)
        
        ret_val = os.popen(Get_debuggable).read()
        print(ret_val)
        
        #ret_val = os.popen(Get_compileSdkVersion).read()
        #print(ret_val)
        
        ret_val = os.popen(Get_uses_permission).read()
        print(ret_val)
    except Exception:
        print('Error reading the manifest. '+ret_val)
        ret = 0
    return ret

def get_frameworks():
    fw_list = []
    
    #Godot
    ret_framework = ""
    test1_Godot = 'find ./'+package+'/ -name "libgodot_android.so"'     
    try:
        ret_val = os.popen(test1_Godot).read()
        if len(ret_val) != 0:
            ret_framework = "Godot"
    except Exception:
        ret_framework = ""
    if ret_framework != "":
        fw_list.append(ret_framework)
    
    #Unity_3D
    ret_framework = ""
    test1_Unity_3D = 'find ./'+package+'/ -name "libunity.so"'
    test2_Unity_3D = 'find ./'+package+'/ -name "libmono.so"'     
    test3_Unity_3D = 'find ./'+package+'/ -name "libil2cpp.so"'
    try:
        ret_val = os.popen(test1_Unity_3D).read()
        if len(ret_val) != 0:
            ret_framework = "Unity_3D"
        ret_val = os.popen(test2_Unity_3D).read()
        if ret_framework == "" and len(ret_val) != 0:
            ret_framework = "Unity_3D"
        ret_val = os.popen(test3_Unity_3D).read()
        if ret_framework == "" and len(ret_val) != 0:
            ret_framework = "Unity_3D"    
    except Exception:
        ret_framework = ""
    if ret_framework != "":
        fw_list.append(ret_framework)    
    
    #Apache_Cordova
    ret_framework = ""
    test1_Apache_Cordova = 'find ./'+package+'/ -name "cordova.js"'
    test2_Apache_Cordova = 'find ./'+package+'/ -name "index.html"'     
    try:
        ret_val1 = os.popen(test1_Apache_Cordova).read()
        ret_val2 = os.popen(test2_Apache_Cordova).read()
        if len(ret_val1) != 0 and len(ret_val2) != 0:
            ret_framework = "Apache_Cordova"
    except Exception:
        ret_framework = ""
    if ret_framework != "":
        fw_list.append(ret_framework)    
    
    #Ionic_Framework
    ret_framework = ""
    test1_Ionic_Framework = 'grep -rn "<ion-side-menus>" ./'+package+'/'
    test2_Ionic_Framework = 'grep -rn "<ion-nav-bar>" ./'+package+'/'     
    test3_Ionic_Framework = 'grep -rn "<ion-nav-buttons>" ./'+package+'/'
    try:
        ret_val = os.popen(test1_Ionic_Framework).read()
        if len(ret_val) != 0:
            ret_framework = "Ionic_Framework"
        ret_val = os.popen(test2_Ionic_Framework).read()
        if ret_framework == "" and len(ret_val) != 0:
            ret_framework = "Ionic_Framework"
        ret_val = os.popen(test3_Ionic_Framework).read()
        if ret_framework == "" and len(ret_val) != 0:
            ret_framework = "Ionic_Framework"    
    except Exception:
        ret_framework = ""
    if ret_framework != "":
        fw_list.append(ret_framework)    
    
    #Cocos2d
    ret_framework = ""
    test1_Cocos2d = 'grep -rn "Cocos2dx" ./'+package+'/'
    try:
        ret_val = os.popen(test1_Cocos2d).read()
        if len(ret_val) != 0:
            ret_framework = "Cocos2d"
    except Exception:
        ret_framework = ""
    if ret_framework != "":
        fw_list.append(ret_framework)
    
    
    #React Native (facebook) #https://stackoverflow.com/questions/44302269/how-do-i-detect-if-the-app-uses-react-native-given-apk-file
    ret_framework = ""
    test1_React_Native = 'find ./'+package+'/ -type d -name "react"'
    test2_React_Native = 'find ./'+package+'/ -name "libreactnativejni.so"'     
    try:
        ret_val = os.popen(test1_React_Native).read()
        if len(ret_val) != 0:
            ret_framework = "React Native"
        else: 
            ret_val = os.popen(test2_React_Native).read()
            if len(ret_val) != 0:
                ret_framework = "React Native"
    except Exception:
        ret_framework = ""     
    if ret_framework != "":
        fw_list.append(ret_framework) 
        
    #Flutter (google) #https://stackoverflow.com/questions/58181186/how-to-determine-if-an-app-is-native-or-flutter
    #https://www.reddit.com/r/FlutterDev/comments/cmxqlx/how_to_know_if_an_app_is_made_with_flutter/
    #libapp.so
    #Примеры на Flutter https://www.thedroidsonroids.com/blog/apps-made-with-flutter
    ret_framework = ""
    test1_Flutter = 'find ./'+package+'/ -type d -name "flutter"'
    test2_Flutter = 'find ./'+package+'/ -name "libflutter.so"'     
    try:
        ret_val = os.popen(test1_Flutter).read()
        if len(ret_val) != 0:
            ret_framework = "Flutter"
        else: 
            ret_val = os.popen(test2_Flutter).read()
            if len(ret_val) != 0:
                ret_framework = "Flutter"
    except Exception:
        ret_framework = ""
    if ret_framework != "":
        fw_list.append(ret_framework)
    
    #Xamarin
    #PhoneGap
    #Framework 7
    #Monaca
    #Mobile Angular UI
    #jQuery Mobile
    #Appcelerator Titanium
    #Corona SDK
    #Onsen UI
    #NativeScript
    #Sencha Ext JS
            
    print(fw_list)
    return ret_framework    
    

def device_present():
    ret = 1
    Get_devices = "adb devices | grep device$"
    try:
        ret_val = os.popen(Get_devices).read()
        if len(ret_val) < 1:
            ret = 0
    except Exception:
        ret = 0
    return ret

def install_apk(apk_file):
    ret = 1
    global package
    Get_install_status = 'adb shell pm list packages | grep '+package
    Install_package = 'adb install '+apk_file
    try:
        ret_val = os.popen(Get_install_status).read()
        if len(ret_val) != 0:    
            print('The package '+package+' is already installed.')
        else:
            print('Installing the package: '+package+'.')
            try:
                ret_val = os.popen(Install_package).read()
                print(ret_val)
            except Exception:
                print('Package Installation error!')
        ret = 0
    except Exception:
        print('Error when getting installed applications!')
        ret = 0
    return ret

def run_apk():
    ret = 1
    global package
    global user_app
    print('Starting: '+package)
    #aapt dump badging base.apk | grep "launchable-activity" #Так можно получить запускаемые активности
    #adb shell am start -n <package>/<activity> #Так можно запустить конкретную активность.
    Start_apk_CMD    = "adb shell monkey -p "+ package +" -c android.intent.category.LAUNCHER 1"
    Get_user_CMD = 'adb shell su -c "ps -A" | grep '+package+' | grep -o "^\S*"'
    try:
        ret_val = os.popen(Start_apk_CMD).read()
        #print(ret_val)
        try:
            user_app = os.popen(Get_user_CMD).read()
            user_app = user_app[:-1]
        except Exception:
            print('Error getting the application user name!')
            ret = 0
    except Exception:
        print('APK launch error!')
        ret = 0
    return ret

def set_iptables(net_interface):
    ret = 1
    #Запрос пароля для запуска iptable
    print("To configure the iptable, you must enter the password su:")
    p = getpass.getpass()
    
    #Get_user_CMD = 'adb shell su -c "ps -A" | grep '+package+' | grep -o "^\S*"'
    #try:
        #user_app = os.popen(Get_user_CMD).read()
        #user_app = user_app[:-1]
    try: #Настраиваем устройство
        ipt1_device = 'adb shell su -c "iptables -P OUTPUT DROP"'
        ret_val = os.popen(ipt1_device).read()
        ipt2_device = 'adb shell su -c "iptables -P OUTPUT ACCEPT -m owner --uid-owner '+user_app+'"'
        ret_val = os.popen(ipt2_device).read()
        try: #Настраиваем host
            ipt1_host = 'echo '+p+' | sudo -S iptables -t nat -F'
            ret_val = os.popen(ipt1_host).read()
            ipt2_host = 'echo '+p+' | sudo -S sysctl -w net.ipv4.ip_forward=1'
            ret_val = os.popen(ipt2_host).read()
            ipt3_host = 'echo '+p+' | sudo sysctl -w net.ipv6.conf.all.forwarding=1'
            ret_val = os.popen(ipt3_host).read()
            ipt4_host = 'echo '+p+' | sudo sysctl -w net.ipv4.conf.all.send_redirects=0'
            ret_val = os.popen(ipt4_host).read()
            ipt5_host = 'echo '+p+' | sudo iptables -t nat -A PREROUTING -i '+net_interface+' -p tcp --dport 80 -j REDIRECT --to-port 8080 '
            ret_val = os.popen(ipt5_host).read()
            ipt6_host = 'echo '+p+' | sudo iptables -t nat -A PREROUTING -i '+net_interface+' -p tcp --dport 443 -j REDIRECT --to-port 8080 '
            ret_val = os.popen(ipt6_host).read()
        except Exception:
            print('Error applying the rules on the host!')
            ret = 0
    except Exception:
        print('Error applying the rules on the device!')
        ret = 0
    return ret

def start_mitm():
    ret = 1
    try:
        mitm_cmd = 'mitmdump --mode transparent --showhost -w '+package+'.trf'
        print('Starting the mitm: '+mitm_cmd)
        #ret_val = os.popen(mitm_cmd,'r')
        global proc_mitm
        proc_mitm = subprocess.Popen(mitm_cmd, shell=True).communicate() 
                      
    except KeyboardInterrupt:
        print('Stopping the mitm!')
        #proc_mitm.kill()
        ret = 0
    return ret

def unset_ipt_app():
    ret = 1
    try: 
        ipt2_device = 'adb shell su -c "iptables -P OUTPUT ACCEPT"'
        ret_val = os.popen(ipt2_device).read()
    except Exception:
        print('Error applying the rules on the device!')
        ret = 0
    
    try: 
        Stop_app = 'adb shell am force-stop '+package
        ret_val = os.popen(Stop_app).read()
    except Exception:
        print('Error stopping the application!')
        ret = 0
    
    return ret

def on_press(key):
    try:
        print('alphanumeric key {0} pressed'.format(key.char))
        proc_mitm.kill()
    except AttributeError:
        print('special key {0} pressed'.format(key))
    # Stop listener
    return False    

def keyboardListen():
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()
            
if __name__ == '__main__':
    if len (sys.argv) == 3:
        apk_file = sys.argv[1]
        net_interface = sys.argv[2]
        ret = open_apk(apk_file)
        if ret!=0:
            #thread_ = threading.Thread(target=keyboardListen)
            #thread_.start()
            read_manifest()
            get_frameworks()
            if device_present() == 1:
                install_apk(apk_file)
                run_apk()
                set_iptables(net_interface)
                start_mitm()
                unset_ipt_app()
            else:
                print("No connected devices were detected!")
    else:
        print("Usage: python apkexp some.apk netinterface")
                        
