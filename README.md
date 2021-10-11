# apk_explorer

Tested on linux

Installation Instructions

    Run make nb to build Newsblur containers. This will set up all necessary databases, celery tasks, node applications, flask database monitor, NGINX, and a Haproxy load balancer.
    Navigate to:
        https://localhost


Плюс README нужно дополнить всей информацией по подготовке среды:

    Как готовить девайс (или все-таки эмулятор подойдет?)
    Как его подготовить к разбору трафика? Для mitmproxy сертификат надо в системный сторадж засунуть - нужна инструкция или ссылка на документацию.
    На чем запускать?



    На какой платформе запускать (линукс? на маке заведется?)
    Какой софт должен быть установлен? Видимо Android SDK и mitmproxy? А нельзя docker-образ подготовить со всем нужным софтом просто? (вопрос на будущее скорее)
    Какая версия питона нужна?

Скопировать сертификаты из ./mitmdump в папку /serts

А в requirements.txt обычно держат зависимости которые для питона нужны.


Before using, you must change the ip address
of the gateway in the device to the address
where the script and mitmdump will be launched.

Before using, you must disable IPv6 protocol.
For devices:
If you are using mobile internet, you should
find the following setting: Access Point Names
->APN protocol and set IPv4 only.

If you are using WIFI, you should
find the protocol selection setting in the
settings menu of your access point and set
IPv4 only.

sudo apt install apktool
sudo apt install mitmproxy


Usage: python3 apkexp some.apk su_pass puse_sec
