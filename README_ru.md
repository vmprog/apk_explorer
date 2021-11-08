# apk_explorer
Стенд для исследования трафика мобильных приложений.
Использование стенда возможно только на опреционной системе Linux.
Запуск возможен как с реальным устройством так и с эмулятором.

Для работы скрипта на host компьютере должны быть установлены:
Android SDK, которая является частью Anroid Studio - https://developer.android.google.cn/studio?hl=id 
Mitmproxy - https://mitmproxy.org/

Сценарий работы при использовании физического устройства т.е. телефона. Тестировалось на REDMI Note 6 armeabi-v7a Android 10 api 29 
 
1) Создание пользователя для изолиции mitmproxy.
sudo useradd --create-home mitmproxyuser
sudo -u mitmproxyuser -H bash -c 'cd ~ && pip install --user mitmproxy'

2) Первичный запуск mitmproxy для генерации сертификата.
sudo -u mitmproxyuser -H bash -c '$HOME/.local/bin/mitmproxy --mode transparent --showhost --set block_global=false'
После запуска жмем Ctrl-C для завершения mitmdump

3)Установка на устройство сертификата mitmproxy описана по ссылкам:
https://docs.mitmproxy.org/stable/howto-install-system-trusted-ca-android/ 
https://docs.mitmproxy.org/stable/concepts-certificates/
Файлы сертификата находятся с папке /home/mitmproxyuser/.mitmdump/

4) Создание образа docker.
$git clone https://github.com/vmprog/apk_explorer.git
$cd apk_explorer
$sudo docker build -t python-img:5.0 .

5) Настройка основного шлюза на устройстве
В меню телефона открываем "Настройки"-Wi-Fi-кликаем на свойства текущего подключения. Находим пункт "Настройки IP" меняем вариант
"DHCP" на "Пользовательские". Находим пункт "Шлюз" и указываем в нем IP адрес host машины на которой будет запускаться mitmdump.

6) Копирование в папку исследуемого приложения.
$cp base_mayak.apk /apk_explorer

7) Запуск образа docker
sudo docker run -it --net=host --privileged -v /dev/bus/usb:/dev/bus/usb --mount src="$(pwd)",target=/home/apkexp/apkexp_src,type=bind --mount src="/home/mitmproxyuser/.mitmproxy",target=/home/mitmproxyuser/.mitmproxy,type=bind  python-img:5.0 /bin/bash

8) Запуск скрпита стенда.
./apkexp.py --type d --apk base_mayak.apk --pass *** --dev_ip 192.168.1.66 --delay 20
где:
--type d задает тип подключенного устройства. d - device т.е. реальный телефон. 
--apk base_mayak.apk название мобильного приложения, которое добавлено в папку п.7.
--pass *** пароль для su.
--dev_ip 192.168.1.66 ip адрес мобильного устройства, подключенного через wifi к той же сети к которой подключен host компьютер
с mitmdump. 
--delay 20 задает время от запуска мобильного приложения до его закрытия в секундах.

Сценарий работы при использовании эмулятора из комплекта android SDK. Тестировалось на образах следующих конфигураций:
nexus 5x api 30 x86_32
nexus 5x api 29 x86_64
nexus 5x api 28 x86_64
 
1) Создание пользователя для изолиции mitmproxy.
sudo useradd --create-home mitmproxyuser
sudo -u mitmproxyuser -H bash -c 'cd ~ && pip install --user mitmproxy'
 
2) Первичный запуск mitmproxy для генерации сертификата.
sudo -u mitmproxyuser -H bash -c '$HOME/.local/bin/mitmproxy --mode transparent --showhost --set block_global=false'
После запуска жмем Ctrl-C для завершения mitmdump
 
3)Установка на устройство сертификата mitmproxy описана по ссылкам:
https://docs.mitmproxy.org/stable/howto-install-system-trusted-ca-android/
https://docs.mitmproxy.org/stable/concepts-certificates/
Файлы сертификата находятся с папке /home/mitmproxyuser/.mitmdump/
 
4) Создание образа docker.
$git clone https://github.com/vmprog/apk_explorer.git
$cd apk_explorer
$sudo docker build -t python-img:5.0 .
 
5) Копирование в папку исследуемого приложения.
$cp base_mayak.apk /apk_explorer
 
6) Запуск эмулируемого устройства.
./emulator -avd nexus_5x_30_x86_32 -gpu swiftshader_indirect -writable-system -no-snapshot -nocache -qemu -cpu host
Все параметры кроме -writable-system могут отличаться т.к. зависят среды выполнения. 

7) Запуск образа docker
sudo docker run -it --net=host --privileged -v /dev/bus/usb:/dev/bus/usb --mount src="$(pwd)",target=/home/apkexp/apkexp_src,type=b
 
8) Запуск скрпита стенда.
./apkexp.py --type e --apk base_mayak.apk --pass *** --delay 20
где:
--type e задает тип подключенного устройства. e - emulator т.е. эмулятор. 
--apk base_mayak.apk название мобильного приложения, которое добавлено в папку п.7.
--pass *** пароль для su.
--delay 20 задает время от запуска мобильного приложения до его закрытия в секундах.

