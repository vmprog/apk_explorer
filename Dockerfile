##FROM python:3
#FROM rappdw/docker-java-python:openjdk1.8.0_171-python3.6.6

FROM python:3.9-slim
COPY --from=openjdk:11 /usr/local/openjdk-11 /usr/local/openjdk-11

ENV JAVA_HOME /usr/local/openjdk-11

RUN update-alternatives --install /usr/bin/java java /usr/local/openjdk-11/bin/java 1

RUN apt-get update && \
		apt-get -y install sudo &&\
		apt-get -y install gcc &&\
        apt-get install -y git


#RUN mkdir /home/jadx && \       
#          cd /home/jadx && \        
#          git clone https://github.com/skylot/jadx.git

RUN python -m venv venv
RUN venv/bin/python -m pip install --upgrade pip

# install required libraries
COPY requirements.txt .
RUN pip install -r requirements.txt

ENV user apkexp

RUN useradd -m -d /home/${user} ${user} && \
    chown -R ${user} /home/${user} && \
    adduser ${user} sudo && \
    echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

COPY --chown=apkexp:apkexp ./jadx/bin/ /usr/local/bin
COPY --chown=apkexp:apkexp ./jadx/lib/ /usr/local/lib

USER ${user}

WORKDIR /home/${user}/apkexp_src

RUN sudo apt-get -y install android-tools-adb && \
    sudo useradd --create-home mitmproxyuser && \
	sudo -u mitmproxyuser -H bash -c 'cd ~ && pip install --user mitmproxy' && \
	sudo apt-get -y install mitmproxy && \
    sudo apt-get -y install iptables && \
    sudo apt-get -y install procps
    
#RUN	mkdir -p /home/apkexp/apkexp_src/jadx && \
#	chown apkexp:apkexp -R /home/apkexp/apkexp_src/jadx && \
#    cd /home/apkexp/apkexp_src/jadx/ && \
#	git clone https://github.com/skylot/jadx.git
#    cd jadx && \
#    ./gradlew dist

#ADD ./sert /

EXPOSE 8080 8081

# Add jadx
#ADD ./jadx/bin/ /usr/local/bin
#ADD ./jadx/lib/ /usr/local/lib

# Add apk
#ADD *.apk /

#ENV JAVA_HOME /usr/lib/jvm/java-8-openjdk-amd64/
#RUN export JAVA_HOME

#ADD apkexp.py /
#CMD [ "python", "./apkexp.py" ]
#ENTRYPOINT ["python","./apkexp.py"]

