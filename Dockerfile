##FROM python:3
#FROM rappdw/docker-java-python:openjdk1.8.0_171-python3.6.6

FROM python:3.9-slim
COPY --from=openjdk:11 /usr/local/openjdk-11 /usr/local/openjdk-11

ENV JAVA_HOME /usr/local/openjdk-11

RUN update-alternatives --install /usr/bin/java java /usr/local/openjdk-11/bin/java 1

ENV PATH=${PATH}:$JAVA_HOME/bin

RUN apt-get update && \
		apt-get -y install sudo &&\
		apt-get -y install gcc &&\
        apt-get install -y git

RUN python -m venv venv
RUN venv/bin/python -m pip install --upgrade pip

# install required libraries
COPY requirements.txt .
RUN pip install -r requirements.txt

ENV user researcher

RUN useradd -m -d /home/${user} ${user} && \
    chown -R ${user} /home/${user} && \
    adduser ${user} sudo && \
    echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

COPY --chown=researcher:researcher ./jadx/bin/ /usr/local/bin
COPY --chown=researcher:researcher ./jadx/lib/ /usr/local/lib

USER ${user}

WORKDIR /home/${user}/app_src

RUN sudo apt-get -y install android-tools-adb && \
    sudo useradd --create-home mitmproxyuser && \
	sudo -u mitmproxyuser -H bash -c 'cd ~ && pip install --user mitmproxy' && \
	sudo apt-get -y install mitmproxy && \
    sudo apt-get -y install iptables && \
    sudo apt-get -y install procps && \
	sudo apt-get -y install aapt && \
	sudo apt-get -y install xxd

EXPOSE 8080 8081

