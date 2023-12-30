# Kali Linux latest with useful tools by tsumarios
FROM kalilinux/kali-rolling
# Install.

# Update
RUN apt -y update && DEBIAN_FRONTEND=noninteractive apt -y dist-upgrade && apt -y autoremove && apt clean

RUN apt-get install -y git && \
  apt-get install -y python3-pip && \
  apt-get install -y jadx && \
  apt-get install -y dex2jar && \
  rm -rf /var/lib/apt/lists/*

# RUN apt -y install git python3-pip jadx dex2jar grep

ENV PATH="/opt/gtk/bin:$PATH"

ENV TARGET_FILE=""

# Install OMSA
RUN git clone https://github.com/nktrinhtrinh/omsa.git 

WORKDIR /omsa
 
ENTRYPOINT python3 OMSA.py -p ./omsa-input/${TARGET_FILE} -l






