FROM python:3.9.0

WORKDIR /source

RUN apt update && apt install -y vim

COPY source/requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY source/client client/
COPY source/server server/

COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]


