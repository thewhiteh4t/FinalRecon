FROM python:latest
WORKDIR /root
RUN git clone https://github.com/thewhiteh4t/finalrecon.git
WORKDIR /root/finalrecon/
RUN pip install wheel
RUN pip install -r requirements.txt
ENTRYPOINT ["python3", "finalrecon.py"]
