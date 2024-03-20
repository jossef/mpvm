FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
RUN apt-get update && apt-get install -y wget && apt-get clean
RUN mkdir utils
RUN wget https://sca-downloads.s3.amazonaws.com/cli/2.6.3/ScaResolver-linux64.tar.gz -O ./utils/ScaResolver-linux64.tar.gz
COPY main.py .
ENTRYPOINT ["python", "main.py"]