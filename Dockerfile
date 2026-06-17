FROM python:3.9-slim

WORKDIR /usr/src/app

COPY requirements.txt ./
COPY requirements-build.txt ./
COPY docker-entrypoint.sh ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
RUN pip install --no-cache-dir --require-hashes -r requirements-build.txt

COPY . .

CMD [ "./docker-entrypoint.sh" ]
