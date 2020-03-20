FROM python:3

WORKDIR /usr/src/app

COPY requirements.txt ./
COPY requirements-build.txt ./
COPY docker-entrypoint.sh ./
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -r requirements-build.txt

COPY . .

CMD [ "./docker-entrypoint.sh" ]