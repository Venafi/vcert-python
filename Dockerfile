FROM python:3.9-slim

WORKDIR /usr/src/app

RUN echo "pip==25.3 --hash=sha256:9655943313a94722b7774661c21049070f6bbb0a1516bf02f7c8d5d9201514cd" \
    > /tmp/pip-pin.txt && pip install --no-cache-dir --require-hashes -r /tmp/pip-pin.txt

COPY requirements-build.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements-build.txt

COPY . .

CMD [ "./docker-entrypoint.sh" ]
