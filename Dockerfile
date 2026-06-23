FROM python:3.9-slim

WORKDIR /usr/src/app

# Pin pip to CVE-safe version (25.0.1 has 4 CVEs; 25.3 is latest 3.9-compatible fix).
# pip cannot be included in requirements-build.txt (pip-tools excludes the package manager).
RUN pip install --no-cache-dir pip==25.3

COPY requirements-build.txt ./
COPY docker-entrypoint.sh ./
RUN pip install --no-cache-dir --require-hashes -r requirements-build.txt

COPY . .

CMD [ "./docker-entrypoint.sh" ]
