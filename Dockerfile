FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY sigilant ./sigilant
COPY rules ./rules
COPY config ./config
COPY data ./data
RUN pip install --no-cache-dir -e . && useradd -m soc
USER soc
ENTRYPOINT ["sigilant"]
CMD ["run", "--input", "/logs", "--out", "/output", "--offline"]
