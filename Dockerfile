FROM python:3.7.5-stretch as requirements

ARG PIP_EXTRA_INDEX_URL

# installing dependencies ONLY
COPY setup.py ./
RUN \
    pip install --user -e . && \
    pip uninstall -y platform-secrets


FROM python:3.7.5-stretch AS service

WORKDIR /neuromation

COPY setup.py ./
COPY --from=requirements /root/.local /root/.local

# installing platform-secrets
COPY platform_secrets platform_secrets
RUN pip install --user -e .

ENV PATH=/root/.local/bin:$PATH

ENV NP_SECRETS_API_PORT=8080
EXPOSE $NP_SECRETS_API_PORT

CMD platform-secrets
