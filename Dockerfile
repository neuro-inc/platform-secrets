ARG PY_VERSION=3.13

FROM python:${PY_VERSION}-slim-bullseye AS builder

ENV PATH=/root/.local/bin:$PATH

WORKDIR /tmp
COPY requirements.txt /tmp/

# Copy to tmp folder to don't pollute home dir
RUN pip install --user --no-cache-dir -r requirements.txt

COPY dist /tmp/dist/
RUN pip install --user --no-cache-dir --find-links /tmp/dist platform-secrets \
    && rm -rf /tmp/dist

FROM python:${PY_VERSION}-slim-bullseye as service
LABEL org.opencontainers.image.source="https://github.com/neuro-inc/platform-secrets"

WORKDIR /app

# Name of your service (folder under /home)
ARG SERVICE_NAME="platform-secrets"
ARG SERVICE_UID=1001
ARG SERVICE_GID=1001

RUN addgroup --gid $SERVICE_GID $SERVICE_NAME && \
    adduser --uid $SERVICE_UID --gid $SERVICE_GID \
    --home /home/$SERVICE_NAME --shell /bin/false \
    --disabled-password --gecos "" $SERVICE_NAME

# Tell Python where the "user" site is
ENV HOME=/home/${SERVICE_NAME}
ENV PYTHONUSERBASE=/home/${SERVICE_NAME}/.local
ENV PATH=/home/${SERVICE_NAME}/.local/bin:$PATH

# Copy everything from the builder’s user‐site into your service’s user‐site
COPY --from=builder --chown=$SERVICE_NAME:$SERVICE_GID /root/.local /home/${SERVICE_NAME}/.local

WORKDIR /app

USER $SERVICE_NAME
ENV NP_SECRETS_API_PORT=8080
EXPOSE $NP_SECRETS_API_PORT

CMD ["platform-secrets"]
