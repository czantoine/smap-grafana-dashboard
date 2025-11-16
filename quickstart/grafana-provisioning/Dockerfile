FROM grafana/grafana:latest

USER root

# Datasource
COPY ./grafana-provisioning/datasources/datasource.yml /etc/grafana/provisioning/datasources/default.yml

# Dashboards provisioning
COPY ./grafana-provisioning/dashboards/dashboards.yml /etc/grafana/provisioning/dashboards/smap.yml

RUN mkdir -p /var/lib/grafana/dashboards

RUN curl -L -o /var/lib/grafana/dashboards/smap.json \
    https://grafana.com/api/dashboards/24085/revisions/1/download && \
    sed -i 's/\${DS_SQLITE}/SQLite/g' /var/lib/grafana/dashboards/smap.json
