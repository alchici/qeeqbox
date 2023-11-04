FROM docker.io/grafana/grafana:7.5.7
COPY ./postgres.yml /etc/grafana/provisioning/datasources/postgres.yml
COPY ./dashboards.yml /etc/grafana/provisioning/dashboards/dashboards.yml
COPY ./chameleon.json /var/lib/grafana/dashboards/chameleon.json
RUN grafana-cli plugins install grafana-worldmap-panel
# grafana-server --homepath=/usr/share/grafana --config=/etc/grafana/grafana.ini --packaging=docker ./import.sh cfg:default.log.mode=console cfg:default.pat