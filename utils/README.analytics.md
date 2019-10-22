# Analytics

This sequence of commands helps parsing data from a data collection:

```bash
export NDMTK_SRC_DIR=/opt/data/ansible/network/2019/12/12
export NDMTK_DST_DIR=~/workbench/network/data
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --ip-interfaces --format json -o ${NDMTK_DST_DIR}/ip_interface.json
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --device-info --format json -o ${NDMTK_DST_DIR}/device_info.json
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --arp-entries --mac-vendor-ref /opt/ouidb/oui.txt --format json -o ${NDMTK_DST_DIR}/arp_entries.json
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --syslog-servers --format json -o ${NDMTK_DST_DIR}/syslog_servers.json
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --snmp-servers --format json -o ${NDMTK_DST_DIR}/snmp_servers.json
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --local-users --format json -o ${NDMTK_DST_DIR}/local_users.json
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --ntp-servers --format json -o ${NDMTK_DST_DIR}/ntp_servers.json
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --aaa-servers --format json -o ${NDMTK_DST_DIR}/aaa_servers.json
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --lldp-neighbors --format json -o ${NDMTK_DST_DIR}/lldp_neighbors.json
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --ospf-neighbors --format json -o ${NDMTK_DST_DIR}/ospf_neighbors.json
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --interface-props --format json -o ${NDMTK_DST_DIR}/interface_props.json
utils/ndmtk-analytics --edge-discovery \
    --ip-interface-ref ${NDMTK_DST_DIR}/ip_interface.json \
    --arp-table-ref ${NDMTK_DST_DIR}/arp_entries.json \
    -o ${NDMTK_DST_DIR}/unregistered_edge_nodes.txt \
    --format csv -l 2
```

Additionally, the same utility could be used to bulk upload the data to Elasticsearch:

```bash
export NDMTK_SRC_DIR=/opt/data/ansible/network/2019/12/12
export NDMTK_DST_DIR=/opt/data/ansible/elasticsearch/20191212.090000
export NDMTK_ES_INDEX_SUFFIX=neteng-20191212-090000
export NDMTK_ES_TS=2019-12-12T09:00:00.000000-0000
export NDMTK_OUT_FMT=elasticsearch
export NDMTK_ES_URL=http://localhost:9200/_bulk
```

Next, configure Elasticsearch index management and patterns:

```bash
TBD
```

Process the files to generate Elasticsearch bulk upload compatible output:

```bash
mkdir -p ${NDMTK_DST_DIR}
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --ip-interfaces --format ${NDMTK_OUT_FMT} -o ${NDMTK_DST_DIR}/ip_interface.json --elasticsearch-index ${NDMTK_ES_INDEX}
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --device-info --format ${NDMTK_OUT_FMT} -o ${NDMTK_DST_DIR}/device_info.json --elasticsearch-index neteng-device-info-${NDMTK_ES_INDEX_SUFFIX} --elasticsearch-timestamp "${NDMTK_ES_TS}"
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --arp-entries --mac-vendor-ref /opt/ouidb/oui.txt --format ${NDMTK_OUT_FMT} -o ${NDMTK_DST_DIR}/arp_entries.json --elasticsearch-index neteng-arp-entries-${NDMTK_ES_INDEX_SUFFIX} --elasticsearch-timestamp "${NDMTK_ES_TS}"
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --syslog-servers --format ${NDMTK_OUT_FMT} -o ${NDMTK_DST_DIR}/syslog_servers.json --elasticsearch-index neteng-syslog-servers-${NDMTK_ES_INDEX_SUFFIX} --elasticsearch-timestamp "${NDMTK_ES_TS}"
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --snmp-servers --format ${NDMTK_OUT_FMT} -o ${NDMTK_DST_DIR}/snmp_servers.json --elasticsearch-index neteng-snmp-servers-${NDMTK_ES_INDEX_SUFFIX} --elasticsearch-timestamp "${NDMTK_ES_TS}"
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --local-users --format ${NDMTK_OUT_FMT} -o ${NDMTK_DST_DIR}/local_users.json --elasticsearch-index neteng-local-users-${NDMTK_ES_INDEX_SUFFIX} --elasticsearch-timestamp "${NDMTK_ES_TS}"
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --ntp-servers --format ${NDMTK_OUT_FMT} -o ${NDMTK_DST_DIR}/ntp_servers.json --elasticsearch-index neteng-ntp-servers-${NDMTK_ES_INDEX_SUFFIX} --elasticsearch-timestamp "${NDMTK_ES_TS}"
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --aaa-servers --format ${NDMTK_OUT_FMT} -o ${NDMTK_DST_DIR}/aaa_servers.json --elasticsearch-index neteng-aaa-servers-${NDMTK_ES_INDEX_SUFFIX} --elasticsearch-timestamp "${NDMTK_ES_TS}"
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --lldp-neighbors --format ${NDMTK_OUT_FMT} -o ${NDMTK_DST_DIR}/lldp_neighbors.json --elasticsearch-index neteng-lldp-neighbors-${NDMTK_ES_INDEX_SUFFIX} --elasticsearch-timestamp "${NDMTK_ES_TS}"
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --ospf-neighbors --format ${NDMTK_OUT_FMT} -o ${NDMTK_DST_DIR}/ospf_neighbors.json --elasticsearch-index neteng-ospf-neighbors-${NDMTK_ES_INDEX_SUFFIX} --elasticsearch-timestamp "${NDMTK_ES_TS}"
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --interface-props --format ${NDMTK_OUT_FMT} -o ${NDMTK_DST_DIR}/interface_props.json --elasticsearch-index neteng-interface-props-${NDMTK_ES_INDEX_SUFFIX} --elasticsearch-timestamp "${NDMTK_ES_TS}"
```

Then, user `curl` to upload the data:


```bash
curl --insecure -H "Content-Type: application/x-ndjson" -XPOST ${NDMTK_ES_URL} --data-binary @${NDMTK_DST_DIR}/ip_interface.json
```
