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
utils/ndmtk-analytics -i ${NDMTK_SRC_DIR} --interface-props --format json -o ${NDMTK_DST_DIR}/interface.props.json
utils/ndmtk-analytics --edge-discovery \
    --ip-interface-ref ${NDMTK_DST_DIR}/ip_interface.json \
    --arp-table-ref ${NDMTK_DST_DIR}/arp_entries.json \
    -o ${NDMTK_DST_DIR}/unregistered_edge_nodes.txt \
    --format csv -l 2
```
