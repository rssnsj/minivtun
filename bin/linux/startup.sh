#!/bin/sh
PKG_NAME=minivtun
BIN_FILE=/opt/minivtun/bin/minivtun
PID_FILE=/var/run/minivtun.pid
CODE='secret'

${BIN_FILE} -r host:port -a 10.2.3.4/24 -n minivtun-go0 -e ${CODE} -t aes-128 -d
PID=`pidof ${PKG_NAME}`
echo ${PID} >${PID_FILE}
echo "${PKG_NAME} started"

exit 0
