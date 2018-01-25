#!/bin/sh
PKG_NAME=minivtun
BIN_FILE=/opt/minivtun/bin/minivtun
PID_FILE=/var/run/minivtun.pid
if [ -e ${PID_FILE} ]; then
  PID=`cat ${PID_FILE}`
  kill $PID > /dev/null 2>&1
  rm -f ${PID_FILE}
  echo "${PKG_NAME} stopped"
else
  echo "${PKG_NAME} is not running"
fi
exit 0

