./keyfender
curl -X PUT -H "Content-Type:application/json" --data-binary "@provision.json" --insecure https://localhost:4433/provision -vv
curl -X POST --insecure https://localhost:4433/system/reboot -u "admin:test1" -vv
curl -X PUT -H "Content-Type:application/json" --data-binary "@provision.json" --insecure https://localhost:4433/provision -vv
