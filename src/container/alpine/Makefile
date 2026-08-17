.PHONY: rebuild down up logs clean flogs etcd-panic etcd-break

clean:
	for i in 1 2 3 4 5 6 7 8 -witness; do docker volume rm -f nethsm-cluster_data$${i}; done

down:
	docker compose -f ./compose-cluster.yaml down 

kill:
	docker compose -f ./compose-cluster.yaml kill
	docker compose -f ./compose-cluster.yaml down

rebuild: kill clean
	docker compose -f ./compose-cluster.yaml up --build --no-start nethsm1

up: kill clean
	docker compose -f ./compose-cluster.yaml up -d

logs:
	docker compose -f ./compose-cluster.yaml logs

flogs:
	docker compose -f ./compose-cluster.yaml logs -f

etcd-break:
	docker exec -it nethsm-cluster-nethsm1-1 sh -c 'echo BROKEN >/data/etcd/member/snap/db'

etcd-panic: etcd-break down
	docker compose -f ./compose-cluster.yaml up -d
