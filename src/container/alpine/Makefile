.PHONY: rebuild down up logs clean

clean:
	sudo rm -rf data

down:
	docker compose -f ./compose-multi.yaml down 

rebuild: down clean
	docker compose -f ./compose-multi.yaml up --build --no-start nethsm1

up: down clean
	docker compose -f ./compose-multi.yaml up -d

logs:
	docker compose -f ./compose-multi.yaml logs
