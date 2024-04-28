#!/bin/sh
set -e

if [ -z "$KENGINE_POSTGRES_USER_DB_PASSWORD" ]; then
  export KENGINE_POSTGRES_USER_DB_PASSWORD="kengine"
fi

if [ -z "$KENGINE_POSTGRES_USER_DB_USER" ]; then
  export KENGINE_POSTGRES_USER_DB_USER="kengine"
fi

until pg_isready -h "${KENGINE_POSTGRES_USER_DB_HOST}" -p "${KENGINE_POSTGRES_USER_DB_PORT}" -U "${KENGINE_POSTGRES_USER_DB_USER}" -d "${KENGINE_POSTGRES_USER_DB_NAME}"; 
do
  echo >&2 "Postgres is unavailable - sleeping"
  sleep 5
done

# check migrations complete
# psql -U ${KENGINE_POSTGRES_USER_DB_USER} -d ${KENGINE_POSTGRES_USER_DB_NAME} -t -c "SELECT EXISTS(SELECT name FROM role WHERE name = 'admin')"
export PGPASSWORD=${KENGINE_POSTGRES_USER_DB_PASSWORD}
until psql -h "${KENGINE_POSTGRES_USER_DB_HOST}" -U ${KENGINE_POSTGRES_USER_DB_USER} -p "${KENGINE_POSTGRES_USER_DB_PORT}" "${KENGINE_POSTGRES_USER_DB_NAME}" -c '\q'; 
do
  echo >&2 "Database is unavailable - sleeping"
  sleep 5
done
echo >&2 "Database is available"

# wait for neo4j to start
until nc -z ${KENGINE_NEO4J_HOST} ${KENGINE_NEO4J_BOLT_PORT};
do 
  echo "neo4j is unavailable - sleeping"
  sleep 5; 
done

# wait for kafka connection
until kcat -L -b ${KENGINE_KAFKA_BROKERS};
do
  echo "kafka is unavailable - sleeping"
  sleep 5;
done

# wait for file server to start
if [ "$KENGINE_FILE_SERVER_HOST" != "s3.amazonaws.com" ]; then
  until nc -z "${KENGINE_FILE_SERVER_HOST}" "${KENGINE_FILE_SERVER_PORT}";
  do
    echo "file server is unavailable - sleeping"
    sleep 5;
  done
else
  echo "S3 mode skip file server health check"
fi

sed -i "s/https:\/\/petstore.swagger.io\/v2\/swagger.json/\/kengine\/openapi.json/g" /usr/local/share/swagger-ui/swagger-initializer.js

exec "$@"
