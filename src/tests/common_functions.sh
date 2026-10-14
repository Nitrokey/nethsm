set -o pipefail
N1_IP=172.22.1.2
N2_IP=172.22.1.3
N3_IP=172.22.1.4
N4_IP=172.22.1.5
N5_IP=172.22.1.6
N6_IP=172.22.1.7
N7_IP=172.22.1.8
N8_IP=172.22.1.9

# Allow overriding from environment.
NETHSM_URL="${NETHSM_URL:-https://192.168.1.1/api}"
CURL_BASE="${CURL_BASE:-curl --fail-with-body -sS}"
CURL_BASE="${CURL_BASE} \
--resolve nethsm1:443:$N1_IP \
--resolve nethsm2:443:$N2_IP \
--resolve nethsm3:443:$N3_IP \
--resolve nethsm4:443:$N4_IP \
--resolve nethsm5:443:$N5_IP \
--resolve nethsm6:443:$N6_IP \
--resolve nethsm7:443:$N7_IP \
--resolve nethsm8:443:$N8_IP"
CURL="${CURL_BASE} -k"

GET()
{
    local url
    url="${NETHSM_URL}$1"
    shift
    echo "GET ${url}" 1>&2
    tmp=$(mktemp)
    (${CURL} ${url} "$@" | tee "${tmp}") || { cat "${tmp}" >&2; rm -f "${tmp}"; exit 1; }
    rm -f "${tmp}";
    echo
}

PUT()
{
    local url
    url="${NETHSM_URL}$1"
    shift
    echo "PUT ${url}" 1>&2
    ${CURL} -X PUT -H "Content-Type: application/json" --data @- ${url} "$@" || exit 1
    echo
}

POST()
{
    local url
    url="${NETHSM_URL}$1"
    shift
    echo "POST ${url}" 1>&2
    tmp=$(mktemp)
    (${CURL} -X POST -H "Content-Type: application/json" --data @- ${url} "$@" | tee "${tmp}") || { cat "${tmp}" >&2; rm -f "${tmp}"; exit 1; }
    rm -f "${tmp}";
    echo
}

DELETE()
{
    local url
    url="${NETHSM_URL}$1"
    shift
    echo "DELETE ${url}" 1>&2
    ${CURL} -X DELETE ${url} "$@" || exit 1
    echo
}

GET_admin()
{
    GET "$@" --user admin:Administrator
}

PUT_admin()
{
    PUT "$@" --user admin:Administrator
}

POST_admin()
{
    POST "$@" --user admin:Administrator
}

DELETE_admin()
{
    DELETE "$@" --user admin:Administrator
}

GET_operator()
{
    GET "$@" --user operator:OperatorOperator
}

PUT_operator()
{
    PUT "$@" --user operator:OperatorOperator
}

POST_operator()
{
    POST "$@" --user operator:OperatorOperator
}

GET_nadmin()
{
    GET "$@" --user 'namespace1~nadmin:NAdministrator'
}

PUT_nadmin()
{
    PUT "$@" --user 'namespace1~nadmin:NAdministrator'
}

POST_nadmin()
{
    POST "$@" --user 'namespace1~nadmin:NAdministrator'
}
