# Allow overriding from environment.
NITROHSM_URL="${NITROHSM_URL:-https://192.168.1.1/api}"
CURL="${CURL:-curl -f -sS -k}"

GET()
{
    local url
    url="${NITROHSM_URL}$1"
    shift
    echo "GET ${url}" 1>&2
    ${CURL} ${url} "$@" || exit 1
    echo
}

PUT()
{
    local url
    url="${NITROHSM_URL}$1"
    shift
    echo "PUT ${url}" 1>&2
    ${CURL} -X PUT -H "Content-Type: application/json" --data @- ${url} "$@" || exit 1
    echo
}

POST()
{
    local url
    url="${NITROHSM_URL}$1"
    shift
    echo "POST ${url}" 1>&2
    ${CURL} -X POST -H "Content-Type: application/json" --data @- ${url} "$@" || exit 1
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
