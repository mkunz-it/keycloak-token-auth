#!/usr/bin/env bash
set -euo pipefail

readonly authUrl="http://localhost:8080"
readonly realm="demo"

#client which simulates the mobile application
readonly srcClientId=mobile-app
readonly username=john.doe@example.com
readonly password=changeIt

#proxy client
readonly proxyClientId=proxy-client
readonly proxyClientSecret=jmFKJOr8VhExFravCPR0uO1HrG2TJoiP

#other client to redirect after session is created in keyclaok
#this uri must be set as valid redirect uri on the proxy-client client
readonly redirectUri=http://localhost:8081/example/

#simulates mobile app login
#scope=audience adds the "account-console" as audience to the ID-Token
resp="$(curl -X POST $authUrl/realms/$realm/protocol/openid-connect/token \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "client_id=$srcClientId" \
    --data-urlencode "grant_type=password" \
    --data-urlencode "username=$username" \
    --data-urlencode "password=$password" \
    --data-urlencode "scope=openid email account")"

id_token="$(jq -r '.id_token' <<<"$resp")"

# optional sanity check
[[ "$id_token" != "null" && -n "$id_token" ]] || { echo "No id_token in response: $resp" >&2; exit 1; }

echo
echo "id_token:"
echo $id_token
echo

# creates a example code challenge
code_verifier="$(
  openssl rand 32 | openssl base64 -A \
  | tr '+/' '-_' | tr -d '=' \
  | tr -d '\n'
)"

code_challenge="$(
  printf '%s' "$code_verifier" \
  | openssl dgst -sha256 -binary \
  | openssl base64 -A \
  | tr '+/' '-_' | tr -d '='
)"

#use Pushed Authorization Request (PAR) to send ID token securely to Keycloak before start login
#PKCE enabled and forced on the target client is a must have, if it is public one
#code_challenge is not used by the mobile-app because it will never see the code, but it prevents "authorization code interception"
resp2="$(curl -X POST $authUrl/realms/$realm/protocol/openid-connect/ext/par/request \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "client_id=$proxyClientId" \
    --data-urlencode "client_secret=$proxyClientSecret" \
    --data-urlencode "response_type=code" \
    --data-urlencode "scope=openid" \
    --data-urlencode "redirect_uri=$redirectUri" \
    --data-urlencode "code_challenge_method=S256" \
    --data-urlencode "code_challenge=$code_challenge" \
    --data-urlencode "id_token=$id_token")"

request_uri="$(jq -r '.request_uri' <<<"$resp2")"

# optional sanity check
[[ "$request_uri" != "null" && -n "$request_uri" ]] || { echo "No id_token in response: $resp2" >&2; exit 1; }

echo
echo "request_uri:"
echo $request_uri
echo
echo "please put the following URL into your browser"
echo "$authUrl/realms/$realm/protocol/openid-connect/auth?client_id=$proxyClientId&request_uri=$request_uri"