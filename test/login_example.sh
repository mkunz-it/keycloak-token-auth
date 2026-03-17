#!/usr/bin/env bash
set -euo pipefail

#Keycloak properties
readonly authUrl="http://localhost:8080"
readonly realm="demo"

#Source client, which simulates the mobile application
readonly srcClientId=mobile-app
readonly username=john.doe@example.com
readonly password=changeIt

#Proxy client
readonly proxyClientId=proxy-client
readonly proxyClientSecret=jmFKJOr8VhExFravCPR0uO1HrG2TJoiP
#Redirect URI to which the proxy client must redirect after logging in via the ID token
readonly redirectUri=$authUrl/realms/$realm/account/

#simulates mobile app login
#scope=proxy adds the "proxy-client" as audience to the ID-Token
resp="$(curl -X POST $authUrl/realms/$realm/protocol/openid-connect/token \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "client_id=$srcClientId" \
    --data-urlencode "grant_type=password" \
    --data-urlencode "username=$username" \
    --data-urlencode "password=$password" \
    --data-urlencode "scope=openid email proxy")"

id_token="$(jq -r '.id_token' <<<"$resp")"
#access_token="$(jq -r '.access_token' <<<"$resp")"

# optional sanity check
[[ "$id_token" != "null" && -n "$id_token" ]] || { echo "No id_token in response: $resp" >&2; exit 1; }
#[[ "$access_token" != "null" && -n "$access_token" ]] || { echo "No access_token in response: $resp" >&2; exit 1; }

echo
echo "id_token:"
echo $id_token
echo

#echo
#echo "access_token:"
#echo $access_token
#echo

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
#PKCE should be enabled and PAR should be forced on the proxy client
#Hint: code_challenge is not used by the proxy-client because it will never see the code, but it prevents "authorization code interception"
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