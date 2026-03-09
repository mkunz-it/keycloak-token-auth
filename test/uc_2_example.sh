#!/usr/bin/env bash
set -euo pipefail

readonly authUrl="http://localhost:8080"
readonly realm="demo"

#client which simulates the mobile application
readonly srcClientId=mobile-app-conf
readonly srcClientSecret=FX32ScdAtnd3LoUewf6ujaMAoFuyNWMt
readonly username=john.doe@example.com
readonly password=changeIt

#other client to redirect after session is created in keyclaok
#this uri must be set as valid redirect uri on the mobile-app client
readonly targetClientId=account-console
readonly redirectUri=$authUrl/realms/$realm/account/

#simulates mobile app login
resp="$(curl -X POST $authUrl/realms/$realm/protocol/openid-connect/token \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "client_id=$srcClientId" \
    --data-urlencode "client_secret=$srcClientSecret" \
    --data-urlencode "grant_type=password" \
    --data-urlencode "username=$username" \
    --data-urlencode "password=$password" \
    --data-urlencode "scope=openid email")"

id_token="$(jq -r '.id_token' <<<"$resp")"
access_token="$(jq -r '.access_token' <<<"$resp")"

# optional sanity check
[[ "$id_token" != "null" && -n "$id_token" ]] || { echo "No id_token in response: $resp" >&2; exit 1; }
[[ "$access_token" != "null" && -n "$access_token" ]] || { echo "No access_token in response: $resp" >&2; exit 1; }

echo
echo "id_token (from password grant):"
echo "$id_token"
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

# --- Standard Token Exchange V2 ---
# Exchange an access token issued to $srcClientId for an ID token that has $targetClientId as audience.
# Docs: https://www.keycloak.org/securing-apps/token-exchange#_standard-token-exchange
resp_tx="$(curl -X POST "$authUrl/realms/$realm/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "client_id=$srcClientId" \
    --data-urlencode "client_secret=$srcClientSecret" \
    --data-urlencode "scope=account" \
    --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
    --data-urlencode "subject_token=$access_token" \
    --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
    --data-urlencode "requested_token_type=urn:ietf:params:oauth:token-type:id_token" \
    --data-urlencode "audience=$targetClientId" )"

# When requesting an ID token, Keycloak returns it in the `access_token` field.
exchanged_id_token="$(jq -r '.access_token' <<<"$resp_tx")"

[[ "$exchanged_id_token" != "null" && -n "$exchanged_id_token" ]] || { echo "Token exchange failed: $resp_tx" >&2; exit 1; }

echo
echo "exchanged_id_token (token exchange v2):"
echo "$exchanged_id_token"
echo

# Use the exchanged ID token for the PAR request below.
id_token="$exchanged_id_token"

#use Pushed Authorization Request (PAR) to send ID token securely to Keycloak before start login
#PKCE enabled and forced on the target client is a must have, if it is public one
#code_challenge is not used by the mobile-app because it will never see the code, but it prevents "authorization code interception"
resp2="$(curl -X POST $authUrl/realms/$realm/protocol/openid-connect/ext/par/request \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "client_id=$targetClientId" \
    --data-urlencode "response_type=code" \
    --data-urlencode "scope=openid profile email" \
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
echo "$authUrl/realms/$realm/protocol/openid-connect/auth?client_id=$targetClientId&request_uri=$request_uri"