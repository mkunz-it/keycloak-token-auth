# A brief overview of the shell script’s functions

## Step 1: Retrieve access token from source client

In this case, we simulate logging in to a mobile app and receive an ID token for the subsequent initiation
of the browser session for the target client.

To obtain the audience for the `proxy-client`, we also request the "**proxy**" scope.

```shell
curl -X POST $authUrl/realms/$realm/protocol/openid-connect/token \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "client_id=$srcClientId" \
    --data-urlencode "grant_type=password" \
    --data-urlencode "username=$username" \
    --data-urlencode "password=$password" \
    --data-urlencode "scope=openid email proxy"
```

## Step 2: Use Token to create browser session

### Step 2.1 Pushed Authorization Request

Send the ID token or access token securely to Keycloak via a backchannel call.
To do this, we use the `proxy-client`, for which we have previously configured the `redirect_uri` of our target client.
In our example, the `redirect_uri` corresponds to the Keycloak account console.

```shell
curl -X POST $authUrl/realms/$realm/protocol/openid-connect/ext/par/request \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "client_id=$proxyClientId" \
    --data-urlencode "client_secret=$proxyClientSecret" \
    --data-urlencode "response_type=code" \
    --data-urlencode "scope=openid" \
    --data-urlencode "redirect_uri=$redirectUri" \
    --data-urlencode "code_challenge_method=S256" \
    --data-urlencode "code_challenge=$code_challenge" \
    --data-urlencode "id_token=$id_token"
```
In response, we receive a `request_uri`, which we use in the next step to call the /auth endpoint.

**Hint:** If we need further information about PAR, you should have a look at the RFC (https://datatracker.ietf.org/doc/html/rfc9126)

### Step 2.2 Call Keycloak's authorization endpoint

Finally, the script generates a URL that can be opened in a browser.
This URL contains the previously requested `request_uri` and the client_id of the `proxy-client`.

```shell
$authUrl/realms/$realm/protocol/openid-connect/auth?client_id=$proxyClientId&request_uri=$request_uri
```