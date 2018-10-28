# SpringSecurityOAuth2Example

## get token
```
// Authorization : Basic base64(testestsetsetset:secret)
// authorization url : /oauth/token

$ curl -XPOST 'http://localhost:8080/oauth/token' -i -H 'Authorization: Basic dGVzdGVzdHNldHNldHNldDpzZWNyZXQ=' -d 'grant_type=password&username=marissa&password=koala'
{"access_token":"07d3aa0c-6cbf-4e11-80b6-0d86c14be337","token_type":"bearer","refresh_token":"51aaca83-81e4-4f83-b8fd-49e4c95ff76a","expires_in":3598,"scope":"read write"}
```

## access secure endpoint
```
$ curl 'http://localhost:8080/secure' -i -H 'Authorization: bearer 07d3aa0c-6cbf-4e11-80b6-0d86c14be337'
```
