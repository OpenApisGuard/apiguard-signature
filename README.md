# apiguard-signature
Open APIs Guard HTTP Signature Plugin

### API Doc
```markdown

/* Create API */
curl -X POST \
  http://localhost:8080/apiguard/apis \
  -H 'content-type: application/json' \
  -d '{
  "id": "f8157910-d857-11e6-8bc0-2d9f23b1a052",
  "creationDate": 1484178301729,
  "request_uri": "/google/(.*)/abc",
  "name": "google",
  "downstream_uri": "http://www.google.com"
  }'
  
/* Update API (downstream_uri) */
curl -X PATCH \
  http://localhost:8080/apiguard/apis \
  -H 'content-type: application/json' \
  -d '{
  "id": "f8157910-d857-11e6-8bc0-2d9f23b1a052",
  "creationDate": 1484178301729,
  "request_uri": "/google/(.*)/abc",
  "name": "google",
  "downstream_uri": "http://www.msn.com"
}'

/* Create client */
curl -X POST \
  http://localhost:8080/apiguard/clients \
  -H 'content-type: application/json' \
  -d '{"id":"Jason"}'

/* Add http signature auth */
curl -X POST \
  http://localhost:8080/apiguard/clients/Jason/signature-auth \
  -H 'content-type: application/json' \
  -d '{
	"client_alias":"abc-nprod-20170321",
	"secret" : "70335ca6-081f-11e7-93ae-92361f003251",
	"request_uri" : "/google/(.*)/abc"
    }'

/* Invoke with http signature */
./sign.sh --key Jason:abc-nprod-20170321 --secret 70335ca6-081f-11e7-93ae-92361f003251 -X GET http://localhost:8080/apiguard/apis/google/123/abc

```

