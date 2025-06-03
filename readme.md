### gofiber CORS issue since v2.52.2

Run the provided CORS configuration and deploy it to AWS in front of CloudFront 


with v2.52.2 you will see

```bash
❯ curl -i -X OPTIONS https://d245hvitoez60u.cloudfront.net
HTTP/2 204
date: Tue, 03 Jun 2025 20:00:12 GMT
apigw-requestid: LmocCiBdIAMEMjg=
vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers
access-control-allow-headers: Origin,Accept,Content-Type,Content-Length,Accept-Encoding,X-CSRF-Token,Authorization,User-Agent
access-control-allow-methods: GET,POST,PUT,DELETE,OPTIONS,PATCH,HEAD
access-control-allow-origin:
x-cache: Miss from cloudfront
via: 1.1 25161ee8e0bc1cc9e1cea0d22207b908.cloudfront.net (CloudFront)
x-amz-cf-pop: DFW56-P5
x-amz-cf-id: uDQG9Bq4tL73_PtilG28oiqMdevrBbh2O5RF1Kt_VHzOAvYgJ4LBgQ==
```

upgrade to any version after v2.52.2 and you will see:

```bash

❯ curl -i -X OPTIONS https://d245hvitoez60u.cloudfront.net
HTTP/2 405
content-type: text/plain; charset=utf-8
content-length: 18
date: Tue, 03 Jun 2025 19:54:28 GMT
apigw-requestid: LmnmPgPGIAMEM1g=
allow: GET, HEAD
vary: Origin
x-cache: Error from cloudfront
via: 1.1 49ebf453d90a4d7fa51513af32906a5c.cloudfront.net (CloudFront)
x-amz-cf-pop: DFW56-P5
x-amz-cf-id: LSJB25upZ4lBK8QhzS1RuGHSuqD2M0QlSbbAsIwgVhNnMYxOWCy2xg==

Method Not Allowed
```
