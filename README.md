# Kong plugin oauthTokenIntrospection
====================

This repository contains a Kong plugin template to verify
several authentication methods using `Token Introspection` specification or `user id`.


## Plugins parameters
=================================

The following fields are available for plugin configuration, with descriptions:

| Key     | Description | Data Type  | Default Value | Require |
| ------- | ----------- | ---------- | ------------- | ------- |
| introspection_host | The host for introspection endpoint | url | "https://introspection-host.com" | true |
| entitlement_host | The host for entitlement endpoint | url | "https://entitlement-host.com" | false |
| token_location_xpath | The XPath for the token location in the soap body envelope | string | "//soapenv:Header/ns:B2BContext/ns:AuthenticationToken" | false |
| token_location_header | The header for the token | string | "Authorization" | false |
| userid_location_xpath | The XPath for the token location in the soap body envelope | string | "//soapenv:Header/ns:B2BContext/ns:UserId" | false |
| iprange_whitelist | The IP or CICD allow for the user ID flow | array | "0.0.0.0/0" | false |
| entitlement_required | The require entitlement to authorize the request to access the service | string | "entitlement_check" | true |
| shared_secret | The shared secret between API gateway & intergration layer | string | "secret" | true |
| verbose | To help debugging and allow more information on the response message | boolean | false | false |
| cache_introspection | The cache ttl for the introspection response | integer | 300 | true |
| cache_entitlement | The cache ttl for the entitlement response | integer | 300 | true |
| auth_methods | The authentication methods allow for the service, order will be respected in case of multiple values | array | ["soap_headers_flow", "rest_headers_flow", "user_id_flow"] | true |

For the iprange_whitelist to allow all IPs use the value `0.0.0.0/0`

**Important:** applicationIdentifier and scopes are optional and must be hardcoded in the plugin code!


## Example and Sample data
-------

* *Introspection*: `sample`
```
{
 "active": true,
 "client_id": "CCCCCC"
}
```

* *Entitlements*: this is for the `client id` flow
```
{
 "ClientId": "CCCCCC",
 "Entitlements": [
  "F-BE-AP-L7-TARIF-GEN",
  "F-BE-AP-L7-TARIF-VEHICLE",
  "F-BE-AP-SGE-AddressCity",
  "F-BE-AP-SGE-AddressCityStreet"
 ]
}
```

* *Entitlements*: this is for the `user id` flow
```
{
 "applicationIdentifier": "ApiGateway",
 "userName": "UUUUUU",
 "entitlements": [
  "F-BE-AP-L7-TARIF-GEN",
  "F-BE-AP-L7-TARIF-VEHICLE",
  "F-BE-AP-SGE-AddressCity",
  "F-BE-AP-SGE-AddressCityStreet"
 ]
}
```

