# Kong Plugin: oauthTokenIntrospection

This repository contains a Kong plugin template that verifies authentication methods using the `Token Introspection` specification or `user id`.

## Plugin Parameters

The following fields are available for plugin configuration, along with descriptions:

| Key                     | Description                                                    | Data Type | Default Value                  | Required |
| ----------------------- | -------------------------------------------------------------- | --------- | ------------------------------ | -------- |
| introspection_host      | The host for the introspection endpoint                        | URL       | "https://introspection-host.com" | true     |
| entitlement_host        | The host for the entitlement endpoint                          | URL       | "https://entitlement-host.com"  | false    |
| token_location_xpath    | The XPath for the token location in the SOAP body envelope     | string    | "//soapenv:Header/ns:B2BContext/ns:AuthenticationToken" | false |
| token_location_header   | The header for the token                                       | string    | "Authorization"                | false    |
| userid_location_xpath  | The XPath for the user ID location in the SOAP body envelope  | string    | "//soapenv:Header/ns:B2BContext/ns:UserId"             | false |
| iprange_whitelist       | The IP or CICD allowlist for the user ID flow                | array     | ["0.0.0.0/0"]                  | false    |
| entitlement_required    | The required entitlement to authorize access to the service   | string    | "entitlement_check"            | true     |
| shared_secret           | The shared secret between the API gateway and integration layer | string  | "secret"                       | true     |
| verbose                 | Enable debugging and receive more information in response messages | boolean | false                        | false    |
| cache_introspection     | The cache time-to-live (TTL) for introspection responses     | integer   | 300                            | true     |
| cache_entitlement       | The cache TTL for entitlement responses                       | integer   | 300                            | true     |
| auth_methods            | The allowed authentication methods for the service, respecting order for multiple values | array | ["soap_headers_flow", "rest_headers_flow", "user_id_flow"] | true |

To allow all IPs in `iprange_whitelist`, use the value `0.0.0.0/0`.

**Important:** `applicationIdentifier` and `scopes` are optional and must be hardcoded in the plugin code.

## Example and Sample Data

### Introspection Sample

```json
{
 "active": true,
 "client_id": "CCCCCC"
}
```

### Entitlements Sample (Client ID Flow)

```json
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

### Entitlements Sample (User ID Flow)

```json
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

Replace the sample data with your actual data and configure the plugin accordingly.


This revised README.md includes corrected formatting and adds clarity to the descriptions of the plugin parameters and the sample data examples. Make sure to replace the sample data with your actual configuration.

Happy Kong-ing!
