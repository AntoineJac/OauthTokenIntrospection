local typedefs = require "kong.db.schema.typedefs"

local PLUGIN_NAME = "oauth-introspection"


local function validate_auth_methods(auth_methods)
  -- explicit ngx.null comparisons needed below because of https://konghq.atlassian.net/browse/FT-3631
  if not auth_methods or next(auth_methods) == nil then
    -- The array is nil or empty, return false
    return false, "at least one of the soap_headers_flow, rest_headers_flow or user_id_flow options should be enable as auth_methods!"
  end

  return true
end

-- Function to check if a value is in an array
local function containsValue(arr, value)
  if arr == nil then
    return false
  end

  for _, v in ipairs(arr) do
      if v == value then
          return true -- Value found in the array
      end
  end

  return false -- Value not found in the array
end


local function validate_parameters(config)

  if containsValue(config.auth_methods, "soap_headers_flow") and config.token_location_xpath == ngx.null then
    return false, "token_location_xpath is mandatory when soap_headers_flow is enable!"
  end

  if containsValue(config.auth_methods, "rest_headers_flow") and config.token_location_header == ngx.null then
    return false, "token_location_header is mandatory when rest_headers_flow is enable!"
  end

  if containsValue(config.auth_methods, "user_id_flow") and config.userid_location_xpath == ngx.null then
    return false, "userid_location_xpath is mandatory when user_id_flow is enable!"
  end

  if ( containsValue(config.auth_methods, "soap_headers_flow") or containsValue(config.auth_methods, "rest_headers_flow") ) and config.introspection_host == ngx.null then
    return false, "introspection_host is mandatory when soap_headers_flow or rest_headers_flow is enable!"
  end

  return true
end

local schema = {
  name = PLUGIN_NAME,
  fields = {
    -- the 'fields' array is the top-level entry with fields defined by Kong
    { consumer = typedefs.no_consumer },
    { route = typedefs.no_route },
    { protocols = typedefs.protocols_http },
    { config = {
        -- The 'config' record is the custom part of the plugin schema
        type = "record",
        custom_validator = validate_parameters,
        fields = {
          {
            introspection_host = typedefs.url {
              required = false,
              default = "https://introspection-host.com"
            }
          },{
            entitlement_host = typedefs.url {
              required = true,
              default = "https://entitlement-host.com"
            }
          },{
            token_location_xpath = {
              type = "string",
              default = "//soapenv:Header/ns:B2BContext/ns:AuthenticationToken"
            }
          },{
            token_location_header = {
              type = "string",
              default = "Authorization"
            }
          },{
            userid_location_xpath = {
              type = "string",
              default = "//soapenv:Header/ns:B2BContext/ns:UserId"
            }
          },{
            iprange_whitelist = {
              type = "array",
              elements = typedefs.ip_or_cidr,
              required = false
            } 
          },{
            entitlement_required = {
              type = "string",
              required = true,
              default = "entitlement_check"
            }
          },{
            shared_secret = {
              type = "string",
              required = true,
              encrypted = true,
              referenceable = true,
            }
          },{
            scope = {
              type = "string",
              required = false,
              default = "entitlements"
            }
          },{
            application_identifier = {
              type = "string",
              required = false
            }
          },{
            verbose = {
              type = "boolean",
              default = false
            }
          },{
            cache_introspection = {
              type = "integer",
              required = true,
              default = 300,
              gt = 1
            }
          },{
            cache_entitlement = {
              type = "integer",
              required = true,
              default = 300,
              gt = 1
            }
          },{
            auth_methods = {
              required = true,
              custom_validator = validate_auth_methods,
              type     = "array",
              default  = {
                "soap_headers_flow",
                "rest_headers_flow",
                "user_id_flow"
              },
              elements = {
                type   = "string",
                one_of = {
                  "soap_headers_flow",
                  "rest_headers_flow",
                  "user_id_flow"
                },
              },
            },
          },
        },
      },
    },
  },
}

return schema
