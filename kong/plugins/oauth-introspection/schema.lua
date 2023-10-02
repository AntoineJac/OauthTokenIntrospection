local typedefs = require "kong.db.schema.typedefs"

local PLUGIN_NAME = "oauth-introspection"
local cjson           = require "cjson"


local function validate_parameters2(myArray)
  -- explicit ngx.null comparisons needed below because of https://konghq.atlassian.net/browse/FT-3631
  if not myArray or next(myArray) == nil then
    -- The array is nil or empty, return false
    return false, "at least one flow should be enable2!"
  end

  return true
end


local function validate_parameters(config)
  -- explicit ngx.null comparisons needed below because of https://konghq.atlassian.net/browse/FT-3631
  if config.soap_headers_flow == false and config.rest_headers_slow == false and config.user_id_flow == false then
    return false, "at least one flow should be enable!"
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
            introspection_endpoint = typedefs.url {
              required = true,
              default = "http://127.0.0.1:8080/introspection"
            }
          },{
            clientinfo_endpoint = typedefs.url {
              required = true,
              default = "http://127.0.0.1:8080/clientinfo"
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
              required = false,
              default = { "0.0.0.0/0" }
            } 
          },{
            entitlement_required = {
              type = "string",
              required = true,
              default = "entitlement_check"
            }
          },{
            soap_headers_flow = {
              type = "boolean",
              default = true,
            }
          },{
            rest_headers_slow = {
              type = "boolean",
              default = true,
            }
          },{
            user_id_flow = {
              type = "boolean",
              default = true,
            }
          },{
            auth_methods = {
              required = true,
              custom_validator = validate_parameters2,
              type     = "array",
              default  = {
                "password",
                "client_credentials",
                "authorization_code"
              },
              elements = {
                type   = "string",
                one_of = {
                  "password",
                  "client_credentials",
                  "authorization_code"
                },
              },
            },
          },
        },
        entity_checks = {
          -- add some validation rules across fields
          -- the following is silly because it is always true, since they are both required
          { conditional = {
            if_field = "soap_headers_flow", if_match = { eq = true },
            then_field = "token_location_xpath", then_match = { required = true },
          } },
          { conditional = {
            if_field = "user_id_flow", if_match = { eq = true },
            then_field = "userid_location_xpath", then_match = { required = true },
          } },
          { conditional = {
            if_field = "rest_headers_slow", if_match = { eq = true },
            then_field = "token_location_header", then_match = { required = true },
          } },
        },
      },
    },
  },
}

return schema
