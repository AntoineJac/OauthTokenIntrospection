
local plugin = {
  PRIORITY = 1000, -- set the plugin priority, which determines plugin execution order
  VERSION = "0.1", -- version in X.Y.Z format. Check hybrid-mode compatibility requirements.
}

local utils = require "kong.plugins.oauth-introspection.utils"
local cjson           = require "cjson"

-- runs in the 'access_by_lua_block'
function plugin:access(plugin_conf)

  local errorMessage
  local user_credentials
  local user_entitlements
  local jwtToken
  local valid_request
  local replaceTokenType

  kong.log.debug("Antoine auth_methods are: ", cjson.encode(plugin_conf.auth_methods))

  kong.log.debug("Antoine auth_methods are: ", plugin_conf.auth_methods[1])

  if plugin_conf.soap_headers_flow then

    user_credentials, errorMessage = utils.get_credentials_soap(plugin_conf.token_location_xpath, plugin_conf.introspection_endpoint)

  end

  if plugin_conf.rest_headers_slow and errorMessage == nil then
    -- get jwt token from header 
    jwtToken = kong.request.get_headers()[plugin_conf.token_location_header]

    if jwtToken == nil then
      kong.log.debug("method: rest_headers, token not found")
    end

    if jwtToken ~= nil then
      user_credentials, errorMessage = utils.introspect_token(plugin_conf.introspection_endpoint, jwtToken)
      kong.service.request.set_header("Authorization", user_credentials)
    end

  end

  if plugin_conf.user_id_flow and errorMessage == nil then
    local ipCheck, errorMessage = utils.checkIpWhitelist(plugin_conf.iprange_whitelist)
    if ipCheck then
      user_credentials, errorMessage = utils.get_userid(plugin_conf.userid_location_xpath)
    end
  end

  if user_credentials ~= nil then
    user_entitlements, errorMessage = utils.get_entitlements(plugin_conf.clientinfo_endpoint,user_credentials)
  elseif errorMessage == nil then
    errorMessage = "user_credentials is empty"
  end

  if user_entitlements ~= nil then
    valid_request, errorMessage= utils.check_entitlements(user_entitlements, plugin_conf.entitlement_required)
  elseif errorMessage == nil then 
    errorMessage = "user_entitlements is empty"
  end

  if errorMessage then
    return kong.response.exit(401, errorMessage, {
      ["Content-Type"] = "text/xml; charset=utf-8"
    })
  end

  kong.service.request.set_header("APIGW-Identity", "SSSSSS")


end --]]



-- return our plugin object
return plugin
