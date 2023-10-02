-- local ffi             = require("ffi")
-- local libxml2         = require("xmlua.libxml2")
local resty_sha256    = require "resty.sha256"
local resty_str       = require "resty.string"
local http            = require "resty.http"
local xmlua           = require("xmlua")
local lrucache        = require "resty.lrucache"
local ipmatcher       = require "resty.ipmatcher"
local cjson           = require("cjson.safe")

local cache = lrucache.new(512)

-- local loaded, xml2 = pcall(ffi.load, "xml2")

local _M = {}


-- Function to hash a given key using SHA256 and return it as a hexadecimal string.
local function hash_key(key)
  local sha256 = resty_sha256:new()
  sha256:update(key)
  return resty_str.to_hex(sha256:final())
end

local function make_request(endpoint, params)

  local params_request = {}
  params_request.method = params.method
  params_request.body = params.body
  params_request.headers = params.headers
  local timeout = params.timeout or 600

  local httpc = http.new()
  httpc:set_timeout(timeout)

  -- local proxyOpts = {
  --   http_proxy = params.proxy_url,
  --   https_proxy = params.proxy_url
  -- }
  -- httpc:set_proxy_options(proxyOpts)

  local res, err = httpc:request_uri(endpoint, params_request)

  -- return if error
  if err then
    return nil, err
  end

  -- always read response body, even if we discard it without using it on success
  local response_body = res.body
  local success = res.status < 400

  if not success then
    return nil, "statusCode: " .. tostring(res.status) .. " , Body (first 500 characters): " .. string.sub(response_body, 1, 500)
  end

  return response_body
end

local function call_introspection(host, token)

  local endpoint = host .. "/oauth/api/v2/token/introspect"

  local response_body, err = make_request(endpoint, {
    method = "POST",
    body = "token="..token,
    headers = { 
      ["Content-Type"] = "application/x-www-form-urlencoded",
      ["Accept"] = "application/json"
    },
    timeout = 20000
  })

  if err then
    return nil, "The introspection request return an error: " .. err
  end

  response_body, err = cjson.decode(response_body)

  if err then
    return nil, "The introspection response is not a valid JSON"
  end

  if not response_body.active then
    return nil, "The introspection show that token is not active"
  end

  if not response_body.client_id then
    return nil, "No client_id in the introspection response"
  end

  return response_body.client_id
end

local function call_entitlements(host, userid, user_id_type)
  local endpoint
  local scopes = ""
  local applicationIdentifier = ""

  if user_id_type == "userid" then
    endpoint = host .. "/oauth/v1/userinfo?userId=" .. userid .. "&scopes=" ..  scopes .. "&applicationIdentifier=" .. applicationIdentifier
  end

  if user_id_type == "clientid" then
    endpoint = host .. "/clients/v1/clientinfo/" .. userid .. "?applicationIdentifier=" .. applicationIdentifier
  end
  
  local response_body, err = make_request(endpoint, {
    method = "GET",
    headers = { 
      ["Accept"] = "application/json"
    },
    timeout = 20000
  })

  if err then
    return nil, "The entitlement request return an error: " .. err
  end

  response_body, err = cjson.decode(response_body)

  if err then
    return nil, "The entitlement response is not a valid JSON"
  end

  if user_id_type == "userid" then
    if not response_body.entitlements then
      return nil, "No userid Entitlements in the entitlement response"
    end

    return response_body.entitlements
  end

  if user_id_type == "clientid" then
    if not response_body.Entitlements then
      return nil, "No clientid Entitlements in the entitlement response"
    end

    return response_body.Entitlements
  end

  return nil, "No Entitlements in the entitlement response"
end


function _M.check_entitlements(user_entitlements, plugin_entitlement)

  if user_entitlements == nil then
    return false, "No Entitlements in the entitlement response"
  end

  -- Iterate through the array and check if the string is present
  for i, v in ipairs(user_entitlements) do
    if v == plugin_entitlement then
      return true
    end
  end

  return false, "The User Entitlements are not authorized to access this service"
end

function _M.get_entitlements(host, cache_ttl, user_credentials, user_id_type)

  if user_credentials == nil then
   return nil, "No user_credentials were found for all the flows"
  end

  -- Calculate a cache key based on the URL using the hash_key function.
  local token_cache_key = hash_key(user_credentials)
  
  -- Try to retrieve the response_body from cache, with a TTL of 300 seconds, using the retrieveEntities function.
  local user_entitlements, err = kong.cache:get(token_cache_key, { ttl = cache_ttl }, call_entitlements, host, user_credentials, user_id_type)

  if err then
    return nil, "Error while retrieving entitlements: " .. err
  end

  return user_entitlements
end

function _M.introspect_token(host, cache_ttl, token)

  -- Calculate a cache key based on the URL using the hash_key function.
  local token_cache_key = hash_key(token)

  -- Try to retrieve the response_body from cache, with a TTL of 300 seconds, using the retrieveEntities function.
  local client_id, err = kong.cache:get(token_cache_key, { ttl = cache_ttl }, call_introspection, host, token)

  if err then
    return nil, "Error during introspection - " .. err
  end

  return client_id
end


function _M.checkIpWhitelist(IpRange)
  local binary_remote_addr = ngx.var.binary_remote_addr
  
  if IpRange == nil then
    return false, "IpRange is nil"
  end

  local matcher, err

  matcher = cache:get(IpRange)
  if not matcher then
    matcher, err = ipmatcher.new(IpRange)
    if err then
      return false, "Failed to create a new ipmatcher instance: " .. err
    end

    cache:set(IpRange, matcher, 3600)
  end

  local is_match
  is_match, err = matcher:match_bin(binary_remote_addr)
  if err then
    return false, "Invalid binary ip address: " .. err
  end

  if not is_match then
    return false, "IP address is not allowed"
  end

  return true
end

function _M.get_userid(XPath)
  
-- Get SOAP envelope from the request
  local soapEnvelope = kong.request.get_raw_body()

  if soapEnvelope == nil then
    return nil, "The body of the request is nil"
  end
  
  -- Load the SOAP request XML into an XML document
  local success, document = pcall(xmlua.XML.parse, soapEnvelope)

  if success then
    -- Use XPath to select the desired element
    local selectedElement = document:search(XPath)

    -- Check if the element was found
    if #selectedElement > 0 then
      -- Extract the text content of the selected element
      local userid = selectedElement[1]:text()

      if userid == nil or #userid == 0 then
        return nil, "No userid was found in the userid element"
      end

      return userid
    else
      return nil, "No Element was found for the userid XPath"
    end
  else
    return nil, "Error when parsing the request for retrieving the userid"
  end

end


function _M.get_credentials_soap(XPath, host, cache_ttl)
  
  -- Get SOAP envelope from the request
    local soapEnvelope = kong.request.get_raw_body()
  
    if soapEnvelope == nil then
      return nil, nil, "The body of the request is nil"
    end

    -- Load the SOAP request XML into an XML document
    local success, document = pcall(xmlua.XML.parse, soapEnvelope)
  
    if success then

      -- Use XPath to select the desired element
      local selectedElement = document:search(XPath)

      -- Check if the element was found
      if #selectedElement > 0 then
        -- Extract the text content of the selected element
        local token = selectedElement[1]:text()

        if token == nil or #token == 0 then
          return nil, nil, "No token was found in the token element"
        end

        local user_credentials, errorMessage = _M.introspect_token(host, cache_ttl, token)

        if errorMessage then
          return nil, "Error while retrieving entities from cache for introspection: " .. errorMessage
        end

        selectedElement[1]:set_content(user_credentials)
        
        local options = {}
        options.include_declaration = false
        -- Serialize the updated XML document back to a string
        local updatedSoapRequest = document:to_xml(options)

        kong.service.request.set_raw_body(updatedSoapRequest)

        return user_credentials
      else
        return nil, nil, "No Element was found for the token XPath"
      end
    else
      return nil, nil, "Error when parsing the request for retrieving the token"
    end
    
  end

return _M
