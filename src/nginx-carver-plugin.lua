local function make_carver_session_request(username, password)
    local http = require "resty.http"
    local httpc = http.new()
    local port = os.getenv("CARVER_INTERNAL_PORT")

    local res, err = httpc:request_uri("https://127.0.0.1:" .. port .. "/sessions", {
        method = "POST",
        body = "username=" .. username .."&password=" .. password,
        headers = {
            ["Content-Type"] = "application/x-www-form-urlencoded",
        },
        ssl_verify = false
    })

    return res, err
end

local function make_carver_token_verification_request(to_check, session_token)
    local http = require "resty.http"
    local httpc = http.new()
    local port = os.getenv("CARVER_INTERNAL_PORT")

    local res, err = httpc:request_uri("http://127.0.0.1:" .. port .. "/tokens/" .. to_check, {
        method = "GET",
        query = "?api_token=" .. session_token,
    })

    return res, err
end

local function extract_uuid(request_body)
    local uuid_pattern = "%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x"
    return string.match(res.body, uuid_pattern)
end

local function get_carver_session_token()
    if (ngx.var.nginx_carver_session != nil and ngx.var.nginx_carver_session != '') then
        return ngx.var.nginx_carver_session
    end

    local username = os.getenv("NGINX_CARVER_UN")
    local password = os.getenv("NGINX_CARVER_PW")

    local res, err = make_carver_session_request(username, password)

    if not (res and res.status == ngx.HTTP_OK) then
        ngx.log(ngx.ERR, "Failed to get carver session token")
        if (err) then
            ngx.log(ngx.ERR, err)
        end
        if (res) then
            ngx.log(ngx.ERR, "Request Status: " .. res.status)
        end
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    ngx.var.nginx_carver_session = extract_uuid(res.body)

    ngx.log(ngx.NOTICE, "Retrieved new carver session token")

    return ngx.var.nginx_carver_session
end

local function on_forwarding_request(request_carver_token)
    if (request_carver_token == nil or request_carver_token == '') then
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    local nginx_carver_session = get_carver_session_token()

    local res, err = make_carver_token_verification_request(request_carver_token, nginx_carver_session)

    if not (res and res.status == ngx.HTTP_OK) then
        if (err) then
            ngx.log(ngx.ERR, err)
        end
        if (res) then
            ngx.log(ngx.ERR, "Incorrect token, status=" .. res.status)
        end
        ngx.exit(ngx.HTTP_NOT_FOUND)
    end
end

on_forwarding_request(ngx.var.arg_token)