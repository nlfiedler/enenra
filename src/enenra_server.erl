%% -*- coding: utf-8 -*-
%%
%% Copyright 2016-2017 Nathan Fiedler. All rights reserved.
%% Use of this source code is governed by a BSD-style
%% license that can be found in the LICENSE file.
%%
-module(enenra_server).

-behavior(gen_server).
-export([start_link/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(BASE_URL, <<"https://www.googleapis.com/storage/v1/b/">>).
-define(UPLOAD_URL, <<"https://www.googleapis.com/upload/storage/v1/b/">>).
-define(AUTH_URL, <<"https://www.googleapis.com/oauth2/v4/token">>).
-define(AUD_URL, <<"https://www.googleapis.com/oauth2/v4/token">>).

-define(GOOGLE_INTERNAL_AUTH_URL, <<"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">>).

% read/write is useful for adding and deleting, but that's about it
-define(READ_WRITE_SCOPE, <<"https://www.googleapis.com/auth/devstorage.read_write">>).
% full-control is required for updating/patching existing resources
-define(FULL_CONTROL_SCOPE, <<"https://www.googleapis.com/auth/devstorage.full_control">>).

% Base64 encoding of JSON {"alg":"RS256","typ":"JWT"}
-define(JWT_HEADER, <<"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9">>).
-define(GRANT_TYPE, <<"urn:ietf:params:oauth:grant-type:jwt-bearer">>).

-include_lib("public_key/include/public_key.hrl").
-include("enenra.hrl").

-record(state, {token}).

%%
%% Client API
%%
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%%
%% gen_server callbacks
%%
init([]) ->
    {ok, #state{}}.

handle_call({list_buckets, Credentials}, _From, State) ->
    ListBuckets = fun(Token) ->
        list_buckets(Credentials, Token)
    end,
    request_with_retry(ListBuckets, Credentials, State);
handle_call({get_bucket, Name, Credentials}, _From, State) ->
    GetBucket = fun(Token) ->
        get_bucket(Name, Token)
    end,
    request_with_retry(GetBucket, Credentials, State);
handle_call({insert_bucket, Bucket, Credentials}, _From, State) ->
    InsertBucket = fun(Token) ->
        insert_bucket(Bucket, Credentials, Token)
    end,
    request_with_retry(InsertBucket, Credentials, State);
handle_call({update_bucket, Name, Properties, Credentials}, _From, State) ->
    UpdateBucket = fun(Token) ->
        update_bucket(Name, Properties, Token)
    end,
    request_with_retry(UpdateBucket, Credentials, State);
handle_call({delete_bucket, Name, Credentials}, _From, State) ->
    DeleteBucket = fun(Token) ->
        delete_bucket(Name, Token)
    end,
    request_with_retry(DeleteBucket, Credentials, State);
handle_call({list_objects, BucketName, Credentials}, _From, State) ->
    ListObjects = fun(Token) ->
        list_objects(BucketName, Token)
    end,
    request_with_retry(ListObjects, Credentials, State);
handle_call({upload_object, Object, RequestBody, Credentials}, _From, State) ->
    UploadObject = fun(Token) ->
        upload_object(Object, RequestBody, Token)
    end,
    request_with_retry(UploadObject, Credentials, State);
handle_call({download_object, BucketName, ObjectName, Filename, Credentials}, _From, State) ->
    DownloadObject = fun(Token) ->
        download_object(BucketName, ObjectName, Filename, Token)
    end,
    request_with_retry(DownloadObject, Credentials, State);
handle_call({get_object, BucketName, ObjectName, Credentials}, _From, State) ->
    GetObject = fun(Token) ->
        get_object(BucketName, ObjectName, Token)
    end,
    request_with_retry(GetObject, Credentials, State);
handle_call({get_object_contents, BucketName, ObjectName, Credentials}, _From, State) ->
    GetObjectContents = fun(Token) ->
        get_object_contents(BucketName, ObjectName, Token)
    end,
    request_with_retry(GetObjectContents, Credentials, State);
handle_call({delete_object, BucketName, ObjectName, Credentials}, _From, State) ->
    DeleteObject = fun(Token) ->
        delete_object(BucketName, ObjectName, Token)
    end,
    request_with_retry(DeleteObject, Credentials, State);
handle_call({update_object, BucketName, ObjectName, Properties, Credentials}, _From, State) ->
    UpdateObject = fun(Token) ->
        update_object(BucketName, ObjectName, Properties, Token)
    end,
    request_with_retry(UpdateObject, Credentials, State).

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%
%% Private functions
%%

% @doc
%
% Retrieve a list of the available buckets.
%
-spec list_buckets(credentials(), access_token()) -> {ok, [bucket()]} | {error, term()}.
list_buckets(Credentials, Token) ->
    Project = Credentials#credentials.project_id,
    Url = hackney_url:make_url(?BASE_URL, <<"">>, [{"project", Project}]),
    ReqHeaders = add_auth_header(Token, []),
    {ok, Status, Headers, Client} = hackney:request(get, Url, ReqHeaders),
    case decode_response(Status, Headers, Client) of
        {ok, Body} ->
            Items = proplists:get_value(<<"items">>, Body, []),
            {ok, [make_bucket(Item) || {Item} <- Items]};
        R -> R
    end.

% @doc
%
% Retrieve the named bucket.
%
-spec get_bucket(binary(), access_token()) -> {ok, bucket()} | {error, term()}.
get_bucket(Name, Token) ->
    Url = <<?BASE_URL/binary, Name/binary>>,
    ReqHeaders = add_auth_header(Token, []),
    {ok, Status, Headers, Client} = hackney:request(get, Url, ReqHeaders),
    case decode_response(Status, Headers, Client) of
        {ok, Body} -> {ok, make_bucket(Body)};
        R -> R
    end.

% @doc
%
% Insert a bucket with the given properties. Only name, location, and class
% are used (and are required). If the bucket already exists, the existing
% properties are retrieved and returned.
%
-spec insert_bucket(bucket(), credentials(), access_token()) -> {ok, bucket()} | {error, term()}.
insert_bucket(Bucket, Credentials, Token) ->
    Project = Credentials#credentials.project_id,
    Url = hackney_url:make_url(?BASE_URL, <<"">>, [{"project", Project}]),
    ReqHeaders = add_auth_header(Token, [
        {<<"Content-Type">>, <<"application/json">>}
    ]),
    ReqBody = binary_to_list(jiffy:encode({[
        {<<"name">>, Bucket#bucket.name},
        {<<"location">>, Bucket#bucket.location},
        {<<"storageClass">>, Bucket#bucket.storageClass}
    ]})),
    {ok, Status, Headers, Client} = hackney:request(post, Url, ReqHeaders, ReqBody),
    case decode_response(Status, Headers, Client) of
        {ok, Body} -> {ok, make_bucket(Body)};
        {error, conflict} -> get_bucket(Bucket#bucket.name, Token);
        R -> R
    end.

% @doc
%
% Update an existing bucket with the properties defined in the given
% property list (uses the PATCH method to update only those fields). The
% names and values should be binary instead of string type. To clear an
% existing field, set the field value to 'null'.
%
-spec update_bucket(binary(), list(), access_token()) -> {ok, bucket()} | {error, term()}.
update_bucket(Name, Properties, Token) ->
    Url = <<?BASE_URL/binary, Name/binary>>,
    ReqHeaders = add_auth_header(Token, [
        {<<"Content-Type">>, <<"application/json">>}
    ]),
    ReqBody = binary_to_list(jiffy:encode({Properties})),
    {ok, Status, Headers, Client} = hackney:request(patch, Url, ReqHeaders, ReqBody),
    case decode_response(Status, Headers, Client) of
        {ok, Body} -> {ok, make_bucket(Body)};
        R -> R
    end.

% @doc
%
% Deletes the named bucket. Returns ok upon success, or {error, Reason} if
% an error occurred.
%
-spec delete_bucket(binary(), access_token()) -> {ok, string()} | {error, term()}.
delete_bucket(Name, Token) ->
    Url = <<?BASE_URL/binary, Name/binary>>,
    ReqHeaders = add_auth_header(Token, []),
    {ok, Status, Headers, Client} = hackney:request(delete, Url, ReqHeaders),
    decode_response(Status, Headers, Client).

% @doc
%
% Construct a bucket record from the given property list.
%
-spec make_bucket(list()) -> bucket().
make_bucket(PropList) ->
    #bucket{
        id=proplists:get_value(<<"id">>, PropList),
        projectNumber=proplists:get_value(<<"projectNumber">>, PropList),
        name=proplists:get_value(<<"name">>, PropList),
        timeCreated=proplists:get_value(<<"timeCreated">>, PropList),
        updated=proplists:get_value(<<"updated">>, PropList),
        location=proplists:get_value(<<"location">>, PropList),
        storageClass=proplists:get_value(<<"storageClass">>, PropList)
    }.

% @doc
%
% Retrieve a list of the objects stored in the named bucket.
%
-spec list_objects(binary(), access_token()) -> {ok, object()} | {error, term()}.
list_objects(BucketName, Token) ->
    Url = <<?BASE_URL/binary, BucketName/binary, "/o">>,
    ReqHeaders = add_auth_header(Token, []),
    {ok, Status, Headers, Client} = hackney:request(get, Url, ReqHeaders),
    case decode_response(Status, Headers, Client) of
        {ok, Body} ->
            Items = proplists:get_value(<<"items">>, Body, []),
            {ok, [make_object(Item) || {Item} <- Items]};
        R -> R
    end.

% @doc
%
% Upload an object to the named bucket and return {ok, Object} or {error,
% Reason}, where Object has the updated object properties.
%
-spec upload_object(object(), request_body(), access_token()) -> {ok, object()} | {error, term()}.
upload_object(Object, RequestBody, Token) ->
    BucketName = Object#object.bucket,
    Url = hackney_url:make_url(
        ?UPLOAD_URL, <<BucketName/binary, "/o">>, [{"uploadType", "resumable"}]),
    ReqHeaders = add_auth_header(Token, [
        {<<"Content-Type">>, <<"application/json; charset=UTF-8">>},
        {<<"X-Upload-Content-Type">>, Object#object.contentType},
        {<<"X-Upload-Content-Length">>, Object#object.size}
    ]),
    ReqBody = binary_to_list(jiffy:encode({[
        {<<"name">>, Object#object.name},
        % include the md5 so GCP can verify the upload was successful
        {<<"md5Hash">>, Object#object.md5Hash}
    ]})),
    {ok, Status, Headers, Client} = hackney:request(post, Url, ReqHeaders, ReqBody),
    case Status of
        200 ->
            % need to read/skip the body to close the connection
            hackney:skip_body(Client),
            UploadUrl = proplists:get_value(<<"Location">>, Headers),
            do_upload(UploadUrl, Object, RequestBody, Token);
        _ -> decode_response(Status, Headers, Client)
    end.

% @doc
%
% Perform put request to upload the object to the given upload URL and return {ok, Object} or
% {error, Reason}, where Object has the updated object properties.
%
-spec do_upload(binary(), object(), request_body(), access_token()) -> {ok, object()} | {error, term()}.
do_upload(Url, Object, RequestBody, Token) ->
    ReqHeaders = add_auth_header(Token, [
        {<<"Content-Type">>, Object#object.contentType},
        {<<"Content-Length">>, Object#object.size}
    ]),
    % Receiving the response after an upload can take a few seconds, so
    % give it a chance to compute the MD5 and such before timing out. Set
    % the timeout rather high as it seems that certain inputs can cause a
    % long delay in response?
    Options = [{recv_timeout, 300000}],
    % Errors during upload are not unusual, so return them gracefully
    % rather than exploding and generating a lengthy crash report.

    %
    % TODO: works on Erlang 19? but not on Erlang 20?
    %
    case hackney:request(put, Url, ReqHeaders, RequestBody, Options) of
        {ok, Status, Headers, Client} ->
            case decode_response(Status, Headers, Client) of
                {ok, Body} -> {ok, make_object(Body)};
                R0 -> R0
            end;
        R1 -> R1
    end.

% @doc
%
% Retrieve the object and save to the named file.
%
-spec download_object(binary(), binary(), string(), credentials()) -> ok | {error, term()}.
download_object(BucketName, ObjectName, Filename, Token) ->
    ON = hackney_url:urlencode(ObjectName),
    UrlPath = <<BucketName/binary, "/o/", ON/binary>>,
    Url = hackney_url:make_url(?BASE_URL, UrlPath, [{"alt", "media"}]),
    ReqHeaders = add_auth_header(Token, []),
    {ok, Status, Headers, Client} = hackney:request(get, Url, ReqHeaders),
    case Status of
        200 ->
            {ok, FileHandle} = file:open(Filename, [write]),
            stream_to_file(FileHandle, Client);
        _ -> decode_response(Status, Headers, Client)
    end.

% @doc
%
% Stream the response body of the HTTP request to the opened file. Returns
% ok if successful, or {error, Reason} if not. The file will closed upon
% successful download.
%
-spec stream_to_file(term(), term()) -> ok | {error, term()}.
stream_to_file(FileHandle, Client) ->
    case hackney:stream_body(Client) of
        done -> file:close(FileHandle);
        {ok, Bin} ->
            ok = file:write(FileHandle, Bin),
            stream_to_file(FileHandle, Client);
        R -> R
    end.

% @doc
%
% Retrieve the properties of the named object in the named bucket.
%
-spec get_object(binary(), binary(), credentials()) -> {ok, object()} | {error, term()}.
get_object(BucketName, ObjectName, Token) ->
    ON = hackney_url:urlencode(ObjectName),
    Url = <<?BASE_URL/binary, BucketName/binary, "/o/", ON/binary>>,
    ReqHeaders = add_auth_header(Token, []),
    {ok, Status, Headers, Client} = hackney:request(get, Url, ReqHeaders),
    case decode_response(Status, Headers, Client) of
        {ok, Body} -> {ok, make_object(Body)};
        R -> R
    end.
% @doc
%
% Retrieve the contents of the named object in the named bucket.
%
-spec get_object_contents(binary(), binary(), credentials()) -> {ok, object()} | {error, term()}.
get_object_contents(BucketName, ObjectName, Token) ->
    ON = hackney_url:urlencode(ObjectName),
    UrlPath = <<BucketName/binary, "/o/", ON/binary>>,
    Url = hackney_url:make_url(?BASE_URL, UrlPath, [{"alt", "media"}]),
    ReqHeaders = add_auth_header(Token, []),
    {ok, Status, Headers, Client} = hackney:request(get, Url, ReqHeaders),
    case Status of
        200 -> stream_to_binary(Client);
        _ -> decode_response(Status, Headers, Client)
    end.

stream_to_binary(Client) -> stream_to_binary(Client, <<>>).
stream_to_binary(Client, Acc) ->
    case hackney:stream_body(Client) of
        done -> {ok, Acc};
        {ok, Data} -> stream_to_binary(Client, << Acc/binary, Data/binary >>);
        R -> R
    end.

% @doc
%
% Delete the named object in the named bucket.
%
-spec delete_object(binary(), binary(), credentials()) -> ok | {error, term()}.
delete_object(BucketName, ObjectName, Token) ->
    ON = hackney_url:urlencode(ObjectName),
    Url = <<?BASE_URL/binary, BucketName/binary, "/o/", ON/binary>>,
    ReqHeaders = add_auth_header(Token, []),
    {ok, Status, Headers, Client} = hackney:request(delete, Url, ReqHeaders),
    decode_response(Status, Headers, Client).

% @doc
%
% Update an existing object with the properties defined in the given
% property list (uses the PATCH method to update only those fields). The
% names and values should be binary instead of string type. To clear an
% existing field, set the field value to 'null'.
%
-spec update_object(binary(), binary(), list(), access_token()) -> {ok, object()} | {error, term()}.
update_object(BucketName, ObjectName, Properties, Token) ->
    ON = hackney_url:urlencode(ObjectName),
    Url = <<?BASE_URL/binary, BucketName/binary, "/o/", ON/binary>>,
    ReqHeaders = add_auth_header(Token, [
        {<<"Content-Type">>, <<"application/json">>}
    ]),
    ReqBody = binary_to_list(jiffy:encode({Properties})),
    {ok, Status, Headers, Client} = hackney:request(patch, Url, ReqHeaders, ReqBody),
    case decode_response(Status, Headers, Client) of
        {ok, Body} -> {ok, make_object(Body)};
        R -> R
    end.

% @doc
%
% Construct an object record from the given property list.
%
-spec make_object(list()) -> object().
make_object(PropList) ->
    #object{
        id=proplists:get_value(<<"id">>, PropList),
        name=proplists:get_value(<<"name">>, PropList),
        bucket=proplists:get_value(<<"bucket">>, PropList),
        contentType=proplists:get_value(<<"contentType">>, PropList),
        timeCreated=proplists:get_value(<<"timeCreated">>, PropList),
        updated=proplists:get_value(<<"updated">>, PropList),
        storageClass=proplists:get_value(<<"storageClass">>, PropList),
        size=proplists:get_value(<<"size">>, PropList),
        md5Hash=proplists:get_value(<<"md5Hash">>, PropList)
    }.

% @doc
%
% Add the "Authorization" header to those given and return the new list.
%
-spec add_auth_header(access_token(), list()) -> list().
add_auth_header(Token, Headers) ->
    AccessToken = Token#access_token.access_token,
    TokenType = Token#access_token.token_type,
    Authorization = <<TokenType/binary, " ", AccessToken/binary>>,
    Headers ++ [
        {<<"Authorization">>, Authorization}
    ].

% @doc
%
% Based on the response, return {ok, Body}, ok, or {error, Reason}. The
% body is the decoded JSON response from the server. The error
% 'auth_required' indicates a new authorization token must be retrieved. A
% 204 returns 'ok', while a 403 returns {error, forbidden}, 404 returns
% {error, not_found}, 409 returns {error, conflict}.
%
-spec decode_response(integer(), list(), term()) -> {ok, term()} | {error, term()}.
decode_response(400, _Headers, Client) ->
    {ok, Body} = hackney:body(Client),
    {error, Body};
decode_response(401, _Headers, Client) ->
    % need to read/skip the body to close the connection
    hackney:skip_body(Client),
    {error, auth_required};
decode_response(403, _Headers, Client) ->
    % need to read/skip the body to close the connection
    hackney:skip_body(Client),
    {error, forbidden};
decode_response(404, _Headers, Client) ->
    % need to read/skip the body to close the connection
    hackney:skip_body(Client),
    {error, not_found};
decode_response(409, _Headers, Client) ->
    % need to read/skip the body to close the connection
    hackney:skip_body(Client),
    {error, conflict};
decode_response(Ok, _Headers, Client) when Ok == 200; Ok == 201 ->
    {ok, Body} = hackney:body(Client),
    try jiffy:decode(Body) of
        {Results} -> {ok, Results}
    catch
        Error -> Error
    end;
decode_response(204, _Headers, Client) ->
    % need to read/skip the body to close the connection
    hackney:skip_body(Client),
    ok;
decode_response(_Status, _Headers, Client) ->
    {ok, Body} = hackney:body(Client),
    try jiffy:decode(Body) of
        {Results} -> {ok, Results}
    catch
        Error -> Error
    end.

% @doc
%
% Invoke the given function with an authorization token. If the function
% returns with an error indicating an expired authorization token, a new
% token will be retrieved and the function invoked again. If the token is
% replaced, the state will be updated with the new token.
%
-spec request_with_retry(fun(), credentials(), #state{}) -> {reply, term(), #state{}}.
request_with_retry(Fun, Credentials, #state{token=undefined}=State) ->
    case get_auth_token(Credentials) of
        {ok, Token} ->
            request_with_retry(Fun, Credentials, State#state{token=Token});
        Result -> {reply, Result, State}
    end;
request_with_retry(Fun, Credentials, State) ->
    case Fun(State#state.token) of
        {error, auth_required} ->
            case get_auth_token(Credentials) of
                {ok, Token} ->
                    {reply, Fun(Token), State#state{token=Token}};
                ResultI -> {reply, ResultI, State}
            end;
        ResultO -> {reply, ResultO, State}
    end.

% @doc
%
% Retrieve a read/write authorization token from the remote service, based
% on the provided credentials, which contains the client email address and
% the PEM encoded private key.
%
-spec get_auth_token(credentials()) -> {ok, access_token()} | {error, term()}.
get_auth_token(use_google_internal_metadata_server) ->
    %% it assumes that workload identity is properly configured
    {ok, Status, Headers, Client} = hackney:request(get, ?GOOGLE_INTERNAL_AUTH_URL, [{<<"Metadata-Flavor">>, <<"Google">>}]),
    decode_token_response(Status, Headers, Client);
get_auth_token(Creds) ->
    Now = seconds_since_epoch(),
    % GCP seems to completely ignore the timeout value and always expires
    % in 3600 seconds anyway. Who knows, maybe someday it will work, but
    % you can forget about automated testing of expiration for now.
    Timeout = application:get_env(enenra, auth_timeout, 3600),
    ClaimSet = base64:encode(jiffy:encode({[
        {<<"iss">>, Creds#credentials.client_email},
        {<<"scope">>, ?FULL_CONTROL_SCOPE},
        {<<"aud">>, ?AUD_URL},
        {<<"exp">>, Now + Timeout},
        {<<"iat">>, Now}
    ]})),
    JwtPrefix = <<?JWT_HEADER/binary, ".", ClaimSet/binary>>,
    PrivateKey = Creds#credentials.private_key,
    Signature = compute_signature(PrivateKey, JwtPrefix),
    Jwt = <<JwtPrefix/binary, ".", Signature/binary>>,
    ReqBody = {form, [{<<"grant_type">>, ?GRANT_TYPE}, {<<"assertion">>, Jwt}]},
    {ok, Status, Headers, Client} = hackney:request(post, ?AUTH_URL, [], ReqBody),
    decode_token_response(Status, Headers, Client).

decode_token_response(Status, Headers, Client) ->
    case decode_response(Status, Headers, Client) of
        {ok, Token} ->
            AccessToken = proplists:get_value(<<"access_token">>, Token),
            TokenType = proplists:get_value(<<"token_type">>, Token),
            {ok, #access_token{access_token=AccessToken, token_type=TokenType}};
        R -> R
    end.

% @doc
%
% Return the seconds since the epoch (1970/1/1 00:00).
%
-spec seconds_since_epoch() -> integer().
seconds_since_epoch() ->
    {Mega, Sec, _Micro} = os:timestamp(),
    Mega * 1000000 + Sec.

% @doc
%
% Compute the SHA256 signature of the given Msg data, using the PEM key
% binary data (which will be decoded and from which the RSA private key
% is extracted). The result is Base64 encoded, appropriate for making
% an authorization request.
%
-spec compute_signature(binary(), binary()) -> binary().
compute_signature(PemKeyBin, Msg) ->
    [PemKeyData] = public_key:pem_decode(PemKeyBin),
    PemKey = public_key:pem_entry_decode(PemKeyData),
    RsaKey = public_key:der_decode('RSAPrivateKey', PemKey#'PrivateKeyInfo'.privateKey),
    base64:encode(public_key:sign(Msg, sha256, RsaKey)).
