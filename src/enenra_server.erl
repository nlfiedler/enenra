%% -*- coding: utf-8 -*-
%%
%% Copyright 2016 Nathan Fiedler. All rights reserved.
%% Use of this source code is governed by a BSD-style
%% license that can be found in the LICENSE file.
%%
-module(enenra_server).

-behavior(gen_server).
-export([start_link/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(BASE_URL, "https://www.googleapis.com/storage/v1/b/").
-define(AUTH_URL, "https://www.googleapis.com/oauth2/v4/token").
-define(AUD_URL, <<"https://www.googleapis.com/oauth2/v4/token">>).

% read/write is useful for adding and deleting, but that's about it
-define(READ_WRITE_SCOPE, <<"https://www.googleapis.com/auth/devstorage.read_write">>).
% full-control is required for updating/patching existing resources
-define(FULL_CONTROL_SCOPE, <<"https://www.googleapis.com/auth/devstorage.full_control">>).

% Base64 encoding of JSON {"alg":"RS256","typ":"JWT"}
-define(JWT_HEADER, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9").
-define(GRANT_TYPE, "urn:ietf:params:oauth:grant-type:jwt-bearer").

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
handle_call({update_bucket, Name, Bucket, Credentials}, _From, State) ->
    UpdateBucket = fun(Token) ->
        update_bucket(Name, Bucket, Token)
    end,
    request_with_retry(UpdateBucket, Credentials, State);
handle_call({delete_bucket, Name, Credentials}, _From, State) ->
    DeleteBucket = fun(Token) ->
        delete_bucket(Name, Token)
    end,
    request_with_retry(DeleteBucket, Credentials, State).

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
-spec list_buckets(credentials(), access_token()) -> {ok, [bucket()]}.
list_buckets(Credentials, Token) ->
    Project = Credentials#credentials.project_id,
    Url = hackney_url:make_url(?BASE_URL, "", [{"project", Project}]),
    ReqHeaders = add_auth_header(Token, []),
    {ok, Status, Headers, Client} = hackney:request(get, Url, ReqHeaders),
    case decode_response(Status, Headers, Client) of
        {ok, Body} ->
            Items = proplists:get_value(<<"items">>, Body),
            {ok, [make_bucket(Item) || {Item} <- Items]};
        R -> R
    end.

% @doc
%
% Retrieve the named bucket.
%
-spec get_bucket(string() | binary(), access_token()) -> {ok, bucket()}.
get_bucket(Name, Token) when is_binary(Name) ->
    get_bucket(binary_to_list(Name), Token);
get_bucket(Name, Token) when is_list(Name) ->
    Url = ?BASE_URL ++ Name,
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
-spec insert_bucket(bucket(), credentials(), access_token()) -> {ok, bucket()}.
insert_bucket(Bucket, Credentials, Token) ->
    Project = Credentials#credentials.project_id,
    Url = hackney_url:make_url(?BASE_URL, "", [{"project", Project}]),
    ReqHeaders = add_auth_header(Token, [
        {"Content-Type", "application/json"}
    ]),
    ReqBody = binary_to_list(jiffy:encode({[
        {<<"name">>, Bucket#bucket.name},
        {<<"location">>, Bucket#bucket.location},
        {<<"storageClass">>, Bucket#bucket.class}
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
-spec update_bucket(string() | binary(), list(), access_token()) -> {ok, bucket()}.
update_bucket(Name, Bucket, Token) when is_binary(Name) ->
    update_bucket(binary_to_list(Name), Bucket, Token);
update_bucket(Name, Bucket, Token) when is_list(Name) ->
    Url = ?BASE_URL ++ Name,
    ReqHeaders = add_auth_header(Token, [
        {"Content-Type", "application/json"}
    ]),
    ReqBody = binary_to_list(jiffy:encode({Bucket})),
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
-spec delete_bucket(string() | binary(), access_token()) -> {ok, string()}.
delete_bucket(Name, Token) when is_binary(Name) ->
    delete_bucket(binary_to_list(Name), Token);
delete_bucket(Name, Token) when is_list(Name) ->
    Url = ?BASE_URL ++ Name,
    ReqHeaders = add_auth_header(Token, []),
    {ok, Status, _Headers, Client} = hackney:request(delete, Url, ReqHeaders),
    case Status of
        Ok when Ok == 200; Ok == 204 -> ok;
        _S -> {ok, Body} = hackney:body(Client), {error, Body}
    end.

% @doc
%
% Construct a bucket record from the given property list.
%
-spec make_bucket([term()]) -> bucket().
make_bucket(PropList) ->
    #bucket{
        id=proplists:get_value(<<"id">>, PropList),
        project=proplists:get_value(<<"projectNumber">>, PropList),
        name=proplists:get_value(<<"name">>, PropList),
        created=proplists:get_value(<<"timeCreated">>, PropList),
        updated=proplists:get_value(<<"updated">>, PropList),
        location=proplists:get_value(<<"location">>, PropList),
        class=proplists:get_value(<<"storageClass">>, PropList)
    }.

% @doc
%
% Add the "Authorization" header to those given and return the new list.
%
-spec add_auth_header(access_token(), list()) -> list().
add_auth_header(Token, Headers) ->
    AccessToken = Token#access_token.access_token,
    TokenType = Token#access_token.token_type,
    Authorization = binary_to_list(TokenType) ++ " " ++ binary_to_list(AccessToken),
    Headers ++ [
        {"Authorization", Authorization}
    ].

% @doc
%
% Based on the response, return {ok, Body} or {error, Reason}. The body is
% the decoded JSON response from the server. The error 'auth_required'
% indicates a new authorization token must be retrieved.
%
-spec decode_response(integer(), list(), term()) -> {ok, term()} | {error, term()}.
decode_response(401, _Headers, _Client) ->
    {error, auth_required};
decode_response(403, _Headers, _Client) ->
    {error, forbidden};
decode_response(409, _Headers, _Client) ->
    {error, conflict};
decode_response(200, _Headers, Client) ->
    {ok, Body} = hackney:body(Client),
    {Results} = jiffy:decode(Body),
    {ok, Results};
decode_response(_Status, _Headers, Client) ->
    {ok, Body} = hackney:body(Client),
    {Results} = jiffy:decode(Body),
    {error, Results}.

% @doc
%
% Invoke the given function with an authorization token. If the function
% returns with an error indicating an expired authorization token, a new
% token will be retrieved and the function invoked again. If the token is
% replaced, the state will be updated with the new token.
%
-spec request_with_retry(fun(), credentials(), #state{}) -> {reply, term(), #state{}}.
request_with_retry(Fun, Credentials, #state{token=undefined}=State) ->
    {ok, Token} = get_auth_token(Credentials),
    request_with_retry(Fun, Credentials, State#state{token=Token});
request_with_retry(Fun, Credentials, State) ->
    case Fun(State#state.token) of
        {error, auth_required} ->
            {ok, Token} = get_auth_token(Credentials),
            Result = Fun(Token),
            {reply, Result, State#state{token=Token}};
        Result -> {reply, Result, State}
    end.

% @doc
%
% Retrieve a read/write authorization token from the remote service, based
% on the provided credentials, which contains the client email address and
% the PEM encoded private key.
%
-spec get_auth_token(credentials()) -> {ok, access_token()}.
get_auth_token(Creds) ->
    Now = seconds_since_epoch(),
    Timeout = application:get_env(enenra, auth_timeout, 3600),
    ClaimSet = binary_to_list(base64:encode(jiffy:encode({[
        {<<"iss">>, Creds#credentials.client_email},
        {<<"scope">>, ?FULL_CONTROL_SCOPE},
        {<<"aud">>, ?AUD_URL},
        {<<"exp">>, Now + Timeout},
        {<<"iat">>, Now}
    ]}))),
    JwtPrefix = ?JWT_HEADER ++ "." ++ ClaimSet,
    PrivateKey = Creds#credentials.private_key,
    Signature = compute_signature(PrivateKey, list_to_binary(JwtPrefix)),
    Jwt = JwtPrefix ++ "." ++ binary_to_list(Signature),
    Body = {form, [{"grant_type", ?GRANT_TYPE}, {"assertion", Jwt}]},
    {ok, _Status, _Headers, Client} = hackney:request(post, ?AUTH_URL, [], Body),
    {ok, Result} = hackney:body(Client),
    {TokenList} = jiffy:decode(Result),
    AccessToken = proplists:get_value(<<"access_token">>, TokenList),
    TokenType = proplists:get_value(<<"token_type">>, TokenList),
    {ok, #access_token{access_token=AccessToken, token_type=TokenType}}.

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
