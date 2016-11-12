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
    NewState = ensure_connection(Credentials, State),
    {ok, Buckets} = list_buckets(Credentials, NewState#state.token),
    {reply, Buckets, NewState}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(Msg, State) ->
    lager:notice("unexpected message: ~w", [Msg]),
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
% Ensure a connection is available for sending requests, creating a new one
% using the given credentials, if necessary.
%
ensure_connection(Credentials, #state{}=State) ->
    case State#state.token of
        undefined ->
            {ok, Token} = get_auth_token(Credentials),
            % {ok, Connection} = create_connection(Credentials),
            State#state{token=Token};
        _ -> State
    end.

% @doc
%
% Retrieve a list of the available buckets.
%
list_buckets(Credentials, Token) ->
    Project = Credentials#credentials.project_id,
    AccessToken = Token#access_token.access_token,
    TokenType = Token#access_token.token_type,
    Authorization = binary_to_list(TokenType) ++ " " ++ binary_to_list(AccessToken),
    ReqHeaders = [
        {"Authorization", Authorization}
    ],
    Parameters = [
        {"project", Project}
    ],
    Url = hackney_url:make_url(?BASE_URL, "", Parameters),
    {ok, _Status, _Headers, Client} = hackney:request(get, Url, ReqHeaders),
    {ok, Body} = hackney:body(Client),
    {Results} = jiffy:decode(Body),
    % TODO: handle token expiration by creating new connection
    Items = proplists:get_value(<<"items">>, Results),
    {ok, [make_bucket(Item) || {Item} <- Items]}.

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
% Retrieve a read/write authorization token from the remote service, based
% on the provided credentials, which contains the client email address and
% the PEM encoded private key.
%
-spec get_auth_token(credentials()) -> {ok, access_token()}.
get_auth_token(Creds) ->
    Now = seconds_since_epoch(),
    ClaimSet = binary_to_list(base64:encode(jiffy:encode({[
        {<<"iss">>, Creds#credentials.client_email},
        {<<"scope">>, ?READ_WRITE_SCOPE},
        {<<"aud">>, ?AUD_URL},
        {<<"exp">>, Now + 3600},
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
