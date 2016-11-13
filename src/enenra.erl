%% -*- coding: utf-8 -*-
%%
%% Copyright 2016 Nathan Fiedler. All rights reserved.
%% Use of this source code is governed by a BSD-style
%% license that can be found in the LICENSE file.
%%

%
% @author Nathan Fiedler <nathanfiedler@fastmail.fm>
% @copyright 2016 Nathan Fiedler
% @version 0.1.0
% @doc A library for interfacing with Google Cloud Storage.
%
% `enenra' is an Erlang/OTP library for creating buckets, uploading objects,
% and otherwise managing said resources on Google Cloud Storage. This is
% done via the HTTP/JSON API described here:
% https://cloud.google.com/storage/docs/json_api/
%
% Some example usage:
%
% ```
% TODO
% '''
%
-module(enenra).

-include("enenra.hrl").

-export([load_credentials/1]).
-export([list_buckets/1, get_bucket/2, insert_bucket/2, delete_bucket/2]).

%
% TODO: URI encode the object names
% TODO: ensure bucket names meet requirements
%       (https://cloud.google.com/storage/docs/naming#requirements)
%

% @doc
%
% Load the credentials for the given file, which is assumed to be a JSON
% file containing the client email address, project identifier, private key
% in PEM format, as well as other properties.
%
-spec load_credentials(string()) -> {ok, credentials()}.
load_credentials(Filepath) ->
    {ok, JsonBin} = file:read_file(Filepath),
    {Creds} = jiffy:decode(JsonBin),
    {ok, #credentials{
        type=proplists:get_value(<<"type">>, Creds),
        project_id=proplists:get_value(<<"project_id">>, Creds),
        private_key_id=proplists:get_value(<<"private_key_id">>, Creds),
        private_key=proplists:get_value(<<"private_key">>, Creds),
        client_email=proplists:get_value(<<"client_email">>, Creds),
        client_id=proplists:get_value(<<"client_id">>, Creds)
    }}.

% @doc
%
% Retrieve the buckets available to the account with the given credentials.
%
-spec list_buckets(Credentials) -> {ok, Buckets} | {error, Reason} when
    Credentials :: credentials(),
    Buckets :: [bucket()],
    Reason :: term().
list_buckets(#credentials{}=Credentials) ->
    gen_server:call(enenra_server, {list_buckets, Credentials}).

% @doc
%
% Retrieve the named bucket, returning {ok, Bucket} upon success.
%
-spec get_bucket(Name, Credentials) -> {ok, Bucket} | {error, Reason} when
    Credentials :: credentials(),
    Name :: binary() | string(),
    Bucket :: bucket(),
    Reason :: term().
get_bucket(Name, #credentials{}=Credentials) ->
    gen_server:call(enenra_server, {get_bucket, Name, Credentials}).

% @doc
%
% Create a bucket with the given properties.
%
-spec insert_bucket(Bucket, Credentials) -> {ok, Bucket} | {error, Reason} when
    Credentials :: credentials(),
    Bucket :: bucket(),
    Reason :: term().
insert_bucket(Bucket, #credentials{}=Credentials) ->
    gen_server:call(enenra_server, {insert_bucket, Bucket, Credentials}).

% @doc
%
% Delete the named bucket, return {ok, Name} upon success.
%
-spec delete_bucket(Name, Credentials) -> {ok, Name} | {error, Reason} when
    Credentials :: credentials(),
    Name :: binary() | string(),
    Reason :: term().
delete_bucket(Name, #credentials{}=Credentials) ->
    gen_server:call(enenra_server, {delete_bucket, Name, Credentials}).

% TODO: update a bucket

% TODO: upload object

% TODO: list objects

% TODO: fetch object

% TODO: delete object
