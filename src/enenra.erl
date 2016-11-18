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
% done via the HTTP/JSON API described in the Google Cloud Storage
% documentation (https://cloud.google.com/storage/docs/json_api/).
%
% Some example usage:
%
% ```
% TODO
% '''
%
% Regarding the authorization scope used for interacting with Google Cloud
% Storage, the `full-control' scope is used, as that allows modifying
% existing resources. The `read-write' scope only allows creating and
% deleting, but not patching.
%
-module(enenra).

-include("enenra.hrl").

-export([load_credentials/1, compute_md5/1]).
-export([list_buckets/1, get_bucket/2, insert_bucket/2, update_bucket/3, delete_bucket/2]).
-export([list_objects/2, get_object/3, update_object/4, delete_object/3]).
-export([upload_file/3, download_object/4]).

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
list_buckets(Credentials) ->
    gen_server:call(enenra_server, {list_buckets, Credentials}).

% @doc
%
% Retrieve the named bucket, returning {ok, Bucket} upon success.
%
-spec get_bucket(Name, Credentials) -> {ok, Bucket} | {error, Reason} when
    Credentials :: credentials(),
    Name :: binary(),
    Bucket :: bucket(),
    Reason :: term().
get_bucket(Name, Credentials) ->
    gen_server:call(enenra_server, {get_bucket, Name, Credentials}).

% @doc
%
% Create a bucket with the given properties.
%
-spec insert_bucket(Bucket, Credentials) -> {ok, Bucket} | {error, Reason} when
    Credentials :: credentials(),
    Bucket :: bucket(),
    Reason :: term().
insert_bucket(Bucket, Credentials) ->
    gen_server:call(enenra_server, {insert_bucket, Bucket, Credentials}).

% @doc
%
% Delete the named bucket, return {ok, Name} upon success.
%
-spec delete_bucket(Name, Credentials) -> {ok, Name} | {error, Reason} when
    Credentials :: credentials(),
    Name :: binary(),
    Reason :: term().
delete_bucket(Name, Credentials) ->
    gen_server:call(enenra_server, {delete_bucket, Name, Credentials}).

% @doc
%
% Update the named bucket with the given properties, using the PATCH method
% such that only the named fields are modified. To clear a field, the value
% should be 'null'. Returns the updated bucket resource.
%
-spec update_bucket(Name, Properties, Credentials) -> {ok, Bucket} | {error, Reason} when
    Credentials :: credentials(),
    Properties :: list(),
    Bucket :: bucket(),
    Name :: binary(),
    Reason :: term().
update_bucket(Name, Properties, Credentials) ->
    gen_server:call(enenra_server, {update_bucket, Name, Properties, Credentials}).

% @doc
%
% Retrieve the objects within the named bucket.
%
-spec list_objects(BucketName, Credentials) -> {ok, Objects} | {error, Reason} when
    BucketName :: binary(),
    Credentials :: credentials(),
    Objects :: [object()],
    Reason :: term().
list_objects(BucketName, Credentials) ->
    gen_server:call(enenra_server, {list_objects, BucketName, Credentials}).

% @doc
%
% Upload the file identified by Filename, with the properties given by
% Object, to the bucket named in the Object#bucket field. The returned
% Object value will have the updated properties.
%
-spec upload_file(Filename, Object, Credentials) -> {ok, Object} | {error, Reason} when
    Filename :: string(),
    Object :: object(),
    Credentials :: credentials(),
    Reason :: term().
upload_file(Filename, Object, Credentials) ->
    gen_server:call(enenra_server, {upload_object, Object, Filename, Credentials}).

% @doc
%
% Retrieve the object named ObjectName in the bucket named BucketName,
% storing the result in the file named Filename. Returns 'ok' on success,
% or {error, Reason} if error.
%
-spec download_object(BucketName, ObjectName, Filename, Credentials) -> ok | {error, Reason} when
    Filename :: string(),
    BucketName :: binary(),
    ObjectName :: binary(),
    Credentials :: credentials(),
    Reason :: term().
download_object(BucketName, ObjectName, Filename, Credentials) ->
    gen_server:call(enenra_server, {download_object, BucketName, ObjectName, Filename, Credentials}).

% @doc
%
% Retrieve the properties of the object named ObjectName in the bucket
% named BucketName, returning {ok, Object} if successful, or {error,
% Reason} if an error occurred.
%
-spec get_object(BucketName, ObjectName, Credentials) -> {ok, Object} | {error, Reason} when
    BucketName :: binary(),
    ObjectName :: binary(),
    Credentials :: credentials(),
    Object :: object(),
    Reason :: term().
get_object(BucketName, ObjectName, Credentials) ->
    gen_server:call(enenra_server, {get_object, BucketName, ObjectName, Credentials}).

% @doc
%
% Update the object in the named bucket, using the PATCH method such that
% only the named fields are modified. To clear a field, the value should be
% 'null'. Returns the updated object resource.
%
-spec update_object(BucketName, ObjectName, Properties, Credentials) -> {ok, Object} | {error, Reason} when
    Credentials :: credentials(),
    Properties :: list(),
    Object :: object(),
    BucketName :: binary(),
    ObjectName :: binary(),
    Reason :: term().
update_object(BucketName, ObjectName, Properties, Credentials) ->
    gen_server:call(enenra_server, {update_object, BucketName, ObjectName, Properties, Credentials}).

% @doc
%
% Delete the object named ObjectName in the bucket named BucketName,
% returning 'ok' if successful, or {error, Reason} if an error occurred.
%
-spec delete_object(BucketName, ObjectName, Credentials) -> ok | {error, Reason} when
    BucketName :: binary(),
    ObjectName :: binary(),
    Credentials :: credentials(),
    Reason :: term().
delete_object(BucketName, ObjectName, Credentials) ->
    gen_server:call(enenra_server, {delete_object, BucketName, ObjectName, Credentials}).

% @doc
%
% Compute the MD5 checksum for the named file, returning the Base64 encoded
% result. This value can be given in the upload request and Google Cloud
% Storage will verify the upload was successful by comparing the checksum
% with its own computation.
%
-spec compute_md5(Filename) -> {ok, Digest} | {error, Reason} when
    Filename :: string(),
    Digest :: string(),
    Reason :: term().
compute_md5(Filename) ->
    {ok, Filehandle} = file:open(Filename, [read, binary, read_ahead]),
    Context = erlang:md5_init(),
    case compute_md5(Filehandle, Context) of
        {ok, Digest} -> {ok, base64:encode(Digest)};
        R -> R
    end.

% @doc
%
% Helper function that recursively computes the MD5 of the opened file in
% 64KB chunks. The file will be closed upon successful completion.
%
compute_md5(Filehandle, Context) ->
    case file:read(Filehandle, 65536) of
        {ok, Data} ->
            NewContext = erlang:md5_update(Context, Data),
            compute_md5(Filehandle, NewContext);
        eof ->
            case file:close(Filehandle) of
                ok -> {ok, erlang:md5_final(Context)};
                RR -> RR
            end;
        R -> R
    end.
