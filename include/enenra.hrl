%% -*- coding: utf-8 -*-
%%
%% Copyright 2016 Nathan Fiedler. All rights reserved.
%% Use of this source code is governed by a BSD-style
%% license that can be found in the LICENSE file.
%%

-record(credentials, {
    type :: binary(),
    project_id :: binary(),
    private_key_id :: binary(),
    private_key :: binary(),
    client_email :: binary(),
    client_id :: binary()
}).
-type credentials() :: #credentials{
    type :: binary(),
    project_id :: binary(),
    private_key_id :: binary(),
    private_key :: binary(),
    client_email :: binary(),
    client_id :: binary()
}.
-export_type([credentials/0]).

-record(access_token, {
    access_token,
    token_type
}).
-type access_token() :: #access_token{
    access_token :: binary(),
    token_type :: binary()
}.
-export_type([access_token/0]).

-record(bucket, {
    id :: binary(),
    projectNumber :: binary(),
    name :: binary(),
    timeCreated :: binary(),
    updated :: binary(),
    location :: binary(),
    storageClass :: binary()
}).
-type bucket() :: #bucket{
    id :: binary(),
    projectNumber :: binary(),
    name :: binary(),
    timeCreated :: binary(),
    updated :: binary(),
    location :: binary(),
    storageClass :: binary()
}.
-export_type([bucket/0]).

-record(object, {
    id :: binary(),
    name :: binary(),
    bucket :: binary(),
    contentType :: binary(),
    timeCreated :: binary(),
    updated :: binary(),
    storageClass :: binary(),
    size :: integer(),
    md5Hash :: binary()
}).
-type object() :: #object{
    id :: binary(),
    name :: binary(),
    bucket :: binary(),
    contentType :: binary(),
    timeCreated :: binary(),
    updated :: binary(),
    storageClass :: binary(),
    size :: integer(),
    md5Hash :: binary()
}.
-export_type([object/0]).

-type request_body() :: {file, string()} | iodata().
-export_type([request_body/0]).
