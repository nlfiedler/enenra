%% -*- coding: utf-8 -*-
%%
%% Copyright 2016 Nathan Fiedler. All rights reserved.
%% Use of this source code is governed by a BSD-style
%% license that can be found in the LICENSE file.
%%

-record(credentials, {
    type :: binary,
    project_id :: binary,
    private_key_id :: binary,
    private_key :: binary,
    client_email :: binary,
    client_id :: binary
}).
-type credentials() :: #credentials{
    type :: binary,
    project_id :: binary,
    private_key_id :: binary,
    private_key :: binary,
    client_email :: binary,
    client_id :: binary
}.
-export_type([credentials/0]).

-record(access_token, {
    access_token,
    token_type
}).
-type access_token() :: #access_token{
    access_token :: binary,
    token_type :: binary
}.
-export_type([access_token/0]).

-record(connection, {
    creds,
    token
}).
-type connection() :: #connection{
    creds :: credentials(),
    token :: access_token()
}.
-export_type([connection/0]).

-record(bucket, {
    id :: binary,
    project :: binary,
    name :: binary,
    created :: binary,
    updated :: binary,
    location :: binary,
    class :: binary
}).
-type bucket() :: #bucket{
    id :: binary,
    project :: binary,
    name :: binary,
    created :: binary,
    updated :: binary,
    location :: binary,
    class :: binary
}.
-export_type([bucket/0]).
