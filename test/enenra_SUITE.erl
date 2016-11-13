%% -*- coding: utf-8 -*-
%%
%% Copyright 2016 Nathan Fiedler. All rights reserved.
%% Use of this source code is governed by a BSD-style
%% license that can be found in the LICENSE file.
%%
-module(enenra_SUITE).
-compile(export_all).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("enenra.hrl").

init_per_suite(Config) ->
    % starting our app starts everything else that we need (e.g. hackney)
    {ok, _Started} = application:ensure_all_started(enenra),
    Config.

end_per_suite(_Config) ->
    case application:stop(enenra) of
        ok -> ok;
        {error, {not_started, enenra}} -> ok;
        {error, Reason} -> error(Reason)
    end.

all() ->
    [
        list_buckets_test
    ].

list_buckets_test(_Config) ->
    Credentials = get_env("GOOGLE_APPLICATION_CREDENTIALS"),
    {ok, Creds} = enenra:load_credentials(Credentials),
    {ok, Buckets} = enenra:list_buckets(Creds),
    ?assert(is_list(Buckets)),
    ok.

% Retrieve an environment variable, ensuring it is defined.
get_env(Name) ->
    case os:getenv(Name) of
        false ->
            error(lists:flatten(io_lib:format("must define ~p environment variable", [Name])));
        Value -> Value
    end.
