%% -*- coding: utf-8 -*-
%%
%% Copyright 2016 Nathan Fiedler. All rights reserved.
%% Use of this source code is governed by a BSD-style
%% license that can be found in the LICENSE file.
%%
-module(enenra_app).
-behaviour(application).
-export([start/2, stop/1]).

start(_Type, _Args) ->
    enenra_sup:start_link().

stop(_) ->
    ok.
