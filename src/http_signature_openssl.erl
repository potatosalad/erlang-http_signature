%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2017, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  05 Oct 2017 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(http_signature_openssl).
-behaviour(gen_statem).

%% API
-export([start_link/4]).
-export([call/1]).
-export([call/2]).
-export([call/3]).

%% gen_statem callbacks
-export([callback_mode/0]).
-export([init/1]).
-export([handle_event/4]).

%%%===================================================================
%%% API functions
%%%===================================================================

start_link(From, Stdin, Args, Timeout) ->
	gen_statem:start_link(?MODULE, {From, Stdin, Args, Timeout}, []).

call(Args) ->
	call(<<>>, Args).

call(Stdin, Args) ->
	call(Stdin, Args, 5000).

call(Stdin, Args, Timeout)
		when is_binary(Stdin)
		andalso ((is_integer(Timeout) andalso Timeout >= 0)
			orelse Timeout == infinity) ->
	To = erlang:self(),
	Tag = erlang:make_ref(),
	{Pid, MonitorRef} = erlang:spawn_monitor(fun () ->
		From = {erlang:self(), Tag},
		{ok, _} = ?MODULE:start_link(From, Stdin, Args, Timeout),
		receive
			{Tag, Reply} ->
				To ! {Tag, Reply},
				erlang:exit(normal)
		end
	end),
	case Timeout of
		infinity ->
			receive
				{Tag, Reply} ->
					_ = erlang:demonitor(MonitorRef, [flush]),
					_ = erlang:exit(Pid, kill),
					receive
						{'DOWN', MonitorRef, process, Pid, _} ->
							ok
					after
						0 ->
							ok
					end,
					Reply;
				{'DOWN', MonitorRef, process, Pid, Reason} ->
					{error, Reason}
			end;
		_ ->
			AdjustedTimeout = Timeout + 100,
			receive
				{Tag, Reply} ->
					_ = erlang:demonitor(MonitorRef, [flush]),
					_ = erlang:exit(Pid, kill),
					receive
						{'DOWN', MonitorRef, process, Pid, _} ->
							ok
					after
						0 ->
							ok
					end,
					Reply;
				{'DOWN', MonitorRef, process, Pid, Reason} ->
					{error, Reason}
			after
				AdjustedTimeout ->
					_ = erlang:demonitor(MonitorRef, [flush]),
					_ = erlang:exit(Pid, kill),
					_ = erlang:demonitor(MonitorRef, [flush]),
					_ = erlang:exit(Pid, kill),
					receive
						{'DOWN', MonitorRef, process, Pid, _} ->
							ok
					after
						0 ->
							ok
					end,
					{error, timeout}
			end
	end.

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================

%% @private
callback_mode() ->
	handle_event_function.

%% @private
init({From={To, _}, Stdin, Args, Timeout}) ->
	true = erlang:link(To),
	Data = #{
		args => Args,
		buffer => <<>>,
		from => From,
		port => nil,
		stdin => Stdin,
		timeout => Timeout
	},
	Actions = [{state_timeout, 0, open}],
	{ok, closed, Data, Actions}.

%% @private
% State Timeout Events
handle_event(state_timeout, open, closed, Data0 = #{ args := Args, stdin := Stdin, timeout := Timeout }) ->
	Command = io_lib:format("~s ~s", [
		application:get_env(http_signature, openssl, "openssl"),
		Args
	]),
	PortOpts = [exit_status, use_stdio, binary, stream, stderr_to_stdout],
	Port = erlang:open_port({spawn, Command}, PortOpts),
	ok =
		case Stdin of
			<<>> ->
				ok;
			_ ->
				true = erlang:port_command(Port, Stdin),
				ok
		end,
	Data1 = Data0#{ port := Port },
	Actions = [{state_timeout, Timeout, timeout}],
	{next_state, open, Data1, Actions};
handle_event(state_timeout, timeout, open, Data0 = #{ from := From, port := Port }) ->
	catch erlang:port_close(Port),
	Data1 = Data0#{ buffer := <<>>, port := nil },
	Actions = [{reply, From, {error, timeout}}],
	{stop_and_reply, normal, Actions, Data1};
% Info Events
handle_event(info, {Port, {data, Output}}, open, Data0 = #{ buffer := Buffer0, port := Port }) ->
	Buffer1 = << Buffer0/binary, Output/binary >>,
	Data1 = Data0#{ buffer := Buffer1 },
	{keep_state, Data1};
handle_event(info, {Port, {exit_status, ExitStatus}}, open, Data0 = #{ buffer := Buffer, from := From, port := Port }) ->
	catch erlang:port_close(Port),
	Data1 = Data0#{ buffer := <<>>, port := nil },
	Actions = [{reply, From, {ok, ExitStatus, Buffer}}],
	{stop_and_reply, normal, Actions, Data1};
handle_event(info, {Port, closed}, open, Data0 = #{ from := From, port := Port }) ->
	catch erlang:port_close(Port),
	Data1 = Data0#{ buffer := <<>>, port := nil },
	Actions = [{reply, From, {error, closed}}],
	{stop_and_reply, normal, Actions, Data1}.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
