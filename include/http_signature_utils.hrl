%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2017, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  07 Oct 2017 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------

-ifndef(HTTP_SIGNATURE_UTILS_HRL).

-define(http_signature_throw(Tag, Format, Arguments),
	erlang:throw({Tag, erlang:iolist_to_binary(io_lib:format(Format, Arguments))})).

%% INLINE_LOWERCASE_BC(Bin)
%%
%% Lowercase the entire binary string in a binary comprehension.

-define(INLINE_LOWERCASE_BC(Bin),
	<< << case C of
		$A -> $a;
		$B -> $b;
		$C -> $c;
		$D -> $d;
		$E -> $e;
		$F -> $f;
		$G -> $g;
		$H -> $h;
		$I -> $i;
		$J -> $j;
		$K -> $k;
		$L -> $l;
		$M -> $m;
		$N -> $n;
		$O -> $o;
		$P -> $p;
		$Q -> $q;
		$R -> $r;
		$S -> $s;
		$T -> $t;
		$U -> $u;
		$V -> $v;
		$W -> $w;
		$X -> $x;
		$Y -> $y;
		$Z -> $z;
		C -> C
	end >> || << C >> <= Bin >>).

-define(HTTP_SIGNATURE_UTILS_HRL, 1).

-endif.
