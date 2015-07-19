defmodule HTTPSignature.Mixfile do
  use Mix.Project

  def project do
    [app: :http_signature,
     version: "1.1.0",
     elixir: "~> 1.0",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps,
     name: "HTTPSignature",
     source_url: "https://github.com/potatosalad/erlang-http_signature",
     docs: fn ->
       {ref, 0} = System.cmd("git", ["rev-parse", "--verify", "--quiet", "HEAD"])
       [source_ref: ref, main: "README", readme: "README.md"]
     end,
     description: description,
     package: package]
  end

  defp deps do
    []
  end

  defp description do
    "Erlang and Elixir implementations of Joyent's HTTP Signature Scheme."
  end

  defp package do
    [contributors: ["Andrew Bennett"],
     files: [
       "build.config",
       "CHANGELOG*",
       "erlang.mk",
       "include",
       "lib",
       "LICENSE*",
       "priv",
       "Makefile",
       "mix.exs",
       "README*",
       "rebar.config",
       "src"
     ],
     licenses: ["Mozilla Public License Version 2.0"],
     links: %{"Github" => "https://github.com/potatosalad/erlang-http_signature"}]
  end
end
