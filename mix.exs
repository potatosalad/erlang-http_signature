defmodule HTTPSignature.Mixfile do
  use Mix.Project

  def project() do
    [
      app: :http_signature,
      version: "2.0.0",
      elixir: "~> 1.4",
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      deps: deps(),
      description: description(),
      docs: fn ->
        {ref, 0} = System.cmd("git", ["rev-parse", "--verify", "--quiet", "HEAD"])
        [source_ref: ref, main: "readme", extras: ["README.md", "CHANGELOG.md"]]
      end,
      name: "http_signature",
      package: package(),
      source_url: "https://github.com/potatosalad/erlang-http_signature"
    ]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application() do
    # Specify extra applications you'll use from Erlang/Elixir
    [
      extra_applications: []
    ]
  end

  # Dependencies can be Hex packages:
  #
  #   {:my_dep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:my_dep, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
  #
  # Type "mix help deps" for more examples and options
  defp deps() do
    [
      {:earmark, "~> 1.2", only: :docs},
      {:ex_doc, "~> 0.17", only: :docs},
      {:quixir, "~> 0.9", only: :test}
    ]
  end

  defp description() do
    """
    HTTP Signature Scheme - Signing HTTP Messages for Erlang and Elixir
    """
  end

  defp package() do
    [
      name: :http_signature,
      files: [
        "CHANGELOG*",
        "include",
        "lib",
        "LICENSE*",
        "mix.exs",
        "priv",
        "README*",
        "rebar.config",
        "src"
      ],
      licenses: ["Mozilla Public License Version 2.0"],
      links: %{
        "GitHub" => "https://github.com/potatosalad/erlang-http_signature"
      },
      maintainers: ["Andrew Bennett"]
    ]
  end
end
