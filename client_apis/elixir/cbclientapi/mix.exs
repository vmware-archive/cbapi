defmodule Cbclientapi.Mixfile do
  use Mix.Project

  def project do
    [app: :cbclientapi,
     version: "0.0.1",
     elixir: "~> 1.0",
     deps: deps]
  end

  # Configuration for the OTP application
  #
  # Type `mix help compile.app` for more information
  def application do
    [applications: [:logger, :hackney]]
  end

  # Dependencies can be Hex packages:
  #
  #   {:mydep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:mydep, git: "https://github.com/elixir-lang/mydep.git", tag: "0.1.0"}
  #
  # Type `mix help deps` for more examples and options
  defp deps do
    [
      {:hackney, "~> 1.0"},
      {:exjsx, "~> 3.1"},
      {:httparrot, "~> 0.3.4", only: :test},
      {:meck, "~> 0.8.2", only: :test},
      {:earmark, "~> 0.1", only: :docs},
      {:ex_doc, "~> 0.7", only: :docs},
    ]
  end
end
