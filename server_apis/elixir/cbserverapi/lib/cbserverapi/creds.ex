defmodule Cbserverapi.Creds do
  @cfconf     "/etc/cb/cb.conf"

  def getcreds do
    File.stream!(@cfconf, [:read], :line)
    |> Enum.reduce([], &fromcbconf/2)
  end

  defp fromcbconf("RabbitMQUser=" <> username, acc) do
    [{:username, String.rstrip(username)}|acc]
  end
  defp fromcbconf("RabbitMQPassword=" <> password, acc) do
    [{:password, String.rstrip(password)}|acc]
  end
  defp fromcbconf("RabbitMQPort=" <> portnum, acc) do
    [{:port, String.rstrip(portnum) |> String.to_integer}|acc]
  end
  defp fromcbconf(_, acc) do
    acc
  end
end

