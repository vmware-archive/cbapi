defmodule Cbprotobuf do
  use Protobuf, from: Path.expand("../../../proto/sensor_events.proto", __DIR__)
end
