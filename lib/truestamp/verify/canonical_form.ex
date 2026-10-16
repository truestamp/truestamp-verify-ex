# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.CanonicalForm do
  @moduledoc """
  The canonical form of a data file (SPEC.md section 9), the form of the trace files under
  `vectors/positive/`, in which the command's `--trace FILE` writes a run's trace (section
  10.6): members in JCS order, two-space indentation, LF line ends and a final newline. A
  member is its name, a colon, one space and its value; an object or array that is not
  empty puts each member or element on a line of its own, one level deeper and followed by
  a comma unless it is the last, and closes on a line of its own at the indentation of the
  line that opens it, while an empty one is `{}` or `[]`; and every name and scalar is
  written as `Truestamp.Verify.JCS` writes it.

  It is for a value within the value profile of section 10.1, as JCS is, and raises where
  JCS raises.
  """

  alias Truestamp.Verify.JCS

  @doc "`value` in the canonical form of section 9, with its final newline."
  @spec encode(term()) :: binary()
  def encode(value), do: IO.iodata_to_binary([form(value, 0), "\n"])

  defp form(map, _level) when map == %{}, do: "{}"

  defp form(map, level) when is_map(map) and not is_struct(map) do
    members =
      map
      |> Enum.sort_by(fn {name, _value} -> utf16(name) end)
      |> Enum.map(fn {name, value} ->
        [indent(level + 1), JCS.encode(name), ": ", form(value, level + 1)]
      end)

    ["{\n", Enum.intersperse(members, ",\n"), "\n", indent(level), "}"]
  end

  defp form([], _level), do: "[]"

  defp form(list, level) when is_list(list) do
    elements = Enum.map(list, &[indent(level + 1), form(&1, level + 1)])
    ["[\n", Enum.intersperse(elements, ",\n"), "\n", indent(level), "]"]
  end

  defp form(scalar, _level), do: JCS.encode(scalar)

  # JCS orders members by the UTF-16 code units of their names (RFC 8785 section 3.2.3),
  # which comparing their UTF-16BE bytes gives. A name that is not UTF-8 sorts somewhere and
  # then raises in JCS.encode/1.
  defp utf16(name) when is_binary(name),
    do: :unicode.characters_to_binary(name, :utf8, {:utf16, :big})

  defp indent(level), do: String.duplicate("  ", level)
end
