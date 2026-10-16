# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.JSON.Pointer do
  @moduledoc """
  JSON Pointers (RFC 6901) into P, the parsed value of `proof`, and the document order that
  orders a step's rows (SPEC.md section 10.2).

  A pointer is held as its list of segments: a string for an object member's name and a
  non-negative integer for an array element's index, so `["block", "record", "merkle_root"]`
  is `/block/record/merkle_root` and `["subject", "inclusion_proof", "path", 3]` is
  `/subject/inclusion_proof/path/3`. `encode/1` writes a row's part from it.

  **Document order** (section 10.2) is the order in which a depth-first walk of P visits
  values, each value before its contents, an object's members in JCS order and an array's
  elements by index. Of two pointers, the one that is a prefix of the other comes first, and
  otherwise the first segment in which they differ decides: two names by JCS order, the order
  of their UTF-16 code units (RFC 8785 section 3.2.3), and two indices by value. A pointer can
  name a member that P lacks, and it takes the place that member would take.
  """

  @typedoc "A pointer as its segments: names and array indices, outermost first."
  @type t :: [String.t() | non_neg_integer()]

  @doc """
  The RFC 6901 string of `segments`: each segment after a `/`, with `~` written `~0` and
  `/` written `~1` in a name.
  """
  @spec encode(t()) :: String.t()
  def encode(segments) when is_list(segments), do: Enum.map_join(segments, &["/", segment(&1)])

  defp segment(index) when is_integer(index) and index >= 0, do: Integer.to_string(index)

  defp segment(name) when is_binary(name),
    do: name |> String.replace("~", "~0") |> String.replace("/", "~1")

  @doc "Whether pointer `a` comes before pointer `b`, or is `b`, in document order."
  @spec before_or_same?(t(), t()) :: boolean()
  def before_or_same?(a, b), do: compare(a, b) != :gt

  @doc "The document order of two pointers: `:lt` when `a` comes first, `:eq`, or `:gt`."
  @spec compare(t(), t()) :: :lt | :eq | :gt
  def compare([], []), do: :eq
  def compare([], [_ | _]), do: :lt
  def compare([_ | _], []), do: :gt
  def compare([same | a], [same | b]), do: compare(a, b)
  def compare([x | _], [y | _]), do: compare_segments(x, y)

  # The two segments of one position name members of one object, or elements of one array;
  # a name and an index never meet there, and are ordered index first only to be total.
  defp compare_segments(x, y) when is_integer(x) and is_integer(y), do: order(x, y)
  defp compare_segments(x, y) when is_binary(x) and is_binary(y), do: order(key(x), key(y))
  defp compare_segments(x, _y) when is_integer(x), do: :lt
  defp compare_segments(_x, _y), do: :gt

  defp order(x, y) when x < y, do: :lt
  defp order(x, y) when x > y, do: :gt
  defp order(_x, _y), do: :eq

  # RFC 8785 section 3.2.3: in UTF-16BE, comparing the bytes compares the code units, and a
  # name that is a prefix of another sorts first.
  defp key(name), do: :unicode.characters_to_binary(name, :utf8, {:utf16, :big})

  @doc """
  `list` sorted into the document order of the pointer `part` gives for each element; the
  sort is stable, so elements at one pointer keep their order.
  """
  @spec sort_by([element], (element -> t())) :: [element] when element: term()
  def sort_by(list, part \\ & &1),
    do: Enum.sort(list, &before_or_same?(part.(&1), part.(&2)))

  @doc """
  The element of `list` whose pointer, as `part` gives it, comes first in document order,
  the earliest in `list` among equals; nil when `list` is empty.
  """
  @spec first_by([element], (element -> t())) :: element | nil when element: term()
  def first_by(list, part \\ & &1)
  def first_by([], _part), do: nil
  def first_by(list, part), do: list |> sort_by(part) |> hd()
end
