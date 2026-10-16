# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Test.SchemaSubset do
  @moduledoc """
  Validates a JSON value against `spec/schema.json` by interpreting only the JSON Schema
  (draft 2020-12) keywords SPEC.md section 9 allows. Any other keyword raises, so the schema
  cannot drift outside the subset unnoticed. Patterns are PCRE searches, whose `$` also
  matches before a final newline, so the schema's length and newline guards are exercised
  as a lenient validator would exercise them.
  """

  @keywords ~w($schema $defs $ref allOf if then else not type const enum properties required
               additionalProperties minProperties pattern minLength maxLength minimum maximum
               items maxItems)

  @doc "The keywords the schema may use."
  @spec keywords() :: [String.t()]
  def keywords, do: @keywords

  @doc "Whether `value` satisfies `schema`, with `root` the whole schema document."
  @spec valid?(map(), term()) :: boolean()
  def valid?(root, value), do: valid?(root, root, value)

  defp valid?(_root, true, _value), do: true
  defp valid?(_root, false, _value), do: false

  defp valid?(root, schema, value) when is_map(schema) do
    for key <- Map.keys(schema), key not in @keywords do
      raise ArgumentError, "keyword outside the subset: #{key}"
    end

    Enum.all?(schema, fn {key, arg} -> keyword?(key, arg, schema, root, value) end)
  end

  defp keyword?(key, _arg, _schema, _root, _value) when key in ~w($schema $defs then else),
    do: true

  defp keyword?("$ref", "#/$defs/" <> name, _schema, root, value),
    do: valid?(root, Map.fetch!(root["$defs"], name), value)

  defp keyword?("$ref", other, _schema, _root, _value),
    do: raise(ArgumentError, "$ref outside #/$defs: #{inspect(other)}")

  defp keyword?("allOf", subs, _schema, root, value),
    do: Enum.all?(subs, &valid?(root, &1, value))

  defp keyword?("if", sub, schema, root, value) do
    branch =
      if valid?(root, sub, value), do: Map.get(schema, "then"), else: Map.get(schema, "else")

    branch == nil or valid?(root, branch, value)
  end

  defp keyword?("not", sub, _schema, root, value), do: not valid?(root, sub, value)

  defp keyword?("type", types, _schema, _root, value),
    do: types |> List.wrap() |> Enum.any?(&type?(&1, value))

  defp keyword?("const", constant, _schema, _root, value), do: equal?(constant, value)
  defp keyword?("enum", values, _schema, _root, value), do: Enum.any?(values, &equal?(&1, value))

  defp keyword?("properties", props, _schema, root, value) when is_map(value) do
    Enum.all?(props, fn {name, sub} ->
      not Map.has_key?(value, name) or valid?(root, sub, value[name])
    end)
  end

  defp keyword?("required", names, _schema, _root, value) when is_map(value),
    do: Enum.all?(names, &Map.has_key?(value, &1))

  defp keyword?("additionalProperties", false, schema, _root, value) when is_map(value) do
    allowed = schema |> Map.get("properties", %{}) |> Map.keys()
    value |> Map.keys() |> Enum.all?(&(&1 in allowed))
  end

  defp keyword?("additionalProperties", other, _schema, _root, _value) when other != false,
    do: raise(ArgumentError, "additionalProperties may only be false")

  defp keyword?("minProperties", n, _schema, _root, value) when is_map(value),
    do: map_size(value) >= n

  defp keyword?("pattern", pattern, _schema, _root, value) when is_binary(value),
    do: Regex.match?(regex(pattern), value)

  defp keyword?("minLength", n, _schema, _root, value) when is_binary(value),
    do: code_points(value) >= n

  defp keyword?("maxLength", n, _schema, _root, value) when is_binary(value),
    do: code_points(value) <= n

  defp keyword?("minimum", n, _schema, _root, value) when is_number(value), do: value >= n
  defp keyword?("maximum", n, _schema, _root, value) when is_number(value), do: value <= n

  defp keyword?("items", sub, _schema, root, value) when is_list(value),
    do: Enum.all?(value, &valid?(root, sub, &1))

  defp keyword?("maxItems", n, _schema, _root, value) when is_list(value), do: length(value) <= n

  # A keyword whose instance type does not apply passes, as JSON Schema says.
  defp keyword?(key, _arg, _schema, _root, _value) when key in @keywords, do: true

  defp type?("object", value), do: is_map(value)
  defp type?("array", value), do: is_list(value)
  defp type?("string", value), do: is_binary(value)

  defp type?("integer", value),
    do: is_integer(value) or (is_float(value) and value == Float.round(value))

  defp type?("number", value), do: is_number(value)
  defp type?("boolean", value), do: is_boolean(value)
  defp type?("null", value), do: value == nil

  defp equal?(a, b) when is_number(a) and is_number(b), do: a == b

  defp equal?(a, b) when is_map(a) and is_map(b),
    do: Map.keys(a) == Map.keys(b) and Enum.all?(a, fn {k, v} -> equal?(v, b[k]) end)

  defp equal?(a, b) when is_list(a) and is_list(b),
    do: length(a) == length(b) and a |> Enum.zip(b) |> Enum.all?(fn {x, y} -> equal?(x, y) end)

  defp equal?(a, b), do: a === b

  defp code_points(string), do: string |> String.to_charlist() |> length()

  # Compiled once per process: the generated negative cases validate thousands of documents.
  defp regex(pattern) do
    case Process.get({__MODULE__, pattern}) do
      nil -> tap(Regex.compile!(pattern), &Process.put({__MODULE__, pattern}, &1))
      regex -> regex
    end
  end
end
