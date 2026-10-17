# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Schema do
  @moduledoc """
  The verifier's own checker for `spec/schema.json` (SPEC.md section 9), the check 3 of SHAPE
  (section 10.2, step 7). The schema is compiled in from the file, and this module interprets
  it directly, keyword by keyword, as JSON Schema draft 2020-12 defines each keyword of the
  subset section 9 allows:

  `$schema`, `$defs`, `$ref` (to `#/$defs` only), `allOf`, `if`, `then`, `else`, `not`,
  `type`, `const`, `enum`, `properties`, `required`, `additionalProperties` (only `false`),
  `minProperties`, `pattern`, `minLength`, `maxLength`, `minimum`, `maximum`, `items` and
  `maxItems`, and the boolean schemas `true` and `false`.

  The build stops when the file uses any other keyword, a `$ref` to anything but a member of
  `#/$defs`, an `additionalProperties` other than `false`, or a pattern that does not compile.

  **What it gives.** Not only whether a value satisfies the schema, but every failure, each
  at a pointer, because SHAPE reports the failure whose part comes first in document order
  (section 10.2, step 7). Each failure is `%{part, keyword, schema}`: `part` is a
  `Truestamp.Verify.JSON.Pointer`, `keyword` the keyword that fails (`"false"` for the boolean
  schema), and `schema` where that keyword sits, as a pointer into the schema written from
  the `$def` the checker last entered, such as `"#/$defs/HEX64/pattern"`. A failure's part is
  the one SPEC.md's rule gives:

  - a member `required` names and the value lacks: the pointer of that member;
  - a member `additionalProperties: false` does not allow: the pointer of that member;
  - a member whose schema is `false`, forbidden for the type: the pointer of that member;
  - `minProperties` or `maxItems`, a count: the pointer of the object or array;
  - every other keyword: the pointer of the value that breaks it.

  **The keywords' meaning**, from JSON Schema: a keyword about objects, strings, numbers or
  arrays says nothing about a value of another type; `if` fails nothing itself and applies
  `then` when its schema holds, else `else`; `not` fails when its schema holds; `properties`
  applies each member's schema to the member when present; `additionalProperties` sees only
  the `properties` of its own schema object; `const` and `enum` compare JSON values, numbers
  by value; `integer` is a number with no fractional part; lengths count code points; and a
  pattern is an ECMA-262 regular expression searched for anywhere in the string, whose `$`
  matches only at the end of the input (section 9: each pattern of the schema is also paired
  with an exact length or the newline guard, so a `$` that matches before a final newline
  would give the same answer).
  """

  alias Truestamp.Verify.JSON.Pointer
  alias Truestamp.Verify.Spec.Data

  @external_resource Data.path("schema.json")
  @schema Data.read!("schema.json")
  @defs Map.fetch!(@schema, "$defs")

  # The document's `proof` member has the schema at #/properties/proof.
  @proof_schema @schema |> Map.fetch!("properties") |> Map.fetch!("proof")

  @keywords ~w($schema $defs $ref allOf if then else not type const enum properties required
               additionalProperties minProperties pattern minLength maxLength minimum maximum
               items maxItems)

  # The types and the kinds of constant `spec/schema.json` uses. JSON Schema allows more, and
  # the build refuses a schema that uses one this checker does not interpret, so a change to
  # the schema that needs more fails loudly here rather than checking it wrong.
  @types ~w(object array string integer)

  # ECMA-262's `$`, without the multiline flag, matches only at the end of the input.
  @regex_options [:unicode, :dollar_endonly]

  # The build refuses a schema outside the subset. Every schema object is visited once.
  children = fn
    node when is_map(node) ->
      Enum.flat_map(node, fn
        {key, map} when key in ["$defs", "properties"] -> Map.values(map)
        {"allOf", list} -> list
        {key, sub} when key in ~w(if then else not items) -> [sub]
        _keyword -> []
      end)

    _boolean ->
      []
  end

  nodes =
    Stream.unfold([@schema], fn
      [] -> nil
      [node | rest] -> {node, children.(node) ++ rest}
    end)

  keywords = @keywords
  defs = @defs
  types = @types
  regex_options = @regex_options

  scalar? = fn value -> is_binary(value) or is_integer(value) end

  # The reason a schema object's keyword is outside the subset, or nil.
  refusal = fn
    {"$ref", "#/$defs/" <> name} ->
      unless Map.has_key?(defs, name), do: "$ref names no member of #/$defs: #{name}"

    {"$ref", ref} ->
      "$ref outside #/$defs: #{inspect(ref)}"

    {"additionalProperties", arg} ->
      unless arg === false, do: "additionalProperties other than false"

    {"pattern", pattern} ->
      unless match?({:ok, _regex}, Regex.compile(pattern, regex_options)),
        do: "a pattern that does not compile: #{inspect(pattern)}"

    {"type", arg} ->
      unless Enum.all?(List.wrap(arg), &(&1 in types)),
        do: "a type this checker does not interpret: #{inspect(arg)}"

    {"const", arg} ->
      unless scalar?.(arg), do: "a const that is not a string or an integer: #{inspect(arg)}"

    {"enum", args} ->
      unless is_list(args) and Enum.all?(args, scalar?),
        do: "an enum of values that are not strings or integers: #{inspect(args)}"

    {key, _arg} ->
      unless key in keywords, do: "#{key}, a keyword outside the subset"
  end

  for node <- nodes, not is_boolean(node) do
    unless is_map(node), do: raise("spec/schema.json: a schema that is not an object or boolean")

    for keyword <- node, reason = refusal.(keyword), reason != nil do
      raise "spec/schema.json uses #{reason} (SPEC.md section 9)"
    end
  end

  @typedoc "A failure: where it is, the keyword that fails and where that keyword sits."
  @type failure :: %{part: Pointer.t(), keyword: String.t(), schema: String.t()}

  @doc "The schema, as compiled from `spec/schema.json`."
  @spec schema() :: map()
  def schema, do: @schema

  @doc "The keywords the schema may use (SPEC.md section 9)."
  @spec keywords() :: [String.t()]
  def keywords, do: @keywords

  @doc """
  Every failure of the document (the envelope) against the schema, each part a pointer into
  the document, in document order.
  """
  @spec failures(term()) :: [failure()]
  def failures(document), do: @schema |> check(document, [], ["#"]) |> Pointer.sort_by(& &1.part)

  @doc """
  Every failure of P, the value of `proof`, against the schema the document gives `proof`,
  each part a pointer into P, in document order. For a document whose `signature` satisfies
  its schema, these are the document's failures, without the leading `/proof`.
  """
  @spec proof_failures(term()) :: [failure()]
  def proof_failures(proof),
    do:
      @proof_schema
      |> check(proof, [], ["proof", "properties", "#"])
      |> Pointer.sort_by(& &1.part)

  @doc "Whether the document satisfies the schema."
  @spec valid?(term()) :: boolean()
  def valid?(document), do: check(@schema, document, [], ["#"]) == []

  # A schema against a value. `at` is the value's pointer and `loc` the schema's location,
  # each with its innermost segment first.
  defp check(true, _value, _at, _loc), do: []
  defp check(false, _value, at, loc), do: [failure(at, loc, "false")]

  defp check(schema, value, at, loc) when is_map(schema) do
    Enum.flat_map(schema, fn {key, arg} ->
      keyword(key, arg, schema, value, at, [key | loc])
    end)
  end

  defp keyword(key, _arg, _schema, _value, _at, _loc) when key in ~w($schema $defs then else),
    do: []

  defp keyword("$ref", "#/$defs/" <> name, _schema, value, at, _loc),
    do: check(Map.fetch!(@defs, name), value, at, [name, "$defs", "#"])

  defp keyword("allOf", subs, _schema, value, at, loc) do
    subs
    |> Enum.with_index()
    |> Enum.flat_map(fn {sub, index} -> check(sub, value, at, [index | loc]) end)
  end

  defp keyword("if", sub, schema, value, at, [_if | loc]) do
    branch = if check(sub, value, at, loc) == [], do: "then", else: "else"

    case Map.fetch(schema, branch) do
      {:ok, branch_schema} -> check(branch_schema, value, at, [branch | loc])
      :error -> []
    end
  end

  defp keyword("not", sub, _schema, value, at, loc),
    do: holds(check(sub, value, at, loc) != [], at, loc)

  defp keyword("type", types, _schema, value, at, loc),
    do: holds(Enum.any?(List.wrap(types), &type?(&1, value)), at, loc)

  defp keyword("const", constant, _schema, value, at, loc),
    do: holds(equal?(constant, value), at, loc)

  defp keyword("enum", values, _schema, value, at, loc),
    do: holds(Enum.any?(values, &equal?(&1, value)), at, loc)

  defp keyword("properties", properties, _schema, value, at, loc) when is_map(value) do
    for {name, sub} <- properties,
        is_map_key(value, name),
        failure <- check(sub, Map.fetch!(value, name), [name | at], [name | loc]),
        do: failure
  end

  defp keyword("required", names, _schema, value, at, loc) when is_map(value),
    do: for(name <- names, not is_map_key(value, name), do: failure([name | at], loc, hd(loc)))

  defp keyword("additionalProperties", false, schema, value, at, loc) when is_map(value) do
    allowed = Map.get(schema, "properties", %{})

    for name <- Map.keys(value),
        not is_map_key(allowed, name),
        do: failure([name | at], loc, hd(loc))
  end

  defp keyword("minProperties", n, _schema, value, at, loc) when is_map(value),
    do: holds(map_size(value) >= n, at, loc)

  defp keyword("pattern", pattern, _schema, value, at, loc) when is_binary(value),
    do: holds(Regex.match?(regex(pattern), value), at, loc)

  defp keyword("minLength", n, _schema, value, at, loc) when is_binary(value),
    do: holds(code_points(value) >= n, at, loc)

  defp keyword("maxLength", n, _schema, value, at, loc) when is_binary(value),
    do: holds(code_points(value) <= n, at, loc)

  defp keyword("minimum", n, _schema, value, at, loc) when is_number(value),
    do: holds(value >= n, at, loc)

  defp keyword("maximum", n, _schema, value, at, loc) when is_number(value),
    do: holds(value <= n, at, loc)

  defp keyword("items", sub, _schema, value, at, loc) when is_list(value) do
    value
    |> Enum.with_index()
    |> Enum.flat_map(fn {element, index} -> check(sub, element, [index | at], loc) end)
  end

  defp keyword("maxItems", n, _schema, value, at, loc) when is_list(value),
    do: holds(length(value) <= n, at, loc)

  # A keyword about another type of value says nothing about this one (JSON Schema).
  defp keyword(key, _arg, _schema, _value, _at, _loc) when key in @keywords, do: []

  defp holds(true, _at, _loc), do: []
  defp holds(false, at, [keyword | _] = loc), do: [failure(at, loc, keyword)]

  defp failure(at, loc, keyword) do
    schema = loc |> Enum.reverse() |> Enum.join("/")
    %{part: Enum.reverse(at), keyword: to_string(keyword), schema: schema}
  end

  defp type?("object", value), do: is_map(value)
  defp type?("array", value), do: is_list(value)
  defp type?("string", value), do: is_binary(value)
  defp type?("integer", value), do: is_integer(value) or integral_float?(value)

  defp integral_float?(value), do: is_float(value) and Float.floor(value) == value

  # JSON equality, for the constants the build allows, strings and integers: a number by
  # value, so the integer 1 equals the float 1.0, and a string exactly.
  defp equal?(a, b) when is_integer(a) and is_number(b), do: a == b
  defp equal?(a, b), do: a === b

  defp code_points(string), do: string |> String.codepoints() |> length()

  # Each of the schema's few patterns is compiled once per node, on first use.
  defp regex(pattern) do
    key = {__MODULE__, :regex, pattern}

    case :persistent_term.get(key, nil) do
      nil -> tap(Regex.compile!(pattern, @regex_options), &:persistent_term.put(key, &1))
      regex -> regex
    end
  end
end
