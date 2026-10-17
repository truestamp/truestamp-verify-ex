# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.JSON do
  @moduledoc """
  The parsing rules J1 to J6 of SPEC.md section 10.1: steps READ (J1) and PARSE (J2 to J6)
  of section 10.2.

  `read/1` and `read_file/1` make J1. `parse/1` makes J2 to J6 and gives the value, or the
  bare rejection `malformed_json` with its `sub_reason` (sections 10.1 and 12.1).
  `decode/1` makes both, in step order.

  A parsed value is within the value profile of section 10.1, and has one Elixir term per
  JSON value, so two files that differ only in formatting parse to equal terms:

  - an object is a map from its member names to their values, and an array is a list;
  - a string is a UTF-8 binary of Unicode scalar values, with every escape resolved;
  - `true`, `false` and `null` are `true`, `false` and `nil`;
  - a number is its nearest binary64 value (J5). That value is an integer exactly when it is
    integral and its magnitude is at most MAX_INTEGER, so `1`, `1.0` and `1e0` all parse to
    `1`, and `-0` parses to `0`. Every other number is a float: one with a fraction, or an
    integral one of magnitude at least 10^21, which J5 lets through. The nearest value is
    `Truestamp.Verify.JSON.Binary64`'s, exact however long the spelling.

  The limits MAX_READ_OCTETS, MAX_DEPTH and MAX_INTEGER are literals here, not read from
  `spec/constants.json`, because `Truestamp.Verify.Spec.Constants` reads that file with this
  module at compile time. A test holds these literals equal to that file.
  """

  import Bitwise, only: [<<<: 2]

  alias Truestamp.Verify.JSON.Binary64

  # SPEC.md section 9, the table of constants.
  @max_read_octets 262_144
  @max_depth 32
  @max_integer 9_007_199_254_740_991
  # J5: no integral value of magnitude above MAX_INTEGER and below 10^21.
  @integer_ceiling 1.0e21

  @typedoc "A JSON value within the value profile of SPEC.md section 10.1."
  @type value ::
          nil
          | boolean()
          | integer()
          | float()
          | String.t()
          | [value()]
          | %{optional(String.t()) => value()}

  @typedoc "The `sub_reason` of `malformed_json`, naming the rule a file breaks (section 10.1)."
  @type sub_reason ::
          :syntax | :invalid_utf8 | :lone_surrogate | :duplicate_name | :number | :depth

  @doc "MAX_READ_OCTETS, the J1 limit."
  @spec max_read_octets() :: pos_integer()
  def max_read_octets, do: @max_read_octets

  @doc "MAX_DEPTH, the J6 limit."
  @spec max_depth() :: pos_integer()
  def max_depth, do: @max_depth

  @doc "MAX_INTEGER, the largest magnitude of an integer below 10^21 that J5 lets through."
  @spec max_integer() :: pos_integer()
  def max_integer, do: @max_integer

  @doc """
  Step READ, J1: `:ok` when `bytes` is at most MAX_READ_OCTETS octets, else
  `{:error, :input_too_large}`.
  """
  @spec read(binary()) :: :ok | {:error, :input_too_large}
  def read(bytes) when is_binary(bytes) and byte_size(bytes) > @max_read_octets,
    do: {:error, :input_too_large}

  def read(bytes) when is_binary(bytes), do: :ok

  @doc """
  Step READ over a file: reads at most MAX_READ_OCTETS + 1 octets of it, which decides J1
  (section 10.1). A file that cannot be read is `{:error, {:unreadable, reason}}`, which is
  not a verification result (SPEC.md 12.2, exit code 1).
  """
  @spec read_file(Path.t()) ::
          {:ok, binary()} | {:error, :input_too_large} | {:error, {:unreadable, term()}}
  def read_file(path) do
    with {:ok, result} <- File.open(path, [:read, :binary], &IO.binread(&1, @max_read_octets + 1)),
         {:ok, bytes} <- bytes(result),
         :ok <- read(bytes) do
      {:ok, bytes}
    else
      {:error, :input_too_large} -> {:error, :input_too_large}
      {:error, reason} -> {:error, {:unreadable, reason}}
    end
  end

  # IO.binread/2 gives the bytes, :eof for an empty file, or {:error, reason}.
  defp bytes(:eof), do: {:ok, ""}
  defp bytes(result), do: if(is_binary(result), do: {:ok, result}, else: result)

  @doc "Steps READ and PARSE in order: J1, then J2 to J6."
  @spec decode(binary()) ::
          {:ok, value()} | {:error, :input_too_large} | {:error, {:malformed_json, sub_reason()}}
  def decode(bytes) when is_binary(bytes) do
    with :ok <- read(bytes), do: parse(bytes)
  end

  @doc """
  Step PARSE, J2 to J6: `{:ok, value}`, or `{:error, {:malformed_json, sub_reason}}`. For a
  text that breaks more than one rule, the sub_reason is the first this reader meets, which
  section 10.1 leaves open.
  """
  @spec parse(binary()) :: {:ok, value()} | {:error, {:malformed_json, sub_reason()}}
  def parse(bytes) when is_binary(bytes) do
    # J3: the bytes are valid UTF-8. Erlang's check also refuses overlong forms and the
    # encoded surrogates U+D800 to U+DFFF, which are not scalar values.
    if String.valid?(bytes), do: parse_text(bytes), else: malformed(:invalid_utf8)
  end

  defp parse_text(bytes) do
    {value, rest} = parse_value(skip_whitespace(bytes), 1)

    # J2: nothing after the value but whitespace. A byte order mark is not whitespace, so a
    # text that begins with one fails at its first byte.
    if skip_whitespace(rest) == "", do: {:ok, value}, else: fail(:syntax)
  catch
    {__MODULE__, sub_reason} -> malformed(sub_reason)
  end

  defp malformed(sub_reason), do: {:error, {:malformed_json, sub_reason}}

  defp fail(sub_reason), do: throw({__MODULE__, sub_reason})

  # RFC 8259's whitespace: space, tab, line feed and carriage return, and nothing else.
  defp skip_whitespace(<<c, rest::binary>>) when c in [?\s, ?\t, ?\n, ?\r],
    do: skip_whitespace(rest)

  defp skip_whitespace(bytes), do: bytes

  # `depth` is the depth of the value about to be read (J6): the outermost value has depth 1,
  # and only an object or an array can exceed MAX_DEPTH, since no other value adds a level.
  defp parse_value(<<c, _rest::binary>>, depth) when c in [?{, ?[] and depth > @max_depth,
    do: fail(:depth)

  defp parse_value(<<?{, rest::binary>>, depth), do: parse_object(skip_whitespace(rest), depth)
  defp parse_value(<<?[, rest::binary>>, depth), do: parse_array(skip_whitespace(rest), depth)
  defp parse_value(<<?", rest::binary>>, _depth), do: parse_string(rest, "")
  defp parse_value(<<"true", rest::binary>>, _depth), do: {true, rest}
  defp parse_value(<<"false", rest::binary>>, _depth), do: {false, rest}
  defp parse_value(<<"null", rest::binary>>, _depth), do: {nil, rest}

  defp parse_value(<<c, _::binary>> = bytes, _depth) when c == ?- or c in ?0..?9,
    do: parse_number(bytes)

  defp parse_value(_bytes, _depth), do: fail(:syntax)

  # Objects. J4: no two members with the same name, compared as code points after
  # unescaping. Names are UTF-8 binaries with every escape resolved, so binary equality is
  # that comparison, with no normalization.

  defp parse_object(<<?}, rest::binary>>, _depth), do: {%{}, rest}
  defp parse_object(bytes, depth), do: parse_members(bytes, depth, %{})

  defp parse_members(<<?", rest::binary>>, depth, members) do
    {name, rest} = parse_string(rest, "")
    rest = expect(skip_whitespace(rest), ?:)
    {value, rest} = parse_value(skip_whitespace(rest), depth + 1)
    if Map.has_key?(members, name), do: fail(:duplicate_name)
    members = Map.put(members, name, value)

    case skip_whitespace(rest) do
      <<?,, rest::binary>> -> parse_members(skip_whitespace(rest), depth, members)
      <<?}, rest::binary>> -> {members, rest}
      _other -> fail(:syntax)
    end
  end

  defp parse_members(_bytes, _depth, _members), do: fail(:syntax)

  defp expect(<<c, rest::binary>>, c), do: rest
  defp expect(_bytes, _c), do: fail(:syntax)

  # Arrays.

  defp parse_array(<<?], rest::binary>>, _depth), do: {[], rest}
  defp parse_array(bytes, depth), do: parse_elements(bytes, depth, [])

  defp parse_elements(bytes, depth, elements) do
    {value, rest} = parse_value(bytes, depth + 1)
    elements = [value | elements]

    case skip_whitespace(rest) do
      <<?,, rest::binary>> -> parse_elements(skip_whitespace(rest), depth, elements)
      <<?], rest::binary>> -> {Enum.reverse(elements), rest}
      _other -> fail(:syntax)
    end
  end

  # Strings. The text is already known to be valid UTF-8, so every byte at or above 0x80 is
  # part of a well-formed sequence and is copied as it is.

  defp parse_string(<<?", rest::binary>>, acc), do: {acc, rest}
  defp parse_string(<<?\\, rest::binary>>, acc), do: parse_escape(rest, acc)
  defp parse_string(<<c, _rest::binary>>, _acc) when c < 0x20, do: fail(:syntax)
  defp parse_string(<<c, rest::binary>>, acc), do: parse_string(rest, <<acc::binary, c>>)
  defp parse_string(<<>>, _acc), do: fail(:syntax)

  # The two-character escapes of RFC 8259 section 7, by the character after the backslash.
  @short_escapes %{
    ?" => ?",
    ?\\ => ?\\,
    ?/ => ?/,
    ?b => 0x08,
    ?f => 0x0C,
    ?n => ?\n,
    ?r => ?\r,
    ?t => ?\t
  }

  defp parse_escape(<<?u, rest::binary>>, acc), do: parse_unicode_escape(rest, acc)

  defp parse_escape(<<c, rest::binary>>, acc) when is_map_key(@short_escapes, c),
    do: parse_string(rest, <<acc::binary, Map.fetch!(@short_escapes, c)>>)

  defp parse_escape(_bytes, _acc), do: fail(:syntax)

  # J3: an escaped high surrogate is only valid as the first half of an escaped pair, and an
  # escaped low surrogate only as the second.
  defp parse_unicode_escape(bytes, acc) do
    {unit, rest} = hex4(bytes)

    cond do
      unit in 0xD800..0xDBFF -> parse_low_surrogate(unit, rest, acc)
      unit in 0xDC00..0xDFFF -> fail(:lone_surrogate)
      true -> parse_string(rest, <<acc::binary, unit::utf8>>)
    end
  end

  defp parse_low_surrogate(high, <<?\\, ?u, rest::binary>>, acc) do
    {low, rest} = hex4(rest)
    if low not in 0xDC00..0xDFFF, do: fail(:lone_surrogate)
    code_point = 0x10000 + ((high - 0xD800) <<< 10) + (low - 0xDC00)
    parse_string(rest, <<acc::binary, code_point::utf8>>)
  end

  defp parse_low_surrogate(_high, _bytes, _acc), do: fail(:lone_surrogate)

  defguardp is_hex(c) when c in ?0..?9 or c in ?a..?f or c in ?A..?F

  defp hex4(<<a, b, c, d, rest::binary>>)
       when is_hex(a) and is_hex(b) and is_hex(c) and is_hex(d),
       do: {String.to_integer(<<a, b, c, d>>, 16), rest}

  defp hex4(_bytes), do: fail(:syntax)

  # Numbers. The text is matched against RFC 8259's grammar, then read as its nearest
  # binary64 value (J5) by Binary64.nearest/1, which rounds to nearest with ties to even,
  # reads an underflow as zero and refuses an overflow, with integer arithmetic only. It
  # never reaches the C library's strtod, which Float.parse/1 calls and which on macOS 27
  # aborts the runtime on some long spellings.

  defp parse_number(bytes) do
    length = number_length(bytes)
    text = binary_part(bytes, 0, length)
    {number_value(text), binary_part(bytes, length, byte_size(bytes) - length)}
  end

  defp number_length(bytes) do
    sign = if match?(<<?-, _::binary>>, bytes), do: 1, else: 0
    integer = integer_length(binary_part(bytes, sign, byte_size(bytes) - sign))
    at = sign + integer
    fraction = fraction_length(binary_part(bytes, at, byte_size(bytes) - at))
    at = at + fraction
    at + exponent_length(binary_part(bytes, at, byte_size(bytes) - at))
  end

  # `0`, or a digit from 1 to 9 followed by any digits.
  defp integer_length(<<?0, _::binary>>), do: 1
  defp integer_length(<<c, rest::binary>>) when c in ?1..?9, do: 1 + digits_length(rest)
  defp integer_length(_bytes), do: fail(:syntax)

  # Nothing, or `.` followed by at least one digit.
  defp fraction_length(<<?., rest::binary>>), do: 1 + at_least_one_digit(rest)
  defp fraction_length(_bytes), do: 0

  # Nothing, or `e` or `E`, an optional sign and at least one digit.
  defp exponent_length(<<e, sign, rest::binary>>) when e in [?e, ?E] and sign in [?+, ?-],
    do: 2 + at_least_one_digit(rest)

  defp exponent_length(<<e, rest::binary>>) when e in [?e, ?E], do: 1 + at_least_one_digit(rest)
  defp exponent_length(_bytes), do: 0

  defp at_least_one_digit(<<c, rest::binary>>) when c in ?0..?9, do: 1 + digits_length(rest)
  defp at_least_one_digit(_bytes), do: fail(:syntax)

  defp digits_length(bytes), do: digits_length(bytes, 0)
  defp digits_length(<<c, rest::binary>>, n) when c in ?0..?9, do: digits_length(rest, n + 1)
  defp digits_length(_bytes, n), do: n

  defp number_value(text) do
    case Binary64.nearest(text) do
      {:ok, float} -> profile_number(float)
      {:error, :overflow} -> fail(:number)
    end
  end

  defp profile_number(float) do
    integral? = Float.floor(float) == float

    cond do
      integral? and abs(float) <= @max_integer -> trunc(float)
      integral? and abs(float) < @integer_ceiling -> fail(:number)
      true -> float
    end
  end
end
