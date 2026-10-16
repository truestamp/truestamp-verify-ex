# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Instant do
  @moduledoc """
  The pattern classes TIME and NISTTIME of SPEC.md section 2.4 (RFC 3339 in UTC):

  - TIME is `[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z`, and format(parse(s)) = s;
  - NISTTIME is TIME with a 3-digit fraction of a second before `Z`.

  A TIME value is an instant in whole Unix seconds, and a NISTTIME value one in whole Unix
  milliseconds. `parse/2` gives the instant a string names, and `format/2` writes an instant
  in the class's pattern.

  The round trip rejects `24:00:00`, February 30 and a seconds value of 60 (section 2.4).
  `parse/2` makes it by reading each field strictly, in the proleptic Gregorian calendar: the
  month from 1 to 12, the day within its month, the hour from 0 to 23 and the minute and
  second from 0 to 59. A string whose fields are all in range formats back to itself, and a
  lenient parse would move any other to a different instant's string, so the two readings
  refuse exactly the same strings. The tests hold `parse/2` to the round trip itself, with a
  lenient parse of their own.

  SHAPE (section 10.2, step 7, check 5) and DERIVE's `header_time` row (step 9 (d)) use this
  module.
  """

  @typedoc "`:time` is TIME, `:nisttime` is NISTTIME."
  @type class :: :time | :nisttime

  @patterns %{
    time: "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
    nisttime: "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z"
  }

  # Gregorian seconds (from year 0) at 1970-01-01T00:00:00Z.
  @unix_epoch :calendar.datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}})

  @doc "The pattern of `class`, written bare as in SPEC.md section 2.4."
  @spec pattern(class()) :: String.t()
  def pattern(class), do: Map.fetch!(@patterns, class)

  @doc "Whether `text` is a string of `class`: it matches the pattern and round-trips."
  @spec valid?(class(), term()) :: boolean()
  def valid?(class, text), do: match?({:ok, _instant}, parse(class, text))

  @doc """
  The instant `text` names: Unix seconds for `:time`, Unix milliseconds for `:nisttime`.
  `{:error, :pattern}` when `text` does not match the class's pattern in full, and
  `{:error, :round_trip}` when it matches but does not format back to itself.
  """
  @spec parse(class(), term()) :: {:ok, integer()} | {:error, :pattern | :round_trip}
  def parse(class, text) when is_binary(text) do
    if Regex.match?(Regex.compile!("\\A" <> pattern(class) <> "\\z"), text),
      do: parse_fields(class, text),
      else: {:error, :pattern}
  end

  def parse(class, _text) when is_map_key(@patterns, class), do: {:error, :pattern}

  defp parse_fields(:time, <<date_time::binary-19, "Z">>), do: seconds(date_time)

  defp parse_fields(:nisttime, <<date_time::binary-19, ".", milliseconds::binary-3, "Z">>) do
    with {:ok, seconds} <- seconds(date_time),
         do: {:ok, seconds * 1000 + String.to_integer(milliseconds)}
  end

  defp seconds(date_time) do
    <<year::binary-4, "-", month::binary-2, "-", day::binary-2, "T", hour::binary-2, ":",
      minute::binary-2, ":", second::binary-2>> = date_time

    date = {String.to_integer(year), String.to_integer(month), String.to_integer(day)}
    time = {String.to_integer(hour), String.to_integer(minute), String.to_integer(second)}

    if :calendar.valid_date(date) and valid_time?(time),
      do: {:ok, :calendar.datetime_to_gregorian_seconds({date, time}) - @unix_epoch},
      else: {:error, :round_trip}
  end

  defp valid_time?({hour, minute, second}), do: hour <= 23 and minute <= 59 and second <= 59

  @doc """
  `instant` written in the pattern of `class`: Unix seconds for `:time`, Unix milliseconds
  for `:nisttime`. `{:error, :out_of_range}` for an instant outside the years 0000 to 9999,
  which the pattern cannot write.
  """
  @spec format(class(), integer()) :: {:ok, String.t()} | {:error, :out_of_range}
  def format(:time, seconds) when is_integer(seconds) do
    with {:ok, date_time} <- date_time(seconds), do: {:ok, date_time <> "Z"}
  end

  def format(:nisttime, milliseconds) when is_integer(milliseconds) do
    seconds = Integer.floor_div(milliseconds, 1000)
    fraction = milliseconds |> Integer.mod(1000) |> pad(3)
    with {:ok, date_time} <- date_time(seconds), do: {:ok, date_time <> "." <> fraction <> "Z"}
  end

  defp date_time(seconds) do
    gregorian = seconds + @unix_epoch
    {{year, _, _} = date, time} = gregorian_date_time(gregorian)

    if year in 0..9999,
      do: {:ok, write(date, time)},
      else: {:error, :out_of_range}
  end

  # :calendar counts from the start of year 0 and refuses a negative count.
  defp gregorian_date_time(gregorian) when gregorian < 0, do: {{-1, 1, 1}, {0, 0, 0}}
  defp gregorian_date_time(gregorian), do: :calendar.gregorian_seconds_to_datetime(gregorian)

  defp write({year, month, day}, {hour, minute, second}) do
    "#{pad(year, 4)}-#{pad(month, 2)}-#{pad(day, 2)}T#{pad(hour, 2)}:#{pad(minute, 2)}:#{pad(second, 2)}"
  end

  defp pad(value, width), do: value |> Integer.to_string() |> String.pad_leading(width, "0")
end
