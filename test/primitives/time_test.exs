# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.InstantTest do
  # TIME and NISTTIME (SPEC.md 2.4): the pattern, each field's range at its limit and one
  # past it, the round trip against a lenient parse the test makes on its own, formatting,
  # and the times the sound proofs carry.
  use ExUnit.Case, async: true

  alias Truestamp.Verify.Test.StrictJSON
  alias Truestamp.Verify.Instant

  @root Truestamp.Verify.Test.Verification.root()

  describe "the pattern" do
    test "takes the one layout of each class" do
      assert Instant.parse(:time, "1970-01-01T00:00:00Z") == {:ok, 0}
      assert Instant.parse(:nisttime, "1970-01-01T00:00:00.000Z") == {:ok, 0}
      assert Instant.parse(:time, "2026-09-28T12:34:56Z") == {:ok, 1_790_598_896}
      assert Instant.parse(:nisttime, "2026-09-28T12:34:56.789Z") == {:ok, 1_790_598_896_789}
    end

    test "refuses every other layout" do
      for text <- [
            "2026-09-28T12:34:56",
            "2026-09-28t12:34:56Z",
            "2026-09-28T12:34:56z",
            "2026-09-28 12:34:56Z",
            "2026-09-28T12:34:56+00:00",
            "2026-09-28T12:34:56.789Z",
            "2026-09-28T12:34:56.Z",
            "2026-09-28T12:34Z",
            "26-09-28T12:34:56Z",
            "02026-09-28T12:34:56Z",
            "2026-9-28T12:34:56Z",
            "2026-09-28T1:34:56Z",
            "2026-09-28T12:34:56Z\n",
            "\n2026-09-28T12:34:56Z",
            " 2026-09-28T12:34:56Z",
            "2026-09-28T12:34:56ZZ",
            "+2026-09-28T12:34:56Z",
            "2026-09-28T12:34:5aZ",
            "2026\u{FF10}09-28T12:34:56Z",
            "\u{FF12}026-09-28T12:34:56Z",
            ""
          ] do
        assert Instant.parse(:time, text) == {:error, :pattern}, inspect(text)
      end
    end

    test "refuses a NISTTIME without exactly three digits of fraction" do
      for text <- [
            "2026-09-28T12:34:56Z",
            "2026-09-28T12:34:56.78Z",
            "2026-09-28T12:34:56.7890Z",
            "2026-09-28T12:34:56,789Z",
            "2026-09-28T12:34:56.789Z\n"
          ] do
        assert Instant.parse(:nisttime, text) == {:error, :pattern}, inspect(text)
      end
    end

    test "refuses what is not a string" do
      for term <- [nil, 0, ~c"1970-01-01T00:00:00Z", :time] do
        assert Instant.parse(:time, term) == {:error, :pattern}
        refute Instant.valid?(:time, term)
      end
    end
  end

  describe "the round trip, field by field" do
    test "the hour runs from 00 to 23" do
      assert Instant.valid?(:time, "2026-09-28T23:59:59Z")
      assert Instant.parse(:time, "2026-09-28T24:00:00Z") == {:error, :round_trip}
    end

    test "the minute and the second run from 00 to 59, with no leap second" do
      assert Instant.valid?(:time, "2026-09-28T12:59:59Z")
      assert Instant.parse(:time, "2026-09-28T12:60:00Z") == {:error, :round_trip}
      assert Instant.parse(:time, "2016-12-31T23:59:60Z") == {:error, :round_trip}
      assert Instant.parse(:nisttime, "2016-12-31T23:59:60.000Z") == {:error, :round_trip}
    end

    test "the month runs from 01 to 12" do
      assert Instant.valid?(:time, "2026-01-01T00:00:00Z")
      assert Instant.valid?(:time, "2026-12-31T00:00:00Z")
      assert Instant.parse(:time, "2026-00-01T00:00:00Z") == {:error, :round_trip}
      assert Instant.parse(:time, "2026-13-01T00:00:00Z") == {:error, :round_trip}
    end

    test "the day runs from 01 to the last day of its month" do
      assert Instant.parse(:time, "2026-01-00T00:00:00Z") == {:error, :round_trip}

      for {month, last} <-
            [{1, 31}, {2, 28}, {3, 31}, {4, 30}, {5, 31}, {6, 30}] ++
              [{7, 31}, {8, 31}, {9, 30}, {10, 31}, {11, 30}, {12, 31}] do
        month = month |> Integer.to_string() |> String.pad_leading(2, "0")
        assert Instant.valid?(:time, "2026-#{month}-#{last}T00:00:00Z"), month

        assert Instant.parse(:time, "2026-#{month}-#{last + 1}T00:00:00Z") ==
                 {:error, :round_trip}
      end
    end

    test "February has 29 days in a Gregorian leap year" do
      assert Instant.valid?(:time, "2024-02-29T00:00:00Z")
      assert Instant.valid?(:time, "2000-02-29T00:00:00Z")
      refute Instant.valid?(:time, "2026-02-29T00:00:00Z")
      refute Instant.valid?(:time, "1900-02-29T00:00:00Z")
      refute Instant.valid?(:time, "2100-02-29T00:00:00Z")
      refute Instant.valid?(:time, "2024-02-30T00:00:00Z")
    end

    test "the year runs from 0000 to 9999" do
      assert Instant.parse(:time, "0000-01-01T00:00:00Z") == {:ok, -62_167_219_200}
      assert Instant.parse(:time, "9999-12-31T23:59:59Z") == {:ok, 253_402_300_799}
      assert Instant.valid?(:time, "0000-02-29T00:00:00Z")
    end

    test "a NISTTIME fraction runs from .000 to .999" do
      assert Instant.parse(:nisttime, "1970-01-01T00:00:00.999Z") == {:ok, 999}
      assert Instant.parse(:nisttime, "1969-12-31T23:59:59.001Z") == {:ok, -999}
    end

    test "refuses exactly the strings a lenient parse moves, over random fields" do
      :rand.seed(:exsss, {7, 8, 9})

      for _ <- 1..5000 do
        fields = [
          :rand.uniform(10_000) - 1,
          :rand.uniform(15) - 1,
          :rand.uniform(33) - 1,
          :rand.uniform(26) - 1,
          :rand.uniform(62) - 1,
          :rand.uniform(62) - 1
        ]

        text = write(fields) <> "Z"
        expected = if lenient_round_trip?(fields), do: :ok, else: :round_trip

        assert (case Instant.parse(:time, text) do
                  {:ok, _seconds} -> :ok
                  {:error, reason} -> reason
                end) == expected,
               text
      end
    end
  end

  describe "formatting" do
    test "writes an instant in each class's pattern" do
      assert Instant.format(:time, 0) == {:ok, "1970-01-01T00:00:00Z"}
      assert Instant.format(:time, 1_790_598_896) == {:ok, "2026-09-28T12:34:56Z"}
      assert Instant.format(:time, -1) == {:ok, "1969-12-31T23:59:59Z"}
      assert Instant.format(:nisttime, 1_790_598_896_007) == {:ok, "2026-09-28T12:34:56.007Z"}
      assert Instant.format(:nisttime, -1) == {:ok, "1969-12-31T23:59:59.999Z"}
    end

    test "writes the largest Bitcoin nTime, 2^32 - 1 seconds" do
      assert Instant.format(:time, 4_294_967_295) == {:ok, "2106-02-07T06:28:15Z"}
    end

    test "writes from year 0000 to year 9999, and refuses an instant outside them" do
      assert Instant.format(:time, -62_167_219_200) == {:ok, "0000-01-01T00:00:00Z"}
      assert Instant.format(:time, -62_167_219_201) == {:error, :out_of_range}
      assert Instant.format(:time, 253_402_300_799) == {:ok, "9999-12-31T23:59:59Z"}
      assert Instant.format(:time, 253_402_300_800) == {:error, :out_of_range}
      assert Instant.format(:nisttime, 253_402_300_800_000) == {:error, :out_of_range}
    end

    test "agrees with Elixir's own calendar on random instants, and parses back" do
      for _ <- 1..2000 do
        seconds = :rand.uniform(253_402_300_799 + 62_167_219_200) - 62_167_219_201
        {:ok, text} = Instant.format(:time, seconds)
        assert Instant.parse(:time, text) == {:ok, seconds}
        {:ok, date_time} = DateTime.from_unix(seconds)
        assert text == DateTime.to_iso8601(date_time)

        milliseconds = seconds * 1000 + :rand.uniform(1000) - 1
        {:ok, nist} = Instant.format(:nisttime, milliseconds)
        assert Instant.parse(:nisttime, nist) == {:ok, milliseconds}
      end
    end
  end

  describe "agreement with spec/encodings.json and the sound proofs" do
    test "each class's pattern equals the file's, which also asks for the round trip" do
      {:ok, encodings} =
        @root |> Path.join("spec/encodings.json") |> File.read!() |> StrictJSON.decode()

      assert Instant.pattern(:time) == encodings["TIME"]["pattern"]
      assert Instant.pattern(:nisttime) == encodings["NISTTIME"]["pattern"]
      assert encodings["TIME"]["round_trip"] == true
      assert encodings["NISTTIME"]["round_trip"] == true
    end

    test "every TIME and NISTTIME value in the sound proofs parses and formats back" do
      values =
        for path <- Path.wildcard(Path.join(@root, "vectors/positive/*.proof.json")),
            {:ok, document} = StrictJSON.decode(File.read!(path)),
            {name, value} <- members(document),
            name in ["header_time", "closed_at", "timeStamp"],
            do: {name, value}

      assert Enum.any?(values, &(elem(&1, 0) == "header_time"))
      assert Enum.any?(values, &(elem(&1, 0) == "timeStamp"))

      for {name, value} <- values do
        class = if name == "timeStamp", do: :nisttime, else: :time
        assert {:ok, instant} = Instant.parse(class, value), value
        assert Instant.format(class, instant) == {:ok, value}
      end
    end
  end

  defp members(map) when is_map(map),
    do: Enum.flat_map(map, fn {name, value} -> [{name, value} | members(value)] end)

  defp members(list) when is_list(list), do: Enum.flat_map(list, &members/1)
  defp members(_scalar), do: []

  defp write([year, month, day, hour, minute, second]) do
    [p4, p2] = [&pad(&1, 4), &pad(&1, 2)]
    "#{p4.(year)}-#{p2.(month)}-#{p2.(day)}T#{p2.(hour)}:#{p2.(minute)}:#{p2.(second)}"
  end

  defp pad(value, width), do: value |> Integer.to_string() |> String.pad_leading(width, "0")

  # An independent lenient reading: fields out of range carry into the next, by the civil
  # day count of Howard Hinnant's algorithms, and the instant is written back.
  defp lenient_round_trip?([year, month, day, hour, minute, second] = fields) do
    year = year + Integer.floor_div(month - 1, 12)
    month = Integer.mod(month - 1, 12) + 1
    days = days_from_civil(year, month, 1) + day - 1
    seconds = days * 86_400 + hour * 3600 + minute * 60 + second
    day_count = Integer.floor_div(seconds, 86_400)
    rest = Integer.mod(seconds, 86_400)
    {y, m, d} = civil_from_days(day_count)
    y in 0..9999 and [y, m, d, div(rest, 3600), div(rem(rest, 3600), 60), rem(rest, 60)] == fields
  end

  defp days_from_civil(y, m, d) do
    y = if m <= 2, do: y - 1, else: y
    era = Integer.floor_div(y, 400)
    yoe = y - era * 400
    doy = div(153 * Integer.mod(m + 9, 12) + 2, 5) + d - 1
    doe = yoe * 365 + div(yoe, 4) - div(yoe, 100) + doy
    era * 146_097 + doe - 719_468
  end

  defp civil_from_days(z) do
    z = z + 719_468
    era = Integer.floor_div(z, 146_097)
    doe = z - era * 146_097
    yoe = div(doe - div(doe, 1460) + div(doe, 36_524) - div(doe, 146_096), 365)
    doy = doe - (365 * yoe + div(yoe, 4) - div(yoe, 100))
    mp = div(5 * doy + 2, 153)
    d = doy - div(153 * mp + 2, 5) + 1
    m = if mp < 10, do: mp + 3, else: mp - 9
    y = yoe + era * 400
    {if(m <= 2, do: y + 1, else: y), m, d}
  end
end
