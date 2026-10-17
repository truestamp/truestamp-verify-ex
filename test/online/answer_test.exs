# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Online.AnswerTest do
  @moduledoc "The classes of an answer's fields (SPEC.md section 13.2's table)."

  use ExUnit.Case, async: true

  alias Truestamp.Verify.Online.Answer

  @max 9_007_199_254_740_991

  test "INT is an integer from 0 to MAX_INTEGER" do
    assert Answer.field(%{"n" => 0}, "n", :int) == {:ok, 0}
    assert Answer.field(%{"n" => @max}, "n", :int) == {:ok, @max}
    assert Answer.field(%{"n" => @max + 1}, "n", :int) == :error
    assert Answer.field(%{"n" => -1}, "n", :int) == :error
    assert Answer.field(%{"n" => 1.0}, "n", :int) == :error

    # Unix seconds a TIME can write: the years 0000 to 9999 (section 2.4).
    assert Answer.field(%{"t" => 253_402_300_799}, "t", :unix_time) == {:ok, 253_402_300_799}
    assert Answer.field(%{"t" => 253_402_300_800}, "t", :unix_time) == :error
    assert Answer.field(%{"t" => -1}, "t", :unix_time) == :error
  end

  test "the string classes match their patterns in full" do
    hex = String.duplicate("ab", 32)
    assert Answer.field(%{"h" => hex}, "h", :hex64) == {:ok, hex}
    assert Answer.field(%{"h" => String.upcase(hex)}, "h", :hex64) == :error
    assert Answer.field(%{"h" => hex <> "\n"}, "h", :hex64) == :error
    assert Answer.field(%{"h" => 7}, "h", :hex64) == :error

    assert Answer.field(%{"h" => String.duplicate("AB", 64)}, "h", :nisthex) ==
             {:ok, String.duplicate("AB", 64)}

    assert Answer.field(%{"p" => "Test SDF Network ; September 2015"}, "p", :ascii128) ==
             {:ok, "Test SDF Network ; September 2015"}

    assert Answer.field(%{"p" => "a\"b"}, "p", :ascii128) == :error
    assert Answer.field(%{"p" => ""}, "p", :ascii128) == :error
  end

  test "TIME and NISTTIME give their instant in milliseconds, and refuse what does not round-trip" do
    assert Answer.field(%{"t" => "1970-01-01T00:00:01Z"}, "t", :time) == {:ok, 1000}
    assert Answer.field(%{"t" => "1970-01-01T00:00:01.002Z"}, "t", :nisttime) == {:ok, 1002}
    assert Answer.field(%{"t" => "1970-02-30T00:00:00Z"}, "t", :time) == :error
    assert Answer.field(%{"t" => "1970-01-01T00:00:01Z"}, "t", :nisttime) == :error
  end

  test "booleans, enumerations and missing fields" do
    assert Answer.field(%{"b" => false}, "b", :boolean) == {:ok, false}
    assert Answer.field(%{"b" => "false"}, "b", :boolean) == :error
    assert Answer.field(%{"e" => "hash"}, "e", {:enum, ["hash"]}) == {:ok, "hash"}
    assert Answer.field(%{"e" => "id"}, "e", {:enum, ["hash"]}) == :error
    assert Answer.field(%{}, "e", :int) == :error
  end

  test "an answer as a row's values write it" do
    meta = %{source: "s", fetched_at: ~U[2026-10-16 12:00:00Z], cached: true}

    assert Answer.to_values({:found, %{"a" => 1}, meta}) == %{
             "cached" => true,
             "fetched_at" => "2026-10-16T12:00:00Z",
             "outcome" => "found",
             "source" => "s",
             "value" => %{"a" => 1}
           }

    assert Answer.to_values({:not_found, meta})["outcome"] == "not_found"

    assert Answer.to_values({:unreachable, :timeout}) == %{
             "outcome" => "unreachable",
             "reason" => "timeout"
           }

    assert Answer.to_values({:unreachable, "http 429"})["reason"] == "http 429"
    assert Answer.to_values({:unreachable, {:http, 503}})["reason"] == "{:http, 503}"
  end
end
