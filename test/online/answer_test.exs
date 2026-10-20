# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.Online.AnswerTest do
  @moduledoc """
  The classes of an answer's fields (SPEC.md section 13.2's table), and an answer as a row's
  `values` write it.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

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
  end

  # SPEC.md 2.4 and 13.2: a reason is an ASCII128, 1 to 128 printable ASCII characters with
  # no `"` or `\`.
  @ascii128 ~r/\A[\x20\x21\x23-\x5b\x5d-\x7e]{1,128}\z/

  test "an unreachable reason is written as text that says why, never an Elixir term" do
    for {reason, written} <- [
          {{:http_status, 503}, "HTTP 503"},
          {{:transport, "connection refused"}, "transport failure: connection refused"},
          {{:rpc_error, %{"code" => -28, "message" => "Loading block index"}},
           "Bitcoin Core RPC error -28"},
          {{:rpc_error, %{"message" => "no code"}}, "the reader gave no usable answer"},
          {{:cookie, :enoent}, "the Bitcoin Core cookie file cannot be read"},
          {{:reader_fault, :error, "RuntimeError"}, "the reader raised RuntimeError"},
          {{:reader_fault, :throw, nil}, "the reader threw"},
          {{:reader_fault, :exit, nil}, "the reader exited"},
          {{:not_in_replay, %{"kind" => "bitcoin_tip"}},
           "the replay file holds no answer to this read"},
          {{:unreachable, "HTTP 503"}, "HTTP 503"},
          {{:unreachable, nil}, "the reader gave no usable answer"},
          {:deadline, "the run's deadline passed before the answer came"},
          {:malformed_answer, "the answer does not parse, or is not in its form"},
          {:cached_live_read, "a cached answer, to a read made only live"},
          {:cached_not_found, "a cached not-found answer, which only a live read gives"},
          {:cached_not_final, "a cached block at a height, read under a tip that was not final"},
          {:identity_not_found, "the identity read answered not found"},
          {:identity_unusable, "the identity read gave no identity in its form"},
          {:answered_another, "the answer names another object than the one asked for"},
          {:timeout, "timeout"},
          {nil, "the reader gave no usable answer"},
          {{:http, 503}, "the reader gave no usable answer"},
          {~s(say "why"\n), "say ?why??"},
          {"caf\u00e9 \\ <<0xFF>>", "caf? ? <<0xFF>>"},
          {<<"a", 0xFF, "b">>, "a?b"},
          {"", "the reader gave no usable answer"},
          {String.duplicate("x", 200), String.duplicate("x", 128)}
        ] do
      assert Answer.describe(reason) == written, inspect(reason)
      assert Regex.match?(@ascii128, written), written
    end
  end

  property "every reason, of any term, is written as an ASCII128" do
    check all(
            reason <-
              one_of([
                term(),
                string(:printable),
                binary(),
                tuple({constant(:unreachable), string(:printable)}),
                tuple({constant(:transport), binary()}),
                tuple({constant(:reader_fault), constant(:error), string(:utf8)})
              ])
          ) do
      written = Answer.describe(reason)
      assert Regex.match?(@ascii128, written), inspect({reason, written})
    end
  end
end
