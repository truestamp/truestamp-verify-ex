# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verify.BitcoinTest do
  # The Bitcoin parsers of DERIVE (SPEC.md 10.2, step 9 (d)): every real transaction,
  # merkleblock and header under vectors/corpus/bitcoin/ gives what its `expected` says
  # (13.2), and single-defect mutants of them break the one rule each is built to break,
  # in the order the tables of Transaction and MerkleBlock give.
  use ExUnit.Case, async: true

  import Bitwise

  alias Truestamp.Verify.{Bitcoin, Instant}
  alias Truestamp.Verify.Spec.Constants
  alias Truestamp.Verify.Bitcoin.{MerkleBlock, Transaction}
  alias Truestamp.Verify.Test.StrictJSON

  @dir Truestamp.Verify.Test.Verification.path("vectors/corpus/bitcoin")
  @files @dir |> Path.join("*.json") |> Path.wildcard() |> Enum.sort()
  for file <- @files, do: @external_resource(file)

  defp corpus(name), do: StrictJSON.read_data!(Path.join(@dir, name <> ".json"))
  defp bytes(name), do: Base.decode16!(corpus(name)["hex"], case: :lower)

  defp time(seconds) do
    {:ok, text} = Instant.format(:time, seconds)
    text
  end

  describe "the corpus" do
    test "holds each kind the parsers read" do
      kinds = for file <- @files, uniq: true, do: StrictJSON.read_data!(file)["kind"]
      assert Enum.sort(kinds) == ~w(header merkleblock transaction)
    end

    for file <- @files do
      @file_path file
      @name Path.basename(file, ".json")

      test "#{@name} gives its expected values" do
        %{"expected" => expected, "hex" => hex, "kind" => kind} =
          StrictJSON.read_data!(@file_path)

        assert_expected(kind, Base.decode16!(hex, case: :lower), expected)
      end
    end
  end

  defp assert_expected("transaction", bytes, expected) do
    assert Bitcoin.display(Bitcoin.sha256d(bytes)) == expected["transaction_hash"]

    case Transaction.parse(bytes) do
      {:ok, pushed} ->
        assert expected["well_formed"]
        assert Bitcoin.hex(pushed) == expected["op_return"]

      {:error, rule} ->
        refute expected["well_formed"]
        assert Atom.to_string(rule) == expected["fails"]
    end
  end

  defp assert_expected("merkleblock", bytes, expected) do
    assert {:ok, block} = MerkleBlock.parse(bytes)
    assert expected["well_formed"]
    assert Bitcoin.display(block.matched) == expected["matched"]
    assert block.total_txs == expected["total_txs"]
    assert_header(block.header, expected)
  end

  defp assert_expected("header", bytes, expected) do
    assert Bitcoin.meets_target?(bytes) == expected["meets_target"]
    assert_header(bytes, expected)
  end

  defp assert_header(header, expected) do
    assert Bitcoin.header_hash(header) == expected["header_hash"]
    assert Bitcoin.header_merkle_root(header) == expected["header_merkle_root"]
    assert time(Bitcoin.header_time(header)) == expected["header_time"]
  end

  describe "the compact size" do
    test "reads only the shortest form" do
      assert Bitcoin.compact_size(<<0xFC, 1>>) == {:ok, 0xFC, <<1>>}
      assert Bitcoin.compact_size(<<0xFD, 0xFD, 0x00>>) == {:ok, 0xFD, ""}
      assert Bitcoin.compact_size(<<0xFD, 0xFC, 0x00>>) == :error
      assert Bitcoin.compact_size(<<0xFE, 0x00, 0x00, 0x01, 0x00>>) == {:ok, 0x10000, ""}
      assert Bitcoin.compact_size(<<0xFE, 0xFF, 0xFF, 0x00, 0x00>>) == :error
      assert Bitcoin.compact_size(<<0xFF, 0::little-32, 1::little-32>>) == {:ok, 1 <<< 32, ""}
      assert Bitcoin.compact_size(<<0xFF, 0xFFFF_FFFF::little-64>>) == :error
      assert Bitcoin.compact_size(<<0xFD, 0x01>>) == :error
      assert Bitcoin.compact_size(<<>>) == :error
    end
  end

  describe "the target nBits encodes" do
    # Bitcoin Core's arith_uint256_tests, SetCompact.
    test "gives Bitcoin Core's answers" do
      assert Bitcoin.target(0x00000000) == {:ok, 0}
      assert Bitcoin.target(0x00123456) == {:ok, 0}
      assert Bitcoin.target(0x01003456) == {:ok, 0}
      assert Bitcoin.target(0x02000056) == {:ok, 0}
      assert Bitcoin.target(0x03000000) == {:ok, 0}
      assert Bitcoin.target(0x04000000) == {:ok, 0}
      assert Bitcoin.target(0x00923456) == {:ok, 0}
      assert Bitcoin.target(0x01803456) == {:ok, 0}
      assert Bitcoin.target(0x02800056) == {:ok, 0}
      assert Bitcoin.target(0x03800000) == {:ok, 0}
      assert Bitcoin.target(0x04800000) == {:ok, 0}
      assert Bitcoin.target(0x01123456) == {:ok, 0x12}
      assert Bitcoin.target(0x01FEDCBA) == :error
      assert Bitcoin.target(0x02123456) == {:ok, 0x1234}
      assert Bitcoin.target(0x03123456) == {:ok, 0x123456}
      assert Bitcoin.target(0x04123456) == {:ok, 0x12345600}
      assert Bitcoin.target(0x04923456) == :error
      assert Bitcoin.target(0x05009234) == {:ok, 0x92340000}
      assert Bitcoin.target(0x20123456) == {:ok, 0x123456 <<< (8 * 29)}
      assert Bitcoin.target(0xFF123456) == :error
      assert Bitcoin.target(0x1D00FFFF) == {:ok, 0xFFFF <<< 208}
    end

    test "overflows at each of the three bounds" do
      assert {:ok, _target} = Bitcoin.target(0x22000001)
      assert Bitcoin.target(0x23000001) == :error
      assert {:ok, _target} = Bitcoin.target(0x210000FF)
      assert Bitcoin.target(0x22000100) == :error
      assert {:ok, _target} = Bitcoin.target(0x2000FFFF)
      assert Bitcoin.target(0x21010000) == :error
    end
  end

  # A transaction of one input with an empty script, and the output scripts given.
  defp transaction(scripts, lock_time \\ <<0::32>>) do
    input = <<0::size(36 * 8), 0, 0xFFFF_FFFF::32>>
    outputs = for script <- scripts, into: <<>>, do: <<0::64, byte_size(script), script::binary>>
    <<2::little-32, 1, input::binary, length(scripts), outputs::binary, lock_time::binary>>
  end

  defp op_return(value), do: <<0x6A, 0x20, value::binary-32>>

  describe "a raw_transaction" do
    setup do
      %{bytes: bytes("regtest-56062-transaction"), value: :crypto.strong_rand_bytes(32)}
    end

    test "the corpus's well-formed transaction is well formed", %{bytes: bytes} do
      assert {:ok, _pushed} = Transaction.parse(bytes)
    end

    test "with a byte after the lock time fails parse", %{bytes: bytes} do
      assert Transaction.parse(bytes <> <<0>>) == {:error, :parse}
      assert Transaction.parse(binary_part(bytes, 0, byte_size(bytes) - 1)) == {:error, :parse}
    end

    test "with no input fails parse", %{value: value} do
      assert <<version::binary-4, 1, _input::binary-41, rest::binary>> =
               transaction([op_return(value)])

      assert Transaction.parse(<<version::binary, 0, rest::binary>>) == {:error, :parse}
    end

    test "with a compact size not in its shortest form fails parse", %{value: value} do
      assert <<version::binary-4, 1, rest::binary>> = transaction([op_return(value)])
      assert Transaction.parse(<<version::binary, 0xFD, 1, 0, rest::binary>>) == {:error, :parse}
    end

    test "gives the one exact OP_RETURN, beside other scripts", %{value: value} do
      assert Transaction.parse(transaction([op_return(value)])) == {:ok, value}
      assert Transaction.parse(transaction([<<0x51>>, op_return(value), <<>>])) == {:ok, value}
    end

    test "of exactly 64 octets fails length, before op_return" do
      sixty_four = transaction([<<0x6A, 0x02, 0, 0>>])
      assert byte_size(sixty_four) == 64
      assert Transaction.parse(sixty_four) == {:error, :length}

      sixty_five = transaction([<<0x6A, 0x03, 0, 0, 0>>])
      assert byte_size(sixty_five) == 65
      assert Transaction.parse(sixty_five) == {:error, :op_return}
    end

    test "with two OP_RETURN outputs fails op_return", %{value: value} do
      assert Transaction.parse(transaction([op_return(value), op_return(value)])) ==
               {:error, :op_return}

      assert Transaction.parse(transaction([op_return(value), <<0x6A>>])) == {:error, :op_return}
    end

    test "with an OP_RETURN script other than 0x6a 0x20 and 32 bytes fails op_return", %{
      value: value
    } do
      for script <- [
            <<0x6A, 0x4C, 0x20, value::binary>>,
            <<0x6A, 0x20, binary_part(value, 0, 31)::binary>>,
            <<0x6A, 0x21, value::binary, 0>>,
            <<0x6A, 0x20, value::binary, 0x51>>,
            <<0x6A>>
          ] do
        assert Transaction.parse(transaction([script])) == {:error, :op_return}, inspect(script)
      end

      assert Transaction.parse(transaction([])) == {:error, :op_return}
      assert Transaction.parse(transaction([<<0x51>>])) == {:error, :op_return}
    end
  end

  # A merkleblock of `header`, `total` and the partial tree `hashes` and `flags`.
  defp merkle_block(header, total, hashes, flags) do
    <<header::binary-80, total::little-32, length(hashes), Enum.join(hashes)::binary,
      byte_size(flags), flags::binary>>
  end

  defp split(bytes) do
    <<header::binary-80, total::little-32, count, rest::binary>> = bytes
    octets = count * 32
    <<hashes::binary-size(^octets), flag_count, flags::binary-size(flag_count)>> = rest
    {header, total, for(<<hash::binary-32 <- hashes>>, do: hash), flags}
  end

  describe "a txoutproof" do
    setup do
      %{regtest: bytes("regtest-56062-merkleblock"), genesis: bytes("mainnet-0-merkleblock")}
    end

    test "the corpus's merkleblocks are well formed", %{regtest: regtest, genesis: genesis} do
      assert {:ok, %{total_txs: 2}} = MerkleBlock.parse(regtest)
      assert {:ok, %{total_txs: 1}} = MerkleBlock.parse(genesis)
    end

    test "with bytes after it, or cut short, fails parse", %{regtest: regtest} do
      assert MerkleBlock.parse(regtest <> <<0>>) == {:error, :parse}

      assert MerkleBlock.parse(binary_part(regtest, 0, byte_size(regtest) - 1)) ==
               {:error, :parse}

      assert MerkleBlock.parse(binary_part(regtest, 0, 79)) == {:error, :parse}
    end

    test "with a hash count not in its shortest form fails parse", %{regtest: regtest} do
      <<head::binary-84, count, rest::binary>> = regtest
      assert MerkleBlock.parse(<<head::binary, 0xFD, count, 0, rest::binary>>) == {:error, :parse}
    end

    test "with total_txs 0 or above BITCOIN_MAX_TOTAL_TXS fails total_txs", %{regtest: regtest} do
      {header, _total, hashes, flags} = split(regtest)
      max = Constants.bitcoin_max_total_txs()

      assert MerkleBlock.parse(merkle_block(header, 0, hashes, flags)) == {:error, :total_txs}

      assert MerkleBlock.parse(merkle_block(header, max + 1, hashes, flags)) ==
               {:error, :total_txs}

      # At the cap the count passes, and a later rule refuses the tree the two hashes make.
      assert {:error, rule} = MerkleBlock.parse(merkle_block(header, max, hashes, flags))
      assert rule not in [:parse, :total_txs]
    end

    test "with an unused hash or an unused flag bit fails partial_tree", %{regtest: regtest} do
      {header, total, hashes, <<flags>>} = split(regtest)

      assert MerkleBlock.parse(merkle_block(header, total, hashes ++ [hd(hashes)], <<flags>>)) ==
               {:error, :partial_tree}

      assert MerkleBlock.parse(merkle_block(header, total, hashes, <<flags ||| 0x80>>)) ==
               {:error, :partial_tree}

      assert MerkleBlock.parse(merkle_block(header, total, hashes, <<flags, 0>>)) ==
               {:error, :partial_tree}

      assert MerkleBlock.parse(merkle_block(header, total, tl(hashes), <<flags>>)) ==
               {:error, :partial_tree}

      assert MerkleBlock.parse(merkle_block(header, total, hashes, <<>>)) ==
               {:error, :partial_tree}
    end

    test "with a right child equal to its left fails duplicate_pair", %{regtest: regtest} do
      {header, 2, [left, _right], _flags} = split(regtest)

      # The root's bit 1, the left leaf's 0 (a hash, no match), the right leaf's 1 (a match).
      assert MerkleBlock.parse(merkle_block(header, 2, [left, left], <<0b101>>)) ==
               {:error, :duplicate_pair}
    end

    test "that matches no transaction, or two, fails matches", %{
      genesis: genesis,
      regtest: regtest
    } do
      {header, 1, hashes, _flags} = split(genesis)
      assert MerkleBlock.parse(merkle_block(header, 1, hashes, <<0>>)) == {:error, :matches}

      {header, 2, hashes, _flags} = split(regtest)
      assert MerkleBlock.parse(merkle_block(header, 2, hashes, <<0b111>>)) == {:error, :matches}
    end

    test "whose root is not the header's Merkle root field fails merkle_root", %{genesis: genesis} do
      {header, 1, _hashes, flags} = split(genesis)
      other = :crypto.hash(:sha256, "another transaction")
      assert MerkleBlock.parse(merkle_block(header, 1, [other], flags)) == {:error, :merkle_root}
    end

    test "whose header misses its target fails target", %{genesis: genesis, regtest: regtest} do
      {<<head::binary-76, _nonce::binary-4>>, 1, hashes, flags} = split(genesis)
      header = <<head::binary, 0::32>>
      refute Bitcoin.meets_target?(header)
      assert MerkleBlock.parse(merkle_block(header, 1, hashes, flags)) == {:error, :target}

      {<<head::binary-72, _bits::binary-4, nonce::binary-4>>, 2, hashes, flags} = split(regtest)

      for bits <- [0xFF123456, 0x04923456, 0x00000000, 0x207FFFFF] do
        header = <<head::binary, bits::little-32, nonce::binary>>
        parsed = MerkleBlock.parse(merkle_block(header, 2, hashes, flags))

        if bits == 0x207FFFFF,
          do: assert({:ok, _block} = parsed),
          else: assert(parsed == {:error, :target}, Integer.to_string(bits, 16))
      end
    end
  end
end
