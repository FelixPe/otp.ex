defmodule :m_asn1rtt_uper do
  use Bitwise

  def skipextensions(bytes0, nr, extensionBitstr)
      when is_bitstring(extensionBitstr) do
    prev = nr - 1

    case extensionBitstr do
      <<_::size(prev), 1::size(1), _::bitstring>> ->
        {len, bytes1} = decode_length(bytes0)
        <<_::size(len)-binary, bytes2::bitstring>> = bytes1
        skipextensions(bytes2, nr + 1, extensionBitstr)

      <<_::size(prev), 0::size(1), _::bitstring>> ->
        skipextensions(bytes0, nr + 1, extensionBitstr)

      _ ->
        bytes0
    end
  end

  defp decode_length(<<0::size(1), oct::size(7), rest::bitstring>>) do
    {oct, rest}
  end

  defp decode_length(<<2::size(2), val::size(14), rest::bitstring>>) do
    {val, rest}
  end

  defp decode_length(<<3::size(2), _::size(14), _Rest::bitstring>>) do
    exit({:error, {:asn1, {:decode_length, {:nyi, :above_16k}}}})
  end

  def complete(inList) when is_list(inList) do
    case :erlang.list_to_bitstring(inList) do
      <<>> ->
        <<0>>

      res ->
        sz = bit_size(res)

        case sz &&& 7 do
          0 ->
            res

          bits ->
            <<res::size(sz)-bitstring, 0::size(8 - bits)>>
        end
    end
  end

  def complete(bin) when is_binary(bin) do
    case bin do
      <<>> ->
        <<0>>

      _ ->
        bin
    end
  end

  def complete(inList) when is_bitstring(inList) do
    sz = bit_size(inList)
    padLen = 8 - sz &&& 7
    <<inList::size(sz)-bitstring, 0::size(padLen)>>
  end

  def complete_NFP(inList) when is_list(inList) do
    :erlang.list_to_bitstring(inList)
  end

  def complete_NFP(inList) when is_bitstring(inList) do
    inList
  end

  def encode_fragmented_sof(fun, comps, len) do
    encode_fragmented_sof_1(fun, comps, len, 4)
  end

  defp encode_fragmented_sof_1(encoder, comps0, len0, n) do
    segSz = n * 16384

    cond do
      len0 >= segSz ->
        {comps, b} = encode_components(comps0, encoder, segSz, [])
        len = len0 - segSz

        [
          <<3::size(2), n::size(6)>>,
          b
          | encode_fragmented_sof_1(encoder, comps, len, n)
        ]

      n > 1 ->
        encode_fragmented_sof_1(encoder, comps0, len0, n - 1)

      len0 < 128 ->
        {[], b} = encode_components(comps0, encoder, len0, [])
        [len0 | b]

      len0 < 16384 ->
        {[], b} = encode_components(comps0, encoder, len0, [])
        [<<2::size(2), len0::size(14)>> | b]
    end
  end

  defp encode_components(cs, _Encoder, 0, acc) do
    {cs, :lists.reverse(acc)}
  end

  defp encode_components([c | cs], encoder, size, acc) do
    b = encoder.(c)
    encode_components(cs, encoder, size - 1, [b | acc])
  end
end
