defmodule :m_binary do
  use Bitwise

  def at(_, _) do
    :erlang.nif_error(:undef)
  end

  def bin_to_list(subject) do
    try do
      :erlang.binary_to_list(subject)
    catch
      :error, reason ->
        error_with_info(reason, [subject])
    end
  end

  def bin_to_list(subject, {pos, len}) do
    try do
      bin_to_list(subject, pos, len)
    catch
      :error, reason ->
        error_with_info(reason, [subject, {pos, len}])
    end
  end

  def bin_to_list(subject, badPosLen) do
    badarg_with_info([subject, badPosLen])
  end

  def bin_to_list(subject, pos, len)
      when not is_binary(subject) or
             not is_integer(pos) or not is_integer(len) do
    badarg_with_info([subject, pos, len])
  end

  def bin_to_list(subject, pos, 0)
      when pos >= 0 and
             pos <= byte_size(subject) do
    []
  end

  def bin_to_list(subject, pos, len) when len < 0 do
    try do
      bin_to_list(subject, pos + len, -len)
    catch
      :error, reason ->
        error_with_info(reason, [subject, pos, len])
    end
  end

  def bin_to_list(subject, pos, len) when len > 0 do
    try do
      :erlang.binary_to_list(subject, pos + 1, pos + len)
    catch
      :error, reason ->
        error_with_info(reason, [subject, pos, len])
    end
  end

  def bin_to_list(subject, pos, len) do
    badarg_with_info([subject, pos, len])
  end

  def compile_pattern(_) do
    :erlang.nif_error(:undef)
  end

  def copy(_) do
    :erlang.nif_error(:undef)
  end

  def copy(_, _) do
    :erlang.nif_error(:undef)
  end

  def decode_unsigned(_) do
    :erlang.nif_error(:undef)
  end

  def decode_unsigned(_, _) do
    :erlang.nif_error(:undef)
  end

  def encode_unsigned(_) do
    :erlang.nif_error(:undef)
  end

  def encode_unsigned(_, _) do
    :erlang.nif_error(:undef)
  end

  def first(_) do
    :erlang.nif_error(:undef)
  end

  def last(_) do
    :erlang.nif_error(:undef)
  end

  def list_to_bin(_) do
    :erlang.nif_error(:undef)
  end

  def longest_common_prefix(_) do
    :erlang.nif_error(:undef)
  end

  def longest_common_suffix(_) do
    :erlang.nif_error(:undef)
  end

  def match(_, _) do
    :erlang.nif_error(:undef)
  end

  def match(_, _, _) do
    :erlang.nif_error(:undef)
  end

  def matches(_, _) do
    :erlang.nif_error(:undef)
  end

  def matches(_, _, _) do
    :erlang.nif_error(:undef)
  end

  def part(_, _) do
    :erlang.nif_error(:undef)
  end

  def part(_, _, _) do
    :erlang.nif_error(:undef)
  end

  def referenced_byte_size(_) do
    :erlang.nif_error(:undef)
  end

  def split(_, _) do
    :erlang.nif_error(:undef)
  end

  def split(_, _, _) do
    :erlang.nif_error(:undef)
  end

  def replace(h, n, r) do
    try do
      replace(h, n, r, [])
    catch
      :error, reason ->
        error_with_info(reason, [h, n, r])
    end
  end

  def replace(haystack, needles, replacement, options) do
    try do
      true = is_binary(replacement)

      {part, global, insert} =
        get_opts_replace(
          options,
          {:no, false, []}
        )

      moptlist =
        case part do
          :no ->
            []

          {a, b} ->
            [{:scope, {a, b}}]
        end

      mList =
        cond do
          global ->
            :binary.matches(haystack, needles, moptlist)

          true ->
            case :binary.match(haystack, needles, moptlist) do
              :nomatch ->
                []

              match ->
                [match]
            end
        end

      replList =
        case insert do
          [] ->
            replacement

          y when is_integer(y) ->
            splitat(replacement, 0, [y])

          li when is_list(li) ->
            splitat(replacement, 0, :lists.sort(li))
        end

      :erlang.iolist_to_binary(do_replace(haystack, mList, replList, 0))
    catch
      :badopt ->
        badarg_with_cause(
          [haystack, needles, replacement, options],
          :badopt
        )

      _, _ ->
        badarg_with_info([haystack, needles, replacement, options])
    end
  end

  defp do_replace(h, [], _, n) do
    [:binary.part(h, {n, byte_size(h) - n})]
  end

  defp do_replace(h, [{a, b} | t], replacement, n) do
    [
      :binary.part(h, {n, a - n}),
      cond do
        is_list(replacement) ->
          do_insert(
            replacement,
            :binary.part(h, {a, b})
          )

        true ->
          replacement
      end
      | do_replace(h, t, replacement, a + b)
    ]
  end

  defp do_insert([x], _) do
    [x]
  end

  defp do_insert([h | t], r) do
    [h, r | do_insert(t, r)]
  end

  defp splitat(h, n, []) do
    [:binary.part(h, {n, byte_size(h) - n})]
  end

  defp splitat(h, n, [i | t]) do
    [:binary.part(h, {n, i - n}) | splitat(h, i, t)]
  end

  defp get_opts_replace([], {part, global, insert}) do
    {part, global, insert}
  end

  defp get_opts_replace(
         [{:scope, {a, b}} | t],
         {_Part, global, insert}
       ) do
    get_opts_replace(t, {{a, b}, global, insert})
  end

  defp get_opts_replace([:global | t], {part, _Global, insert}) do
    get_opts_replace(t, {part, true, insert})
  end

  defp get_opts_replace(
         [{:insert_replaced, n} | t],
         {part, global, _Insert}
       ) do
    get_opts_replace(t, {part, global, n})
  end

  defp get_opts_replace(_, _) do
    throw(:badopt)
  end

  def encode_hex(bin) when is_binary(bin) do
    encode_hex(bin, :uppercase)
  end

  def encode_hex(bin) do
    error_with_info(:badarg, [bin])
  end

  def encode_hex(bin, :uppercase) when is_binary(bin) do
    encode_hex1(bin, 1)
  end

  def encode_hex(bin, :lowercase) when is_binary(bin) do
    encode_hex1(bin, 257)
  end

  def encode_hex(bin, case__) do
    error_with_info(:badarg, [bin, case__])
  end

  defp encode_hex1(data, offset) do
    <<first::size(div(bit_size(data), 64))-binary-unit(64), rest::binary>> = data

    hex =
      for <<(<<a, b, c, d, e, f, g, h>> <- first)>>,
        into: <<>> do
        <<hex(a, offset)::size(16), hex(b, offset)::size(16), hex(c, offset)::size(16),
          hex(d, offset)::size(16), hex(e, offset)::size(16), hex(f, offset)::size(16),
          hex(g, offset)::size(16), hex(h, offset)::size(16)>>
      end

    encode_hex2(rest, offset, hex)
  end

  defp encode_hex2(<<a, data::binary>>, offset, acc) do
    encode_hex2(data, offset, <<acc::binary, hex(a, offset)::size(16)>>)
  end

  defp encode_hex2(<<>>, _Offset, acc) do
    acc
  end

  defp hex(x, offset) do
    :erlang.element(
      x + offset,
      {12336, 12337, 12338, 12339, 12340, 12341, 12342, 12343, 12344, 12345, 12353, 12354, 12355,
       12356, 12357, 12358, 12592, 12593, 12594, 12595, 12596, 12597, 12598, 12599, 12600, 12601,
       12609, 12610, 12611, 12612, 12613, 12614, 12848, 12849, 12850, 12851, 12852, 12853, 12854,
       12855, 12856, 12857, 12865, 12866, 12867, 12868, 12869, 12870, 13104, 13105, 13106, 13107,
       13108, 13109, 13110, 13111, 13112, 13113, 13121, 13122, 13123, 13124, 13125, 13126, 13360,
       13361, 13362, 13363, 13364, 13365, 13366, 13367, 13368, 13369, 13377, 13378, 13379, 13380,
       13381, 13382, 13616, 13617, 13618, 13619, 13620, 13621, 13622, 13623, 13624, 13625, 13633,
       13634, 13635, 13636, 13637, 13638, 13872, 13873, 13874, 13875, 13876, 13877, 13878, 13879,
       13880, 13881, 13889, 13890, 13891, 13892, 13893, 13894, 14128, 14129, 14130, 14131, 14132,
       14133, 14134, 14135, 14136, 14137, 14145, 14146, 14147, 14148, 14149, 14150, 14384, 14385,
       14386, 14387, 14388, 14389, 14390, 14391, 14392, 14393, 14401, 14402, 14403, 14404, 14405,
       14406, 14640, 14641, 14642, 14643, 14644, 14645, 14646, 14647, 14648, 14649, 14657, 14658,
       14659, 14660, 14661, 14662, 16688, 16689, 16690, 16691, 16692, 16693, 16694, 16695, 16696,
       16697, 16705, 16706, 16707, 16708, 16709, 16710, 16944, 16945, 16946, 16947, 16948, 16949,
       16950, 16951, 16952, 16953, 16961, 16962, 16963, 16964, 16965, 16966, 17200, 17201, 17202,
       17203, 17204, 17205, 17206, 17207, 17208, 17209, 17217, 17218, 17219, 17220, 17221, 17222,
       17456, 17457, 17458, 17459, 17460, 17461, 17462, 17463, 17464, 17465, 17473, 17474, 17475,
       17476, 17477, 17478, 17712, 17713, 17714, 17715, 17716, 17717, 17718, 17719, 17720, 17721,
       17729, 17730, 17731, 17732, 17733, 17734, 17968, 17969, 17970, 17971, 17972, 17973, 17974,
       17975, 17976, 17977, 17985, 17986, 17987, 17988, 17989, 17990, 12336, 12337, 12338, 12339,
       12340, 12341, 12342, 12343, 12344, 12345, 12385, 12386, 12387, 12388, 12389, 12390, 12592,
       12593, 12594, 12595, 12596, 12597, 12598, 12599, 12600, 12601, 12641, 12642, 12643, 12644,
       12645, 12646, 12848, 12849, 12850, 12851, 12852, 12853, 12854, 12855, 12856, 12857, 12897,
       12898, 12899, 12900, 12901, 12902, 13104, 13105, 13106, 13107, 13108, 13109, 13110, 13111,
       13112, 13113, 13153, 13154, 13155, 13156, 13157, 13158, 13360, 13361, 13362, 13363, 13364,
       13365, 13366, 13367, 13368, 13369, 13409, 13410, 13411, 13412, 13413, 13414, 13616, 13617,
       13618, 13619, 13620, 13621, 13622, 13623, 13624, 13625, 13665, 13666, 13667, 13668, 13669,
       13670, 13872, 13873, 13874, 13875, 13876, 13877, 13878, 13879, 13880, 13881, 13921, 13922,
       13923, 13924, 13925, 13926, 14128, 14129, 14130, 14131, 14132, 14133, 14134, 14135, 14136,
       14137, 14177, 14178, 14179, 14180, 14181, 14182, 14384, 14385, 14386, 14387, 14388, 14389,
       14390, 14391, 14392, 14393, 14433, 14434, 14435, 14436, 14437, 14438, 14640, 14641, 14642,
       14643, 14644, 14645, 14646, 14647, 14648, 14649, 14689, 14690, 14691, 14692, 14693, 14694,
       24880, 24881, 24882, 24883, 24884, 24885, 24886, 24887, 24888, 24889, 24929, 24930, 24931,
       24932, 24933, 24934, 25136, 25137, 25138, 25139, 25140, 25141, 25142, 25143, 25144, 25145,
       25185, 25186, 25187, 25188, 25189, 25190, 25392, 25393, 25394, 25395, 25396, 25397, 25398,
       25399, 25400, 25401, 25441, 25442, 25443, 25444, 25445, 25446, 25648, 25649, 25650, 25651,
       25652, 25653, 25654, 25655, 25656, 25657, 25697, 25698, 25699, 25700, 25701, 25702, 25904,
       25905, 25906, 25907, 25908, 25909, 25910, 25911, 25912, 25913, 25953, 25954, 25955, 25956,
       25957, 25958, 26160, 26161, 26162, 26163, 26164, 26165, 26166, 26167, 26168, 26169, 26209,
       26210, 26211, 26212, 26213, 26214}
    )
  end

  def decode_hex(data) when rem(byte_size(data), 2) === 0 do
    try do
      decode_hex1(data)
    catch
      :error, :badarg ->
        badarg_with_info([data])
    end
  end

  def decode_hex(data) do
    badarg_with_info([data])
  end

  defp decode_hex1(data) do
    <<first::size(div(byte_size(data), 8))-binary-unit(64), rest::binary>> = data

    bin =
      for <<(<<a, b, c, d, e, f, g, h>> <- first)>>,
        into: <<>> do
        <<unhex(a)::size(4), unhex(b)::size(4), unhex(c)::size(4), unhex(d)::size(4),
          unhex(e)::size(4), unhex(f)::size(4), unhex(g)::size(4), unhex(h)::size(4)>>
      end

    decode_hex2(rest, bin)
  end

  defp decode_hex2(<<a, data::binary>>, acc) do
    decode_hex2(
      data,
      <<acc::binary-unit(4), unhex(a)::size(4)>>
    )
  end

  defp decode_hex2(<<>>, acc) do
    acc
  end

  defp unhex(x) do
    :erlang.element(
      x,
      {:nonono, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no,
       :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no,
       :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
       :no, :no, :no, :no, :no, :no, :no, 10, 11, 12, 13, 14, 15, :no, :no, :no, :no, :no, :no,
       :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no, :no,
       :no, :no, 10, 11, 12, 13, 14, 15, :no, :no, :no, :no, :no, :no, :no, :no, :no}
    )
  end

  defp badarg_with_cause(args, cause) do
    :erlang.error(:badarg, args, [{:error_info, %{module: :erl_stdlib_errors, cause: cause}}])
  end

  defp badarg_with_info(args) do
    :erlang.error(:badarg, args, [{:error_info, %{module: :erl_stdlib_errors}}])
  end

  defp error_with_info(reason, args) do
    :erlang.error(reason, args, [{:error_info, %{module: :erl_stdlib_errors}}])
  end
end
