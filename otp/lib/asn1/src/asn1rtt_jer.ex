defmodule :m_asn1rtt_jer do
  use Bitwise

  def encode_jer(module, type, val) do
    info = module.typeinfo(type)
    encode_jer(info, val)
  end

  defp encode_jer(
         {:sequence_tab, simple, sname, arity, compInfos},
         value
       )
       when tuple_size(value) == arity + 1 do
    [^sname | clist] = :erlang.tuple_to_list(value)
    encode_jer_component_tab(compInfos, clist, simple, %{})
  end

  defp encode_jer(
         {:sequence_map, _Sname, _Arity, compInfos},
         value
       )
       when is_map(value) do
    encode_jer_component_map(compInfos, value, [])
  end

  defp encode_jer({:sequence, sname, arity, compInfos}, value)
       when tuple_size(value) == arity + 1 do
    [^sname | clist] = :erlang.tuple_to_list(value)
    encode_jer_component(compInfos, clist, [])
  end

  defp encode_jer(:string, str) when is_list(str) do
    :erlang.list_to_binary(str)
  end

  defp encode_jer({:string, _Prop}, str) when is_list(str) do
    :erlang.list_to_binary(str)
  end

  defp encode_jer(:string, str) when is_binary(str) do
    str
  end

  defp encode_jer({:string, _Prop}, str) when is_binary(str) do
    str
  end

  defp encode_jer(:INTEGER, int) when is_integer(int) do
    int
  end

  defp encode_jer({:INTEGER, {min, max}}, int)
       when is_integer(int) and max >= int and int >= min do
    int
  end

  defp encode_jer({:INTEGER_NNL, _NNL}, int)
       when is_integer(int) do
    int
  end

  defp encode_jer(type = {:INTEGER_NNL, nNList}, int)
       when is_atom(int) do
    case :lists.keyfind(int, 1, nNList) do
      {_, newVal} ->
        newVal

      _ ->
        exit({:error, {:asn1, {type, int}}})
    end
  end

  defp encode_jer(
         {type = {:INTEGER_NNL, _NNList}, _Constraint},
         int
       )
       when is_atom(int) do
    encode_jer(type, int)
  end

  defp encode_jer({{:INTEGER_NNL, _NNList}, constraint}, int)
       when is_integer(int) do
    encode_jer({:INTEGER, constraint}, int)
  end

  defp encode_jer(:BOOLEAN, bool) when is_boolean(bool) do
    bool
  end

  defp encode_jer({:BOOLEAN, _Prop}, bool)
       when is_boolean(bool) do
    bool
  end

  defp encode_jer(:NULL, _) do
    :null
  end

  defp encode_jer(:legacy_octet_string, value)
       when is_list(value) do
    bitstring2json(:erlang.list_to_binary(value))
  end

  defp encode_jer({:legacy_octet_string, _Prop}, value)
       when is_list(value) do
    bitstring2json(:erlang.list_to_binary(value))
  end

  defp encode_jer(:octet_string, value) when is_binary(value) do
    encode_jer({:octet_string, []}, value)
  end

  defp encode_jer({:octet_string, _Prop}, value)
       when is_binary(value) do
    bitstring2json(value)
  end

  defp encode_jer({:ENUMERATED, enumMap}, val)
       when :erlang.is_map_key(val, enumMap) do
    val
  end

  defp encode_jer(
         {type = {:ENUMERATED, _EnumList}, _Constr},
         val
       ) do
    encode_jer(type, val)
  end

  defp encode_jer({:ENUMERATED_EXT, _EnumMap}, val)
       when is_atom(val) do
    val
  end

  defp encode_jer(
         {type = {:ENUMERATED_EXT, _EnumList}, _Constr},
         val
       ) do
    encode_jer(type, val)
  end

  defp encode_jer({:typeinfo, {module, type}}, val) do
    typeInfo = module.typeinfo(type)
    encode_jer(typeInfo, val)
  end

  defp encode_jer({:sof, type}, vals) when is_list(vals) do
    for val <- vals do
      encode_jer(type, val)
    end
  end

  defp encode_jer({:choice, choices}, {alt, value}) do
    case :erlang.is_map_key(
           altBin =
             :erlang.atom_to_binary(
               alt,
               :utf8
             ),
           choices
         ) do
      true ->
        encodedVal =
          encode_jer(
            :maps.get(altBin, choices),
            value
          )

        %{altBin => encodedVal}

      false ->
        exit({:error, {:asn1, {:invalid_choice, alt, choices}}})
    end
  end

  defp encode_jer(:bit_string, value) do
    str = bitstring2json(value)
    %{value: str, length: bit_size(value)}
  end

  defp encode_jer({:bit_string, fixedLength}, value)
       when is_bitstring(value) and
              is_integer(fixedLength) do
    value2 = jer_padbitstr(value, fixedLength)
    bitstring2json(value2)
  end

  defp encode_jer(:compact_bit_string, compact) do
    bitStr = jer_compact2bitstr(compact)
    encode_jer(:bit_string, bitStr)
  end

  defp encode_jer(
         {:compact_bit_string, fixedLength},
         compact = {_Unused, binary}
       )
       when is_binary(binary) do
    bitStr = jer_compact2bitstr(compact)
    encode_jer({:bit_string, fixedLength}, bitStr)
  end

  defp encode_jer({:bit_string_nnl, nNL}, value) do
    value1 = jer_bit_str2bitstr(value, nNL)
    encode_jer(:bit_string, value1)
  end

  defp encode_jer({{:bit_string_nnl, nNL}, fixedLength}, value) do
    value1 = jer_bit_str2bitstr(value, nNL)
    encode_jer({:bit_string, fixedLength}, value1)
  end

  defp encode_jer({:compact_bit_string_nnl, nNL}, value) do
    value1 = jer_bit_str2bitstr(value, nNL)
    encode_jer(:bit_string, value1)
  end

  defp encode_jer(
         {{:compact_bit_string_nnl, nNL}, fixedLength},
         value
       ) do
    value1 = jer_bit_str2bitstr(value, nNL)
    encode_jer({:bit_string, fixedLength}, value1)
  end

  defp encode_jer(:"OBJECT IDENTIFIER", oid) when is_tuple(oid) do
    oid2json(oid)
  end

  defp encode_jer(:"RELATIVE-OID", oid) when is_tuple(oid) do
    oid2json(oid)
  end

  defp encode_jer({:ObjClassFieldType, _, _}, val)
       when is_binary(val) do
    val
  end

  defp encode_jer(:ASN1_OPEN_TYPE, val) when is_binary(val) do
    val
  end

  defp encode_jer({:container, type, _Containing}, val) do
    encode_jer(type, val)
  end

  defp encode_jer(type, val) do
    exit({:error, {:asn1, {{:encode, type}, val}}})
  end

  defp encode_jer_component_tab(
         [{_Name, _Type, :OPTIONAL} | compInfos],
         [:asn1_NOVALUE | rest],
         simple,
         mapAcc
       ) do
    encode_jer_component_tab(compInfos, rest, simple, mapAcc)
  end

  defp encode_jer_component_tab(
         [{_Name, _Type, {:DEFAULT, _}} | compInfos],
         [:asn1_DEFAULT | rest],
         simple,
         mapAcc
       ) do
    encode_jer_component_tab(compInfos, rest, simple, mapAcc)
  end

  defp encode_jer_component_tab(
         [{name, type, _OptOrDefault} | compInfos],
         [value | rest],
         simple,
         mapAcc
       ) do
    enc = encode_jer(type, value)
    encode_jer_component_tab(compInfos, rest, simple, Map.put(mapAcc, name, enc))
  end

  defp encode_jer_component_tab([], _, _Simple, mapAcc) do
    mapAcc
  end

  defp encode_jer_component_map(
         [
           {name, aName, type, _OptOrDefault}
           | compInfos
         ],
         mapVal,
         acc
       )
       when :erlang.is_map_key(aName, mapVal) do
    value = :maps.get(aName, mapVal)
    enc = encode_jer(type, value)
    encode_jer_component_map(compInfos, mapVal, [{name, enc} | acc])
  end

  defp encode_jer_component_map([{_Name, _AName, _Type, :OPTIONAL} | compInfos], mapVal, acc) do
    encode_jer_component_map(compInfos, mapVal, acc)
  end

  defp encode_jer_component_map(
         [
           {_Name, _AName, _Type, {:DEFAULT, _}}
           | compInfos
         ],
         mapVal,
         acc
       ) do
    encode_jer_component_map(compInfos, mapVal, acc)
  end

  defp encode_jer_component_map([], mapVal, []) when map_size(mapVal) == 0 do
    %{}
  end

  defp encode_jer_component_map([], mapVal, acc)
       when map_size(mapVal) == length(acc) do
    :lists.reverse(acc)
  end

  defp encode_jer_component_map(_, mapVal, acc) do
    erroneousKeys =
      :maps.keys(mapVal) --
        for {k, _V} <- acc do
          k
        end

    exit({:error, {:asn1, {{:encode, :SEQUENCE}, {:erroneous_keys, erroneousKeys}}}})
  end

  defp encode_jer_component([{_Name, _Type, :OPTIONAL} | compInfos], [:asn1_NOVALUE | rest], acc) do
    encode_jer_component(compInfos, rest, acc)
  end

  defp encode_jer_component(
         [{_Name, _Type, {:DEFAULT, _}} | compInfos],
         [:asn1_DEFAULT | rest],
         acc
       ) do
    encode_jer_component(compInfos, rest, acc)
  end

  defp encode_jer_component([{name, type, _OptOrDefault} | compInfos], [value | rest], acc) do
    enc = encode_jer(type, value)
    encode_jer_component(compInfos, rest, [{name, enc} | acc])
  end

  defp encode_jer_component([], _, []) do
    %{}
  end

  defp encode_jer_component([], _, acc) do
    :lists.reverse(acc)
  end

  def decode_jer(module, type, val) do
    typeInfo = module.typeinfo(type)
    decode_jer(typeInfo, val)
  end

  defp decode_jer({:ENUMERATED, _EnumList}, val)
       when is_binary(val) do
    :erlang.binary_to_existing_atom(val, :utf8)
  end

  defp decode_jer({:ENUMERATED, _EnumList}, val)
       when is_boolean(val) do
    val
  end

  defp decode_jer({:ENUMERATED, _EnumList}, :null) do
    :null
  end

  defp decode_jer(
         {type = {:ENUMERATED, _EnumList}, _Constr},
         val
       ) do
    decode_jer(type, val)
  end

  defp decode_jer({:ENUMERATED_EXT, enumList}, val) do
    decode_jer({:ENUMERATED, enumList}, val)
  end

  defp decode_jer(
         {type = {:ENUMERATED_EXT, _EnumList}, _Constr},
         val
       ) do
    decode_jer(type, val)
  end

  defp decode_jer({:typeinfo, {module, type}}, val) do
    typeInfo = module.typeinfo(type)
    decode_jer(typeInfo, val)
  end

  defp decode_jer({:sequence, sname, _Arity, compInfos}, value)
       when is_map(value) do
    decodedComps = decode_jer_component(compInfos, value, [])
    :erlang.list_to_tuple([sname | decodedComps])
  end

  defp decode_jer(
         {:sequence_map, _Sname, _Arity, compInfos},
         value
       )
       when is_map(value) do
    decode_jer_component_map(compInfos, value, [])
  end

  defp decode_jer(:string, str) when is_binary(str) do
    :erlang.binary_to_list(str)
  end

  defp decode_jer({:string, _Prop}, str) when is_binary(str) do
    :erlang.binary_to_list(str)
  end

  defp decode_jer(:INTEGER, int) when is_integer(int) do
    int
  end

  defp decode_jer({:INTEGER, {min, max}}, int)
       when is_integer(int) and max >= int and int >= min do
    int
  end

  defp decode_jer({type = {:INTEGER_NNL, _NNList}, _}, int) do
    decode_jer(type, int)
  end

  defp decode_jer({:INTEGER_NNL, nNList}, int) do
    case :lists.keyfind(int, 2, nNList) do
      {newName, _} ->
        newName

      _ ->
        int
    end
  end

  defp decode_jer(:BOOLEAN, bool) when is_boolean(bool) do
    bool
  end

  defp decode_jer({:BOOLEAN, _Prop}, bool)
       when is_boolean(bool) do
    bool
  end

  defp decode_jer(:NULL, :null) do
    :NULL
  end

  defp decode_jer(:legacy_octet_string, str)
       when is_binary(str) do
    json2octetstring2string(:erlang.binary_to_list(str))
  end

  defp decode_jer(:octet_string, str) when is_binary(str) do
    json2octetstring2binary(:erlang.binary_to_list(str))
  end

  defp decode_jer({:sof, type}, vals) when is_list(vals) do
    for val <- vals do
      decode_jer(type, val)
    end
  end

  defp decode_jer({:choice, choiceTypes}, choiceVal) do
    [{alt, val}] = :maps.to_list(choiceVal)

    case choiceTypes do
      %{^alt => type} ->
        ^type = :maps.get(alt, choiceTypes)
        {:erlang.binary_to_atom(alt, :utf8), decode_jer(type, val)}

      _ ->
        exit({:error, {:asn1, {:invalid_choice, alt, :maps.keys(choiceTypes)}}})
    end
  end

  defp decode_jer(:bit_string, %{"value" => str, "length" => length}) do
    json2bitstring(:erlang.binary_to_list(str), length)
  end

  defp decode_jer({:bit_string, fixedLength}, str)
       when is_binary(str) do
    json2bitstring(:erlang.binary_to_list(str), fixedLength)
  end

  defp decode_jer(
         {:bit_string_nnl, nNL},
         %{"value" => str, "length" => length}
       ) do
    bitStr =
      json2bitstring(
        :erlang.binary_to_list(str),
        length
      )

    jer_bitstr2names(bitStr, nNL)
  end

  defp decode_jer({{:bit_string_nnl, nNL}, fixedLength}, str)
       when is_binary(str) do
    bitStr =
      json2bitstring(
        :erlang.binary_to_list(str),
        fixedLength
      )

    jer_bitstr2names(bitStr, nNL)
  end

  defp decode_jer({:compact_bit_string_nnl, nNL}, value) do
    decode_jer({:bit_string_nnl, nNL}, value)
  end

  defp decode_jer(
         {{:compact_bit_string_nnl, nNL}, fixedLength},
         value
       ) do
    decode_jer({{:bit_string_nnl, nNL}, fixedLength}, value)
  end

  defp decode_jer(
         :compact_bit_string,
         %{"value" => str, "length" => length}
       ) do
    bitStr =
      json2bitstring(
        :erlang.binary_to_list(str),
        length
      )

    jer_bitstr2compact(bitStr)
  end

  defp decode_jer({:compact_bit_string, fixedLength}, str) do
    bitStr =
      json2bitstring(
        :erlang.binary_to_list(str),
        fixedLength
      )

    unused = 8 - rem(fixedLength, 8) &&& 7
    {unused, <<bitStr::bitstring, 0::size(unused)>>}
  end

  defp decode_jer(:"OBJECT IDENTIFIER", oidBin) when is_binary(oidBin) do
    json2oid(oidBin)
  end

  defp decode_jer(:"RELATIVE-OID", oidBin) when is_binary(oidBin) do
    json2oid(oidBin)
  end

  defp decode_jer({:ObjClassFieldType, _, _}, bin)
       when is_binary(bin) do
    bin
  end

  defp decode_jer(:ASN1_OPEN_TYPE, bin) when is_binary(bin) do
    bin
  end

  defp decode_jer({:container, type, _Containing}, val) do
    decode_jer(type, val)
  end

  defp decode_jer(type, val) do
    exit({:error, {:asn1, {{:decode, type}, val}}})
  end

  defp decode_jer_component([{name, type, _OptOrDefault} | compInfos], vMap, acc)
       when :erlang.is_map_key(name, vMap) do
    value = :maps.get(name, vMap)
    dec = decode_jer(type, value)
    decode_jer_component(compInfos, vMap, [dec | acc])
  end

  defp decode_jer_component([{_Name, _Type, :OPTIONAL} | compInfos], vMap, acc) do
    decode_jer_component(compInfos, vMap, [:asn1_NOVALUE | acc])
  end

  defp decode_jer_component(
         [
           {_Name, _Type, {:DEFAULT, dvalue}}
           | compInfos
         ],
         vMap,
         acc
       ) do
    decode_jer_component(compInfos, vMap, [dvalue | acc])
  end

  defp decode_jer_component([{name, _Type, _OptOrDefault} | _CompInfos], vMap, _Acc) do
    exit({:error, {:asn1, {{:decode, {:mandatory_component_missing, name}}, vMap}}})
  end

  defp decode_jer_component([], _, acc) do
    :lists.reverse(acc)
  end

  defp decode_jer_component_map(
         [
           {name, atomName, type, _OptOrDefault}
           | compInfos
         ],
         vMap,
         acc
       )
       when :erlang.is_map_key(name, vMap) do
    value = :maps.get(name, vMap)
    dec = decode_jer(type, value)
    decode_jer_component_map(compInfos, vMap, [{atomName, dec} | acc])
  end

  defp decode_jer_component_map(
         [
           {_Name, _AtomName, _Type, :OPTIONAL}
           | compInfos
         ],
         vMap,
         acc
       ) do
    decode_jer_component_map(compInfos, vMap, acc)
  end

  defp decode_jer_component_map(
         [
           {_Name, atomName, _Type, {:DEFAULT, dvalue}}
           | compInfos
         ],
         vMap,
         acc
       ) do
    decode_jer_component_map(compInfos, vMap, [{atomName, dvalue} | acc])
  end

  defp decode_jer_component_map(
         [
           {name, _AtomName, _Type, _OptOrDefault}
           | _CompInfos
         ],
         vMap,
         _Acc
       ) do
    exit({:error, {:asn1, {{:decode, {:mandatory_component_missing, name}}, vMap}}})
  end

  defp decode_jer_component_map([], _, acc) do
    :maps.from_list(acc)
  end

  defp json2octetstring2binary(value) do
    :erlang.list_to_binary(json2octetstring(value, []))
  end

  defp json2octetstring2string(value) do
    json2octetstring(value, [])
  end

  defp json2octetstring([a1, a2 | rest], acc) do
    int = :erlang.list_to_integer([a1, a2], 16)
    json2octetstring(rest, [int | acc])
  end

  defp json2octetstring([], acc) do
    :lists.reverse(acc)
  end

  defp json2bitstring(value, length) do
    json2bitstring(value, length, [])
  end

  defp json2bitstring([a1, a2], length, acc) do
    int =
      :erlang.list_to_integer(
        [a1, a2],
        16
      ) >>> (8 - length)

    bin = :erlang.list_to_binary(:lists.reverse(acc))
    <<bin::binary, int::size(length)>>
  end

  defp json2bitstring([a1, a2 | rest], length, acc) do
    int = :erlang.list_to_integer([a1, a2], 16)
    json2bitstring(rest, length - 8, [int | acc])
  end

  defp json2bitstring([], 0, acc) do
    bin = :erlang.list_to_binary(:lists.reverse(acc))
    bin
  end

  defp bitstring2json(bitStr) when is_binary(bitStr) do
    octetstring2json(:erlang.binary_to_list(bitStr))
  end

  defp bitstring2json(bitStr) do
    pad = 8 - rem(bit_size(bitStr), 8)
    newStr = <<bitStr::bitstring, 0::size(pad)>>
    octetstring2json(:erlang.binary_to_list(newStr))
  end

  defp octetstring2json(list) when is_list(list) do
    :erlang.list_to_binary(
      for x <- list do
        num = :erlang.integer_to_list(x, 16)

        cond do
          length(num) == 1 ->
            ~c"0" ++ num

          true ->
            num
        end
      end
    )
  end

  defp oid2json(oid) when is_tuple(oid) do
    oidList = :erlang.tuple_to_list(oid)

    oidNumberStr =
      for v <- oidList do
        :erlang.integer_to_list(v)
      end

    oid2json(oidNumberStr, [])
  end

  defp oid2json([num | t], []) do
    oid2json(t, [num])
  end

  defp oid2json([num | t], acc) do
    oid2json(t, [num, ?. | acc])
  end

  defp oid2json([], acc) do
    :erlang.list_to_binary(:lists.reverse(acc))
  end

  defp json2oid(oidStr) when is_binary(oidStr) do
    oidList = :binary.split(oidStr, ["."], [:global])

    oidNumList =
      for num <- oidList do
        :erlang.binary_to_integer(num)
      end

    :erlang.list_to_tuple(oidNumList)
  end

  defp jer_bit_str2bitstr(compact = {_Unused, _Binary}, _NamedBitList) do
    jer_compact2bitstr(compact)
  end

  defp jer_bit_str2bitstr(int, _NamedBitList) when is_integer(int) do
    jer_compact2bitstr(int)
  end

  defp jer_bit_str2bitstr(bitList = [bit | _], _NamedBitList)
       when bit == 1 or bit == 0 do
    int =
      :erlang.list_to_integer(
        for b <- bitList do
          case b do
            0 ->
              ?0

            1 ->
              ?1
          end
        end,
        2
      )

    len = length(bitList)
    <<int::size(len)>>
  end

  defp jer_bit_str2bitstr([h | _] = bits, namedBitList) when is_atom(h) do
    jer_do_encode_named_bit_string(bits, namedBitList)
  end

  defp jer_bit_str2bitstr([{:bit, _} | _] = bits, namedBitList) do
    jer_do_encode_named_bit_string(bits, namedBitList)
  end

  defp jer_bit_str2bitstr([], _NamedBitList) do
    <<>>
  end

  defp jer_bit_str2bitstr(bitStr, _NamedBitList)
       when is_bitstring(bitStr) do
    bitStr
  end

  defp jer_compact2bitstr({unused, binary}) do
    size = bit_size(binary) - unused
    <<bitStr::size(size)-bitstring, _::bitstring>> = binary
    bitStr
  end

  defp jer_compact2bitstr(int) when is_integer(int) do
    jer_int2bitstr(int)
  end

  defp jer_compact2bitstr(bitList = [bit | _])
       when bit == 1 or
              bit == 0 do
    intStr = jer_skip_trailing_zeroes(bitList, [])
    int = :erlang.list_to_integer(intStr, 2)
    len = length(intStr)
    <<int::size(len)>>
  end

  defp jer_skip_trailing_zeroes([1 | rest], acc) do
    jer_skip_trailing_zeroes(rest, [?1 | acc])
  end

  defp jer_skip_trailing_zeroes([0 | rest], acc) do
    jer_skip_trailing_zeroes(rest, [?0 | acc])
  end

  defp jer_skip_trailing_zeroes([], [?0 | acc]) do
    jer_skip_trailing_zeroes([], acc)
  end

  defp jer_skip_trailing_zeroes([], acc) do
    :lists.reverse(acc)
  end

  defp jer_padbitstr(bitStr, fixedLength)
       when bit_size(bitStr) == fixedLength do
    bitStr
  end

  defp jer_padbitstr(bitStr, fixedLength)
       when bit_size(bitStr) < fixedLength do
    len = bit_size(bitStr)
    padLen = fixedLength - len
    <<bitStr::bitstring, 0::size(padLen)>>
  end

  defp jer_int2bitstr(int) when is_integer(int) and int >= 0 do
    jer_int2bitstr(int, <<>>)
  end

  defp jer_int2bitstr(0, acc) do
    acc
  end

  defp jer_int2bitstr(int, acc) do
    bit = int &&& 1

    jer_int2bitstr(
      int >>> 1,
      <<acc::bitstring, bit::size(1)>>
    )
  end

  defp jer_bitstr2compact(bitStr) do
    size = bit_size(bitStr)
    unused = 8 - rem(size, 8) &&& 7
    {unused, <<bitStr::bitstring, 0::size(unused)>>}
  end

  defp jer_do_encode_named_bit_string([firstVal | restVal], namedBitList) do
    toSetPos = jer_get_all_bitposes([firstVal | restVal], namedBitList, [])
    size = :lists.max(toSetPos) + 1
    bitList = jer_make_and_set_list(size, toSetPos, 0)
    jer_encode_bitstring(bitList)
  end

  defp jer_get_all_bitposes([{:bit, valPos} | rest], namedBitList, ack) do
    jer_get_all_bitposes(rest, namedBitList, [valPos | ack])
  end

  defp jer_get_all_bitposes([val | rest], namedBitList, ack)
       when is_atom(val) do
    case :lists.keyfind(val, 1, namedBitList) do
      {_ValName, valPos} ->
        jer_get_all_bitposes(rest, namedBitList, [valPos | ack])

      _ ->
        exit({:error, {:asn1, {:bitstring_namedbit, val}}})
    end
  end

  defp jer_get_all_bitposes([], _NamedBitList, ack) do
    :lists.sort(ack)
  end

  defp jer_make_and_set_list(0, [], _) do
    []
  end

  defp jer_make_and_set_list(0, _, _) do
    exit({:error, {:asn1, :bitstring_sizeconstraint}})
  end

  defp jer_make_and_set_list(len, [xPos | setPos], xPos) do
    [1 | jer_make_and_set_list(len - 1, setPos, xPos + 1)]
  end

  defp jer_make_and_set_list(len, [pos | setPos], xPos) do
    [0 | jer_make_and_set_list(len - 1, [pos | setPos], xPos + 1)]
  end

  defp jer_make_and_set_list(len, [], xPos) do
    [0 | jer_make_and_set_list(len - 1, [], xPos + 1)]
  end

  defp jer_encode_bitstring([b8, b7, b6, b5, b4, b3, b2, b1 | rest]) do
    val =
      b8 <<< 7 ||| b7 <<< 6 ||| b6 <<< 5 ||| b5 <<< 4 ||| b4 <<< 3 ||| b3 <<< 2 ||| b2 <<< 1 |||
        b1

    jer_encode_bitstring(rest, <<val>>)
  end

  defp jer_encode_bitstring(val) do
    jer_unused_bitlist(val, <<>>)
  end

  defp jer_encode_bitstring([b8, b7, b6, b5, b4, b3, b2, b1 | rest], acc) do
    val =
      b8 <<< 7 ||| b7 <<< 6 ||| b6 <<< 5 ||| b5 <<< 4 ||| b4 <<< 3 ||| b3 <<< 2 ||| b2 <<< 1 |||
        b1

    jer_encode_bitstring(rest, [acc, val])
  end

  defp jer_encode_bitstring([], acc) do
    acc
  end

  defp jer_encode_bitstring(rest, acc) do
    jer_unused_bitlist(rest, acc)
  end

  defp jer_unused_bitlist([], acc) do
    acc
  end

  defp jer_unused_bitlist([bit | rest], acc) do
    jer_unused_bitlist(
      rest,
      <<acc::bitstring, bit::size(1)>>
    )
  end

  defp jer_bitstr2names(bitStr, []) do
    bitStr
  end

  defp jer_bitstr2names(bitStr, nNL) do
    sortedList = :lists.keysort(2, nNL)
    jer_bitstr2names(bitStr, sortedList, 0, [])
  end

  defp jer_bitstr2names(<<1::size(1), bitStr::bitstring>>, [{name, pos} | rest], pos, acc) do
    jer_bitstr2names(bitStr, rest, pos + 1, [name | acc])
  end

  defp jer_bitstr2names(<<1::size(1), bitStr::bitstring>>, nNL, num, acc) do
    jer_bitstr2names(bitStr, nNL, num + 1, [{:bit, num} | acc])
  end

  defp jer_bitstr2names(<<0::size(1), bitStr::bitstring>>, [{_, num} | rest], num, acc) do
    jer_bitstr2names(bitStr, rest, num + 1, acc)
  end

  defp jer_bitstr2names(<<0::size(1), bitStr::bitstring>>, nNL, num, acc) do
    jer_bitstr2names(bitStr, nNL, num + 1, acc)
  end

  defp jer_bitstr2names(<<>>, _, _, acc) do
    :lists.reverse(acc)
  end
end
