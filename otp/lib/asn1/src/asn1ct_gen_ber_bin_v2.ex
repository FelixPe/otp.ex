defmodule :m_asn1ct_gen_ber_bin_v2 do
  use Bitwise
  import :asn1ct_gen, only: [emit: 1]
  require Record

  Record.defrecord(:r_module, :module,
    pos: :undefined,
    name: :undefined,
    defid: :undefined,
    tagdefault: :EXPLICIT,
    exports: {:exports, []},
    imports: {:imports, []},
    extensiondefault: :empty,
    typeorval: :undefined
  )

  Record.defrecord(:r_ExtensionAdditionGroup, :ExtensionAdditionGroup, number: :undefined)

  Record.defrecord(:r_SEQUENCE, :SEQUENCE,
    pname: false,
    tablecinf: false,
    extaddgroup: :undefined,
    components: []
  )

  Record.defrecord(:r_SET, :SET, pname: false, sorted: false, tablecinf: false, components: [])

  Record.defrecord(:r_ComponentType, :ComponentType,
    pos: :undefined,
    name: :undefined,
    typespec: :undefined,
    prop: :undefined,
    tags: :undefined,
    textual_order: :undefined
  )

  Record.defrecord(:r_ObjectClassFieldType, :ObjectClassFieldType,
    classname: :undefined,
    class: :undefined,
    fieldname: :undefined,
    type: :undefined
  )

  Record.defrecord(:r_typedef, :typedef,
    checked: false,
    pos: :undefined,
    name: :undefined,
    typespec: :undefined
  )

  Record.defrecord(:r_classdef, :classdef,
    checked: false,
    pos: :undefined,
    name: :undefined,
    module: :undefined,
    typespec: :undefined
  )

  Record.defrecord(:r_valuedef, :valuedef,
    checked: false,
    pos: :undefined,
    name: :undefined,
    type: :undefined,
    value: :undefined,
    module: :undefined
  )

  Record.defrecord(:r_ptypedef, :ptypedef,
    checked: false,
    pos: :undefined,
    name: :undefined,
    args: :undefined,
    typespec: :undefined
  )

  Record.defrecord(:r_pvaluedef, :pvaluedef,
    checked: false,
    pos: :undefined,
    name: :undefined,
    args: :undefined,
    type: :undefined,
    value: :undefined
  )

  Record.defrecord(:r_pvaluesetdef, :pvaluesetdef,
    checked: false,
    pos: :undefined,
    name: :undefined,
    args: :undefined,
    type: :undefined,
    valueset: :undefined
  )

  Record.defrecord(:r_pobjectdef, :pobjectdef,
    checked: false,
    pos: :undefined,
    name: :undefined,
    args: :undefined,
    class: :undefined,
    def: :undefined
  )

  Record.defrecord(:r_pobjectsetdef, :pobjectsetdef,
    checked: false,
    pos: :undefined,
    name: :undefined,
    args: :undefined,
    class: :undefined,
    def: :undefined
  )

  Record.defrecord(:r_Constraint, :Constraint,
    SingleValue: :no,
    SizeConstraint: :no,
    ValueRange: :no,
    PermittedAlphabet: :no,
    ContainedSubtype: :no,
    TypeConstraint: :no,
    InnerSubtyping: :no,
    e: :no,
    Other: :no
  )

  Record.defrecord(:r_simpletableattributes, :simpletableattributes,
    objectsetname: :undefined,
    c_name: :undefined,
    c_index: :undefined,
    usedclassfield: :undefined,
    uniqueclassfield: :undefined,
    valueindex: :undefined
  )

  Record.defrecord(:r_type, :type,
    tag: [],
    def: :undefined,
    constraint: [],
    tablecinf: [],
    inlined: :no
  )

  Record.defrecord(:r_objectclass, :objectclass,
    fields: [],
    syntax: :undefined
  )

  Record.defrecord(:r_Object, :Object, classname: :undefined, gen: true, def: :undefined)

  Record.defrecord(:r_ObjectSet, :ObjectSet,
    class: :undefined,
    gen: true,
    uniquefname: :undefined,
    set: :undefined
  )

  Record.defrecord(:r_tag, :tag,
    class: :undefined,
    number: :undefined,
    type: :undefined,
    form: 32
  )

  Record.defrecord(:r_cmap, :cmap,
    single_value: :no,
    contained_subtype: :no,
    value_range: :no,
    size: :no,
    permitted_alphabet: :no,
    type_constraint: :no,
    inner_subtyping: :no
  )

  Record.defrecord(:r_EXTENSIONMARK, :EXTENSIONMARK,
    pos: :undefined,
    val: :undefined
  )

  Record.defrecord(:r_SymbolsFromModule, :SymbolsFromModule,
    symbols: :undefined,
    module: :undefined,
    objid: :undefined
  )

  Record.defrecord(:r_Externaltypereference, :Externaltypereference,
    pos: :undefined,
    module: :undefined,
    type: :undefined
  )

  Record.defrecord(:r_Externalvaluereference, :Externalvaluereference,
    pos: :undefined,
    module: :undefined,
    value: :undefined
  )

  Record.defrecord(:r_seqtag, :seqtag, pos: :undefined, module: :undefined, val: :undefined)

  Record.defrecord(:r_state, :state,
    module: :undefined,
    mname: :undefined,
    tname: :undefined,
    erule: :undefined,
    parameters: [],
    inputmodules: [],
    abscomppath: [],
    recordtopname: [],
    options: :undefined,
    sourcedir: :undefined,
    error_context: :undefined
  )

  Record.defrecord(:r_gen, :gen,
    erule: :ber,
    der: false,
    jer: false,
    aligned: false,
    rec_prefix: ~c"",
    macro_prefix: ~c"",
    pack: :record,
    options: []
  )

  Record.defrecord(:r_abst, :abst,
    name: :undefined,
    types: :undefined,
    values: :undefined,
    ptypes: :undefined,
    classes: :undefined,
    objects: :undefined,
    objsets: :undefined
  )

  Record.defrecord(:r_gen_state, :gen_state,
    active: false,
    prefix: :undefined,
    inc_tag_pattern: :undefined,
    tag_pattern: :undefined,
    inc_type_pattern: :undefined,
    type_pattern: :undefined,
    func_name: :undefined,
    namelist: :undefined,
    tobe_refed_funcs: [],
    gen_refed_funcs: [],
    generated_functions: [],
    suffix_index: 1,
    current_suffix_index: :undefined
  )

  def dialyzer_suppressions(_) do
    case :asn1ct.use_legacy_types() do
      false ->
        :ok

      true ->
        suppress({:ber, :encode_bit_string, 4})
    end

    suppress({:ber, :decode_selective, 2})
    emit([~c"    ok.", :nl])
  end

  defp suppress({m, f, a} = mFA) do
    case :asn1ct_func.is_used(mFA) do
      false ->
        :ok

      true ->
        args =
          for i <- :lists.seq(1, a) do
            :lists.concat([~c"element(", i, ~c", Arg)"])
          end

        emit([~c"    ", {:call, m, f, args}, :com, :nl])
    end
  end

  def gen_encode(erules, r_typedef() = d) do
    gen_encode_user(erules, r_typedef() = d, true)
  end

  def gen_encode(erules, typename, type)
      when elem(type, 0) === :type do
    innerType = :asn1ct_gen.get_inner(r_type(type, :def))

    objFun =
      case :lists.keysearch(:objfun, 1, r_type(type, :tablecinf)) do
        {:value, {_, _Name}} ->
          ~c", ObjFun"

        false ->
          ~c""
      end

    case :asn1ct_gen.type(innerType) do
      {:constructed, :bif} ->
        func = {:asis, enc_func(:asn1ct_gen.list2name(typename))}

        emit([
          :nl,
          :nl,
          :nl,
          ~c"%%================================",
          :nl,
          ~c"%%  ",
          :asn1ct_gen.list2name(typename),
          :nl,
          ~c"%%================================",
          :nl,
          func,
          ~c"(Val, TagIn",
          objFun,
          ~c") ->",
          :nl,
          ~c"   "
        ])

        :asn1ct_gen.gen_encode_constructed(erules, typename, innerType, type)

      _ ->
        true
    end
  end

  def gen_encode(erules, tname, r_ComponentType(name: cname, typespec: type)) do
    newTname = [cname | tname]
    newType = r_type(type, tag: [])
    gen_encode(erules, newTname, newType)
  end

  defp gen_encode_user(erules, r_typedef() = d, wrapper) do
    typename = [r_typedef(d, :name)]
    type = r_typedef(d, :typespec)
    innerType = :asn1ct_gen.get_inner(r_type(type, :def))
    emit([:nl, :nl, ~c"%%================================"])
    emit([:nl, ~c"%%  ", typename])
    emit([:nl, ~c"%%================================", :nl])
    funcName = {:asis, enc_func(:asn1ct_gen.list2name(typename))}

    case wrapper do
      true ->
        oTag = r_type(type, :tag)

        tag0 =
          for r_tag(class: class, form: form, number: number) <- oTag do
            encode_tag_val(decode_class(class), form, number)
          end

        tag = :lists.reverse(tag0)

        emit([
          funcName,
          ~c"(Val) ->",
          :nl,
          ~c"    ",
          funcName,
          ~c"(Val, ",
          {:asis, tag},
          ~c").",
          :nl,
          :nl
        ])

      false ->
        :ok
    end

    emit([funcName, ~c"(Val, TagIn) ->", :nl])
    currentMod = :erlang.get(:currmod)

    case :asn1ct_gen.type(innerType) do
      {:constructed, :bif} ->
        :asn1ct_gen.gen_encode_constructed(erules, typename, innerType, d)

      {:primitive, :bif} ->
        gen_encode_prim(:ber, type, ~c"TagIn", ~c"Val")
        emit([~c".", :nl])

      r_Externaltypereference(module: ^currentMod, type: etype) ->
        emit([~c"   ", {:asis, enc_func(etype)}, ~c"(Val, TagIn).", :nl])

      r_Externaltypereference(module: emod, type: etype) ->
        emit([~c"   ", {:asis, emod}, ~c":", {:asis, enc_func(etype)}, ~c"(Val, TagIn).", :nl])

      :ASN1_OPEN_TYPE ->
        emit([~c"%% OPEN TYPE", :nl])
        gen_encode_prim(:ber, r_type(type, def: :ASN1_OPEN_TYPE), ~c"TagIn", ~c"Val")
        emit([~c".", :nl])
    end
  end

  def gen_encode_prim(_Erules, r_type() = d, doTag, value) do
    bitStringConstraint = get_size_constraint(r_type(d, :constraint))

    maxBitStrSize =
      case bitStringConstraint do
        [] ->
          :none

        {_, :MAX} ->
          :none

        {_, max} ->
          max

        max when is_integer(max) ->
          max
      end

    :asn1ct_name.new(:enumval)

    type =
      case r_type(d, :def) do
        :"OCTET STRING" ->
          :restricted_string

        :ObjectDescriptor ->
          :restricted_string

        :NumericString ->
          :restricted_string

        :TeletexString ->
          :restricted_string

        :T61String ->
          :restricted_string

        :VideotexString ->
          :restricted_string

        :GraphicString ->
          :restricted_string

        :VisibleString ->
          :restricted_string

        :GeneralString ->
          :restricted_string

        :PrintableString ->
          :restricted_string

        :IA5String ->
          :restricted_string

        :UTCTime ->
          :restricted_string

        :GeneralizedTime ->
          :restricted_string

        other ->
          other
      end

    case type do
      :restricted_string ->
        call(:encode_restricted_string, [value, doTag])

      :BOOLEAN ->
        call(:encode_boolean, [value, doTag])

      :INTEGER ->
        call(:encode_integer, [value, doTag])

      {:INTEGER, namedNumberList} ->
        call(
          :encode_integer,
          [value, {:asis, namedNumberList}, doTag]
        )

      {:ENUMERATED, namedNumberList = {_, _}} ->
        emit([~c"case ", value, ~c" of", :nl])
        emit_enc_enumerated_cases(namedNumberList, doTag)

      {:ENUMERATED, namedNumberList} ->
        emit([~c"case ", value, ~c" of", :nl])
        emit_enc_enumerated_cases(namedNumberList, doTag)

      :REAL ->
        :asn1ct_name.new(:realval)
        :asn1ct_name.new(:realsize)

        emit([
          ~c"begin",
          :nl,
          {:curr, :realval},
          ~c" = ",
          {:call, :real_common, :ber_encode_real, [value]},
          :com,
          :nl,
          {:curr, :realsize},
          ~c" = ",
          {:call, :erlang, :byte_size, [{:curr, :realval}]},
          :com,
          :nl,
          {:call, :ber, :encode_tags, [doTag, {:curr, :realval}, {:curr, :realsize}]},
          :nl,
          ~c"end"
        ])

      {:"BIT STRING", []} ->
        case :asn1ct.use_legacy_types() do
          false when maxBitStrSize === :none ->
            call(:encode_unnamed_bit_string, [value, doTag])

          false ->
            call(
              :encode_unnamed_bit_string,
              [{:asis, maxBitStrSize}, value, doTag]
            )

          true ->
            call(
              :encode_bit_string,
              [{:asis, bitStringConstraint}, value, {:asis, []}, doTag]
            )
        end

      {:"BIT STRING", namedNumberList} ->
        case :asn1ct.use_legacy_types() do
          false when maxBitStrSize === :none ->
            call(
              :encode_named_bit_string,
              [value, {:asis, namedNumberList}, doTag]
            )

          false ->
            call(
              :encode_named_bit_string,
              [{:asis, maxBitStrSize}, value, {:asis, namedNumberList}, doTag]
            )

          true ->
            call(
              :encode_bit_string,
              [{:asis, bitStringConstraint}, value, {:asis, namedNumberList}, doTag]
            )
        end

      :NULL ->
        call(:encode_null, [value, doTag])

      :"OBJECT IDENTIFIER" ->
        call(:encode_object_identifier, [value, doTag])

      :"RELATIVE-OID" ->
        call(:encode_relative_oid, [value, doTag])

      :UniversalString ->
        call(:encode_universal_string, [value, doTag])

      :UTF8String ->
        call(:encode_UTF8_string, [value, doTag])

      :BMPString ->
        call(:encode_BMP_string, [value, doTag])

      :ASN1_OPEN_TYPE ->
        call(:encode_open_type, [value, doTag])
    end
  end

  defp emit_enc_enumerated_cases({l1, l2}, tags) do
    emit_enc_enumerated_cases(l1 ++ l2, tags, :ext)
  end

  defp emit_enc_enumerated_cases(l, tags) do
    emit_enc_enumerated_cases(l, tags, :noext)
  end

  defp emit_enc_enumerated_cases([{enumName, enumVal} | t], tags, ext) do
    {bytes, len} = encode_integer(enumVal)

    emit([
      {:asis, enumName},
      ~c" -> ",
      {:call, :ber, :encode_tags, [tags, {:asis, bytes}, len]},
      ~c";",
      :nl
    ])

    emit_enc_enumerated_cases(t, tags, ext)
  end

  defp emit_enc_enumerated_cases([], _Tags, _Ext) do
    emit([
      {:curr, :enumval},
      ~c" -> exit({error,{asn1, {enumerated_not_in_range,",
      {:curr, :enumval},
      ~c"}}})"
    ])

    emit([:nl, ~c"end"])
  end

  defp encode_integer(val) do
    bytes =
      cond do
        val >= 0 ->
          encode_integer_pos(val, [])

        true ->
          encode_integer_neg(val, [])
      end

    {bytes, length(bytes)}
  end

  defp encode_integer_pos(0, [b | _Acc] = l) when b < 128 do
    l
  end

  defp encode_integer_pos(n, acc) do
    encode_integer_pos(n >>> 8, [n &&& 255 | acc])
  end

  defp encode_integer_neg(-1, [b1 | _T] = l) when b1 > 127 do
    l
  end

  defp encode_integer_neg(n, acc) do
    encode_integer_neg(n >>> 8, [n &&& 255 | acc])
  end

  def gen_decode(erules, type) when elem(type, 0) === :typedef do
    def__ = r_typedef(type, :typespec)
    innerTag = r_type(def__, :tag)

    tag =
      for x <- innerTag do
        decode_class(r_tag(x, :class)) <<< (10 + r_tag(x, :number))
      end

    funcName0 =
      case {:asn1ct.get_gen_state_field(:active), :asn1ct.get_gen_state_field(:prefix)} do
        {true, pref} ->
          case :asn1ct.current_sindex() do
            i when is_integer(i) and i > 0 ->
              [pref, r_typedef(type, :name), ~c"_", i]

            _ ->
              [pref, r_typedef(type, :name)]
          end

        {_, _} ->
          [~c"dec_", r_typedef(type, :name)]
      end

    funcName = {:asis, :erlang.list_to_atom(:lists.concat(funcName0))}

    emit([
      :nl,
      :nl,
      funcName,
      ~c"(Tlv) ->",
      :nl,
      ~c"   ",
      funcName,
      ~c"(Tlv, ",
      {:asis, tag},
      ~c").",
      :nl,
      :nl,
      funcName,
      ~c"(Tlv, TagIn) ->",
      :nl
    ])

    gen_decode_user(erules, type)
  end

  def gen_inc_decode(erules, type) when elem(type, 0) === :typedef do
    prefix = :asn1ct.get_gen_state_field(:prefix)
    suffix = :asn1ct_gen.index2suffix(:asn1ct.current_sindex())
    funcName0 = [prefix, r_typedef(type, :name), suffix]
    funcName = {:asis, :erlang.list_to_atom(:lists.concat(funcName0))}
    emit([:nl, :nl, funcName, ~c"(Tlv, TagIn) ->", :nl])
    gen_decode_user(erules, type)
  end

  def gen_decode_selected(erules, type, funcName) do
    emit([funcName, ~c"(Bin) ->", :nl])
    patterns = :asn1ct.read_config_data(:partial_decode)

    pattern =
      case :lists.keysearch(funcName, 1, patterns) do
        {:value, {_, p}} ->
          p

        false ->
          exit({:error, {:internal, :no_pattern_saved}})
      end

    emit([
      ~c"  case ",
      {:call, :ber, :decode_selective, [{:asis, pattern}, ~c"Bin"]},
      ~c" of",
      :nl,
      ~c"    {ok,Bin2} when is_binary(Bin2) ->",
      :nl,
      ~c"      {Tlv,_} = ",
      {:call, :ber, :ber_decode_nif, [~c"Bin2"]},
      :com,
      :nl
    ])

    emit(~c"{ok,")
    gen_decode_selected_type(erules, type)
    emit([~c"};", :nl, ~c"    Err -> exit({error,{selective_decode,Err}})", :nl, ~c"  end.", :nl])
  end

  defp gen_decode_selected_type(_Erules, typeDef) do
    def__ = r_typedef(typeDef, :typespec)
    innerType = :asn1ct_gen.get_inner(r_type(def__, :def))
    bytesVar = ~c"Tlv"

    tag =
      for x <- r_type(def__, :tag) do
        decode_class(r_tag(x, :class)) <<< (10 + r_tag(x, :number))
      end

    case :asn1ct_gen.type(innerType) do
      :ASN1_OPEN_TYPE ->
        :asn1ct_name.new(:len)
        gen_dec_prim(r_type(def__, def: :ASN1_OPEN_TYPE), bytesVar, tag)

      {:primitive, :bif} ->
        :asn1ct_name.new(:len)
        gen_dec_prim(def__, bytesVar, tag)

      {:constructed, :bif} ->
        topType =
          case r_typedef(typeDef, :name) do
            a when is_atom(a) ->
              [a]

            n ->
              n
          end

        decFunName = :lists.concat([~c"'", :dec, ~c"_", :asn1ct_gen.list2name(topType), ~c"'"])
        emit([decFunName, ~c"(", bytesVar, ~c", ", {:asis, tag}, ~c")"])

      theType ->
        decFunName = mkfuncname(theType, :dec)
        emit([decFunName, ~c"(", bytesVar, ~c", ", {:asis, tag}, ~c")"])
    end
  end

  def gen_decode(erules, typename, type)
      when elem(type, 0) === :type do
    innerType = :asn1ct_gen.get_inner(r_type(type, :def))

    functionName =
      case :asn1ct.get_gen_state_field(:active) do
        true ->
          pattern = :asn1ct.get_gen_state_field(:namelist)

          suffix =
            case :asn1ct.maybe_saved_sindex(
                   typename,
                   pattern
                 ) do
              i when is_integer(i) and i > 0 ->
                :lists.concat([~c"_", i])

              _ ->
                ~c""
            end

          :lists.concat([~c"'dec-inc-", :asn1ct_gen.list2name(typename), suffix])

        _ ->
          :lists.concat([~c"'dec_", :asn1ct_gen.list2name(typename)])
      end

    case :asn1ct_gen.type(innerType) do
      {:constructed, :bif} ->
        objFun =
          case r_type(type, :tablecinf) do
            [{:objfun, _} | _R] ->
              ~c", ObjFun"

            _ ->
              ~c""
          end

        emit([functionName, ~c"'(Tlv, TagIn", objFun, ~c") ->", :nl])
        :asn1ct_gen.gen_decode_constructed(erules, typename, innerType, type)

      rec when elem(rec, 0) === :Externaltypereference ->
        case {typename, :asn1ct.get_gen_state_field(:namelist)} do
          {[cname | _], [{cname, _} | _]} ->
            case :asn1ct.is_function_generated(typename) do
              true ->
                :ok

              _ ->
                :asn1ct.generated_refed_func(typename)
                r_Externaltypereference(module: m, type: name) = rec
                typeDef = :asn1_db.dbget(m, name)
                gen_decode(erules, typeDef)
            end

          _ ->
            true
        end

      _ ->
        true
    end
  end

  def gen_decode(erules, tname, r_ComponentType(name: cname, typespec: type)) do
    newTname = [cname | tname]
    newType = r_type(type, tag: [])

    case {:asn1ct.get_gen_state_field(:active), :asn1ct.get_tobe_refed_func(newTname)} do
      {true, {_, nameList}} ->
        :asn1ct.update_gen_state(:namelist, nameList)
        gen_decode(erules, newTname, newType)

      {no, _} when no == false or no == :undefined ->
        gen_decode(erules, newTname, newType)

      _ ->
        :ok
    end
  end

  defp gen_decode_user(erules, d) when elem(d, 0) === :typedef do
    typename = [r_typedef(d, :name)]
    def__ = r_typedef(d, :typespec)
    innerType = :asn1ct_gen.get_inner(r_type(def__, :def))
    bytesVar = ~c"Tlv"

    case :asn1ct_gen.type(innerType) do
      :ASN1_OPEN_TYPE ->
        :asn1ct_name.new(:len)
        gen_dec_prim(r_type(def__, def: :ASN1_OPEN_TYPE), bytesVar, {:string, ~c"TagIn"})
        emit([~c".", :nl, :nl])

      {:primitive, :bif} ->
        :asn1ct_name.new(:len)
        gen_dec_prim(def__, bytesVar, {:string, ~c"TagIn"})
        emit([~c".", :nl, :nl])

      {:constructed, :bif} ->
        :asn1ct.update_namelist(r_typedef(d, :name))
        :asn1ct_gen.gen_decode_constructed(erules, typename, innerType, d)

      theType ->
        decFunName = mkfuncname(theType, :dec)
        emit([decFunName, ~c"(", bytesVar, ~c", TagIn).", :nl, :nl])
    end
  end

  def gen_dec_prim(att, bytesVar, doTag) do
    typename = r_type(att, :def)
    constraint = get_size_constraint(r_type(att, :constraint))
    intConstr = int_constr(r_type(att, :constraint))

    newTypeName =
      case typename do
        :NumericString ->
          :restricted_string

        :TeletexString ->
          :restricted_string

        :T61String ->
          :restricted_string

        :VideotexString ->
          :restricted_string

        :GraphicString ->
          :restricted_string

        :VisibleString ->
          :restricted_string

        :GeneralString ->
          :restricted_string

        :PrintableString ->
          :restricted_string

        :IA5String ->
          :restricted_string

        :ObjectDescriptor ->
          :restricted_string

        :UTCTime ->
          :restricted_string

        :GeneralizedTime ->
          :restricted_string

        :"OCTET STRING" ->
          case :asn1ct.use_legacy_types() do
            true ->
              :restricted_string

            false ->
              typename
          end

        _ ->
          typename
      end

    tagStr =
      case doTag do
        {:string, tag1} ->
          tag1

        _ when is_list(doTag) ->
          {:asis, doTag}
      end

    case newTypeName do
      :BOOLEAN ->
        call(:decode_boolean, [bytesVar, tagStr])

      :INTEGER ->
        check_constraint(:decode_integer, [bytesVar, tagStr], intConstr, :identity, :identity)

      {:INTEGER, nNL} ->
        check_constraint(:decode_integer, [bytesVar, tagStr], intConstr, :identity, fn val ->
          :asn1ct_name.new(:val)
          emit([{:curr, :val}, ~c" = "])
          val.()
          emit([:com, :nl, {:call, :ber, :number2name, [{:curr, :val}, {:asis, nNL}]}])
        end)

      {:ENUMERATED, nNL} ->
        gen_dec_enumerated(bytesVar, nNL, tagStr)

      :REAL ->
        :asn1ct_name.new(:tmpbuf)

        emit([
          ~c"begin",
          :nl,
          {:curr, :tmpbuf},
          ~c" = ",
          {:call, :ber, :match_tags, [bytesVar, tagStr]},
          :com,
          :nl,
          {:call, :real_common, :decode_real, [{:curr, :tmpbuf}]},
          :nl,
          ~c"end",
          :nl
        ])

      {:"BIT STRING", nNL} ->
        gen_dec_bit_string(bytesVar, constraint, nNL, tagStr)

      :NULL ->
        call(:decode_null, [bytesVar, tagStr])

      :"OBJECT IDENTIFIER" ->
        call(:decode_object_identifier, [bytesVar, tagStr])

      :"RELATIVE-OID" ->
        call(:decode_relative_oid, [bytesVar, tagStr])

      :"OCTET STRING" ->
        check_constraint(
          :decode_octet_string,
          [bytesVar, tagStr],
          constraint,
          {:erlang, :byte_size},
          :identity
        )

      :restricted_string ->
        check_constraint(
          :decode_restricted_string,
          [bytesVar, tagStr],
          constraint,
          {:erlang, :byte_size},
          fn val ->
            emit(~c"binary_to_list(")
            val.()
            emit(~c")")
          end
        )

      :UniversalString ->
        check_constraint(
          :decode_universal_string,
          [bytesVar, tagStr],
          constraint,
          {:erlang, :length},
          :identity
        )

      :UTF8String ->
        call(:decode_UTF8_string, [bytesVar, tagStr])

      :BMPString ->
        check_constraint(
          :decode_BMP_string,
          [bytesVar, tagStr],
          constraint,
          {:erlang, :length},
          :identity
        )

      :ASN1_OPEN_TYPE ->
        call(:decode_open_type_as_binary, [bytesVar, tagStr])
    end
  end

  defp int_constr(c) do
    case :asn1ct_imm.effective_constraint(:integer, c) do
      [{_, []}] ->
        []

      [{:ValueRange, {:MIN, _}}] ->
        []

      [{:ValueRange, {_, _} = range}] ->
        range

      [{:SingleValue, sv}] ->
        sv

      [] ->
        []
    end
  end

  defp gen_dec_bit_string(bytesVar, _Constraint, [_ | _] = nNL, tagStr) do
    call(
      :decode_named_bit_string,
      [bytesVar, {:asis, nNL}, tagStr]
    )
  end

  defp gen_dec_bit_string(bytesVar, constraint, [], tagStr) do
    case :asn1ct.get_bit_string_format() do
      :compact ->
        check_constraint(
          :decode_compact_bit_string,
          [bytesVar, tagStr],
          constraint,
          {:ber, :compact_bit_string_size},
          :identity
        )

      :legacy ->
        check_constraint(
          :decode_native_bit_string,
          [bytesVar, tagStr],
          constraint,
          {:erlang, :bit_size},
          fn val ->
            :asn1ct_name.new(:val)
            emit([{:curr, :val}, ~c" = "])
            val.()
            emit([:com, :nl, {:call, :ber, :native_to_legacy_bit_string, [{:curr, :val}]}])
          end
        )

      :bitstring ->
        check_constraint(
          :decode_native_bit_string,
          [bytesVar, tagStr],
          constraint,
          {:erlang, :bit_size},
          :identity
        )
    end
  end

  defp check_constraint(f, args, constr, preConstr0, returnVal0) do
    preConstr =
      case preConstr0 do
        :identity ->
          fn v ->
            v
          end

        {mod, name} ->
          fn v ->
            :asn1ct_name.new(:c)
            emit([{:curr, :c}, ~c" = ", {:call, mod, name, [v]}, :com, :nl])
            {:curr, :c}
          end
      end

    returnVal =
      case returnVal0 do
        :identity ->
          fn val ->
            val.()
          end

        _ ->
          returnVal0
      end

    case constr do
      [] when returnVal0 === :identity ->
        call(f, args)

      [] ->
        emit([~c"begin", :nl])

        returnVal.(fn ->
          call(f, args)
        end)

        emit([:nl, ~c"end", :nl])

      _ ->
        :asn1ct_name.new(:val)
        emit([~c"begin", :nl, {:curr, :val}, ~c" = ", {:call, :ber, f, args}, :com, :nl])
        preVal0 = :asn1ct_gen.mk_var(:asn1ct_name.curr(:val))
        preVal = preConstr.(preVal0)
        emit(~c"if ")

        case constr do
          {min, max} ->
            emit([{:asis, min}, ~c" =< ", preVal, ~c", ", preVal, ~c" =< ", {:asis, max}])

          sv when is_integer(sv) ->
            emit([preVal, ~c" =:= ", {:asis, sv}])
        end

        emit([~c" ->", :nl])

        returnVal.(fn ->
          emit(preVal0)
        end)

        emit([
          ~c";",
          :nl,
          ~c"true ->",
          :nl,
          ~c"exit({error,{asn1,bad_range}})",
          :nl,
          ~c"end",
          :nl,
          ~c"end"
        ])
    end
  end

  defp gen_dec_enumerated(bytesVar, nNL0, tagStr) do
    :asn1ct_name.new(:enum)
    emit([~c"case ", {:call, :ber, :decode_integer, [bytesVar, tagStr]}, ~c" of", :nl])

    nNL =
      case nNL0 do
        {l1, l2} ->
          l1 ++ l2 ++ [:accept]

        [_ | _] ->
          nNL0 ++ [:error]
      end

    gen_dec_enumerated_1(nNL)
    emit(~c"end")
  end

  defp gen_dec_enumerated_1([:accept]) do
    :asn1ct_name.new(:default)
    emit([{:curr, :default}, ~c" -> {asn1_enum,", {:curr, :default}, ~c"}", :nl])
  end

  defp gen_dec_enumerated_1([:error]) do
    :asn1ct_name.new(:default)

    emit([
      {:curr, :default},
      ~c" -> exit({error,{asn1,{illegal_enumerated,",
      {:curr, :default},
      ~c"}}})",
      :nl
    ])
  end

  defp gen_dec_enumerated_1([{v, k} | t]) do
    emit([{:asis, k}, ~c" -> ", {:asis, v}, ~c";", :nl])
    gen_dec_enumerated_1(t)
  end

  def gen_obj_code(erules, _Module, obj)
      when elem(obj, 0) === :typedef do
    objName = r_typedef(obj, :name)
    def__ = r_typedef(obj, :typespec)
    r_Externaltypereference(module: m, type: clName) = r_Object(def__, :classname)
    class = :asn1_db.dbget(m, clName)
    {:object, _, fields} = r_Object(def__, :def)

    emit([
      :nl,
      :nl,
      :nl,
      ~c"%%================================",
      :nl,
      ~c"%%  ",
      objName,
      :nl,
      ~c"%%================================",
      :nl
    ])

    encConstructed = gen_encode_objectfields(clName, get_class_fields(class), objName, fields, [])
    emit(:nl)
    gen_encode_constr_type(erules, encConstructed)
    emit(:nl)
    decConstructed = gen_decode_objectfields(clName, get_class_fields(class), objName, fields, [])
    emit(:nl)
    gen_decode_constr_type(erules, decConstructed)
    emit_tlv_format_function()
  end

  defp gen_encode_objectfields(
         className,
         [{:typefield, name, optOrMand} | rest],
         objName,
         objectFields,
         constrAcc
       ) do
    emitFuncClause = fn arg ->
      emit([
        {:asis, enc_func(objName)},
        ~c"(",
        {:asis, name},
        ~c", ",
        arg,
        ~c", _RestPrimFieldName) ->",
        :nl
      ])
    end

    maybeConstr =
      case {get_object_field(
              name,
              objectFields
            ), optOrMand} do
        {false, :OPTIONAL} ->
          emitFuncClause.(~c"Val")
          emit([~c"   {Val,0}"])
          []

        {false, {:DEFAULT, defaultType}} ->
          emitFuncClause.(~c"Val")
          gen_encode_default_call(className, name, defaultType)

        {{^name, typeSpec}, _} ->
          emitFuncClause.(~c"Val")
          gen_encode_field_call(objName, name, typeSpec)
      end

    case more_genfields(rest) do
      true ->
        emit([~c";", :nl])

      false ->
        emit([~c".", :nl])
    end

    gen_encode_objectfields(className, rest, objName, objectFields, maybeConstr ++ constrAcc)
  end

  defp gen_encode_objectfields(
         className,
         [{:objectfield, name, _, _, optOrMand} | rest],
         objName,
         objectFields,
         constrAcc
       ) do
    currentMod = :erlang.get(:currmod)

    emitFuncClause = fn args ->
      emit([{:asis, enc_func(objName)}, ~c"(", {:asis, name}, ~c", ", args, ~c") ->", :nl])
    end

    case {get_object_field(name, objectFields), optOrMand} do
      {false, :OPTIONAL} ->
        emitFuncClause.(~c"_,_")
        emit([~c"  exit({error,{'use of missing field in object', ", {:asis, name}, ~c"}})"])

      {false, {:DEFAULT, _DefaultObject}} ->
        exit({:error, {:asn1, {~c"not implemented yet", name}}})

      {{^name, r_Externalvaluereference(module: ^currentMod, value: typeName)}, _} ->
        emitFuncClause.(~c" Val, [H|T]")
        emit([indent(3), {:asis, enc_func(typeName)}, ~c"(H, Val, T)"])

      {{^name, r_Externalvaluereference(module: m, value: typeName)}, _} ->
        emitFuncClause.(~c" Val, [H|T]")
        emit([indent(3), {:asis, m}, ~c":", {:asis, enc_func(typeName)}, ~c"(H, Val, T)"])

      {{^name, r_typedef(name: typeName)}, _} when is_atom(typeName) ->
        emitFuncClause.(~c" Val, [H|T]")
        emit([indent(3), {:asis, enc_func(typeName)}, ~c"(H, Val, T)"])
    end

    case more_genfields(rest) do
      true ->
        emit([~c";", :nl])

      false ->
        emit([~c".", :nl])
    end

    gen_encode_objectfields(className, rest, objName, objectFields, constrAcc)
  end

  defp gen_encode_objectfields(className, [_C | cs], o, oF, acc) do
    gen_encode_objectfields(className, cs, o, oF, acc)
  end

  defp gen_encode_objectfields(_, [], _, _, acc) do
    acc
  end

  defp gen_encode_constr_type(erules, [typeDef | rest])
       when elem(typeDef, 0) === :typedef do
    case is_already_generated(:enc, r_typedef(typeDef, :name)) do
      true ->
        :ok

      false ->
        gen_encode_user(erules, typeDef, false)
    end

    gen_encode_constr_type(erules, rest)
  end

  defp gen_encode_constr_type(_, []) do
    :ok
  end

  defp gen_encode_field_call(_ObjName, _FieldName, r_Externaltypereference(module: m, type: t)) do
    currentMod = :erlang.get(:currmod)
    tDef = :asn1_db.dbget(m, t)
    def__ = r_typedef(tDef, :typespec)
    oTag = r_type(def__, :tag)

    tag =
      for x <- oTag do
        encode_tag_val(decode_class(r_tag(x, :class)), r_tag(x, :form), r_tag(x, :number))
      end

    cond do
      m == currentMod ->
        emit([~c"   ", {:asis, enc_func(t)}, ~c"(Val, ", {:asis, tag}, ~c")"])
        []

      true ->
        emit([~c"   ", {:asis, m}, ~c":", {:asis, enc_func(t)}, ~c"(Val, ", {:asis, tag}, ~c")"])
        []
    end
  end

  defp gen_encode_field_call(objName, fieldName, type) do
    def__ = r_typedef(type, :typespec)
    oTag = r_type(def__, :tag)

    tag =
      for x <- oTag do
        encode_tag_val(decode_class(r_tag(x, :class)), r_tag(x, :form), r_tag(x, :number))
      end

    case r_typedef(type, :name) do
      {:primitive, :bif} ->
        gen_encode_prim(:ber, def__, {:asis, :lists.reverse(tag)}, ~c"Val")
        []

      {:constructed, :bif} ->
        name = :lists.concat([objName, :_, fieldName])
        emit([~c"   ", {:asis, enc_func(name)}, ~c"(Val,", {:asis, tag}, ~c")"])
        [r_typedef(type, name: :erlang.list_to_atom(name))]

      {extMod, typeName} ->
        emit([
          ~c"   ",
          {:asis, extMod},
          ~c":",
          {:asis, enc_func(typeName)},
          ~c"(Val,",
          {:asis, tag},
          ~c")"
        ])

        []

      typeName ->
        emit([~c"   ", {:asis, enc_func(typeName)}, ~c"(Val,", {:asis, tag}, ~c")"])
        []
    end
  end

  defp gen_encode_default_call(className, fieldName, type) do
    currentMod = :erlang.get(:currmod)
    innerType = :asn1ct_gen.get_inner(r_type(type, :def))
    oTag = r_type(type, :tag)

    tag =
      for x <- oTag do
        encode_tag_val(decode_class(r_tag(x, :class)), r_tag(x, :form), r_tag(x, :number))
      end

    case :asn1ct_gen.type(innerType) do
      {:constructed, :bif} ->
        name = :lists.concat([className, :_, fieldName])
        emit([~c"   ", {:asis, enc_func(name)}, ~c"(Val, ", {:asis, tag}, ~c")"])
        [r_typedef(name: :erlang.list_to_atom(name), typespec: type)]

      {:primitive, :bif} ->
        gen_encode_prim(:ber, type, {:asis, :lists.reverse(tag)}, ~c"Val")
        []

      r_Externaltypereference(module: ^currentMod, type: etype) ->
        emit([~c"   'enc_", etype, ~c"'(Val, ", {:asis, tag}, ~c")", :nl])
        []

      r_Externaltypereference(module: emod, type: etype) ->
        emit([~c"   '", emod, ~c"':'enc_", etype, ~c"'(Val, ", {:asis, tag}, ~c")", :nl])
        []
    end
  end

  defp gen_decode_objectfields(
         className,
         [{:typefield, name, optOrMand} | rest],
         objName,
         objectFields,
         constrAcc
       ) do
    emitFuncClause = fn arg ->
      emit([{:asis, dec_func(objName)}, ~c"(", {:asis, name}, ~c", ", arg, ~c",_) ->", :nl])
    end

    maybeConstr =
      case {get_object_field(
              name,
              objectFields
            ), optOrMand} do
        {false, :OPTIONAL} ->
          emitFuncClause.(~c" Bytes")
          emit([~c"   Bytes"])
          []

        {false, {:DEFAULT, defaultType}} ->
          emitFuncClause.(~c"Bytes")
          emit_tlv_format(~c"Bytes")
          gen_decode_default_call(className, name, ~c"Tlv", defaultType)

        {{^name, typeSpec}, _} ->
          emitFuncClause.(~c"Bytes")
          emit_tlv_format(~c"Bytes")
          gen_decode_field_call(objName, name, ~c"Tlv", typeSpec)
      end

    case more_genfields(rest) do
      true ->
        emit([~c";", :nl])

      false ->
        emit([~c".", :nl])
    end

    gen_decode_objectfields(className, rest, objName, objectFields, maybeConstr ++ constrAcc)
  end

  defp gen_decode_objectfields(
         className,
         [{:objectfield, name, _, _, optOrMand} | rest],
         objName,
         objectFields,
         constrAcc
       ) do
    currentMod = :erlang.get(:currmod)

    emitFuncClause = fn args ->
      emit([{:asis, dec_func(objName)}, ~c"(", {:asis, name}, ~c", ", args, ~c") ->", :nl])
    end

    case {get_object_field(name, objectFields), optOrMand} do
      {false, :OPTIONAL} ->
        emitFuncClause.(~c"_,_")

        emit([
          ~c"  exit({error,{'illegal use of missing field in object', ",
          {:asis, name},
          ~c"}})"
        ])

      {false, {:DEFAULT, _DefaultObject}} ->
        exit({:error, {:asn1, {~c"not implemented yet", name}}})

      {{^name, r_Externalvaluereference(module: ^currentMod, value: typeName)}, _} ->
        emitFuncClause.(~c"Bytes,[H|T]")
        emit([indent(3), {:asis, dec_func(typeName)}, ~c"(H, Bytes, T)"])

      {{^name, r_Externalvaluereference(module: m, value: typeName)}, _} ->
        emitFuncClause.(~c"Bytes,[H|T]")
        emit([indent(3), {:asis, m}, ~c":", {:asis, dec_func(typeName)}, ~c"(H, Bytes, T)"])

      {{^name, r_typedef(name: typeName)}, _} when is_atom(typeName) ->
        emitFuncClause.(~c"Bytes,[H|T]")
        emit([indent(3), {:asis, dec_func(typeName)}, ~c"(H, Bytes, T)"])
    end

    case more_genfields(rest) do
      true ->
        emit([~c";", :nl])

      false ->
        emit([~c".", :nl])
    end

    gen_decode_objectfields(className, rest, objName, objectFields, constrAcc)
  end

  defp gen_decode_objectfields(cN, [_C | cs], o, oF, cAcc) do
    gen_decode_objectfields(cN, cs, o, oF, cAcc)
  end

  defp gen_decode_objectfields(_, [], _, _, cAcc) do
    cAcc
  end

  defp emit_tlv_format(bytes) do
    notice_tlv_format_gen()
    emit([~c"  Tlv = tlv_format(", bytes, ~c"),", :nl])
  end

  defp notice_tlv_format_gen() do
    module = :erlang.get(:currmod)

    case :erlang.get(:tlv_format) do
      {:done, ^module} ->
        :ok

      _ ->
        :erlang.put(:tlv_format, true)
    end
  end

  defp emit_tlv_format_function() do
    module = :erlang.get(:currmod)

    case :erlang.get(:tlv_format) do
      true ->
        emit_tlv_format_function1()
        :erlang.put(:tlv_format, {:done, module})

      _ ->
        :ok
    end
  end

  defp emit_tlv_format_function1() do
    emit([
      ~c"tlv_format(Bytes) when is_binary(Bytes) ->",
      :nl,
      ~c"  {Tlv,_} = ",
      {:call, :ber, :ber_decode_nif, [~c"Bytes"]},
      :com,
      :nl,
      ~c"  Tlv;",
      :nl,
      ~c"tlv_format(Bytes) ->",
      :nl,
      ~c"  Bytes.",
      :nl
    ])
  end

  defp gen_decode_constr_type(erules, [typeDef | rest])
       when elem(typeDef, 0) === :typedef do
    case is_already_generated(:dec, r_typedef(typeDef, :name)) do
      true ->
        :ok

      _ ->
        emit([:nl, :nl, ~c"'dec_", r_typedef(typeDef, :name), ~c"'(Tlv, TagIn) ->", :nl])
        gen_decode_user(erules, typeDef)
    end

    gen_decode_constr_type(erules, rest)
  end

  defp gen_decode_constr_type(_, []) do
    :ok
  end

  defp gen_decode_field_call(
         _ObjName,
         _FieldName,
         bytes,
         r_Externaltypereference(module: m, type: t)
       ) do
    currentMod = :erlang.get(:currmod)
    tDef = :asn1_db.dbget(m, t)
    def__ = r_typedef(tDef, :typespec)
    oTag = r_type(def__, :tag)

    tag =
      for x <- oTag do
        decode_class(r_tag(x, :class)) <<< (10 + r_tag(x, :number))
      end

    cond do
      m == currentMod ->
        emit([~c"   ", {:asis, dec_func(t)}, ~c"(", bytes, ~c", ", {:asis, tag}, ~c")"])
        []

      true ->
        emit([
          ~c"   ",
          {:asis, m},
          ~c":",
          {:asis, dec_func(t)},
          ~c"(",
          bytes,
          ~c", ",
          {:asis, tag},
          ~c")"
        ])

        []
    end
  end

  defp gen_decode_field_call(objName, fieldName, bytes, type) do
    def__ = r_typedef(type, :typespec)
    oTag = r_type(def__, :tag)

    tag =
      for x <- oTag do
        decode_class(r_tag(x, :class)) <<< (10 + r_tag(x, :number))
      end

    case r_typedef(type, :name) do
      {:primitive, :bif} ->
        gen_dec_prim(def__, bytes, tag)
        []

      {:constructed, :bif} ->
        name = :lists.concat([objName, ~c"_", fieldName])
        emit([~c"   ", {:asis, dec_func(name)}, ~c"(", bytes, ~c",", {:asis, tag}, ~c")"])
        [r_typedef(type, name: :erlang.list_to_atom(name))]

      {extMod, typeName} ->
        emit([
          ~c"   ",
          {:asis, extMod},
          ~c":",
          {:asis, dec_func(typeName)},
          ~c"(",
          bytes,
          ~c",",
          {:asis, tag},
          ~c")"
        ])

        []

      typeName ->
        emit([~c"   ", {:asis, dec_func(typeName)}, ~c"(", bytes, ~c",", {:asis, tag}, ~c")"])
        []
    end
  end

  defp gen_decode_default_call(className, fieldName, bytes, type) do
    currentMod = :erlang.get(:currmod)
    innerType = :asn1ct_gen.get_inner(r_type(type, :def))
    oTag = r_type(type, :tag)

    tag =
      for x <- oTag do
        decode_class(r_tag(x, :class)) <<< (10 + r_tag(x, :number))
      end

    case :asn1ct_gen.type(innerType) do
      {:constructed, :bif} ->
        emit([~c"   'dec_", className, :_, fieldName, ~c"'(", bytes, ~c",", {:asis, tag}, ~c")"])

        [
          r_typedef(
            name: :erlang.list_to_atom(:lists.concat([className, :_, fieldName])),
            typespec: type
          )
        ]

      {:primitive, :bif} ->
        gen_dec_prim(type, bytes, tag)
        []

      r_Externaltypereference(module: ^currentMod, type: etype) ->
        emit([~c"   'dec_", etype, ~c"'(", bytes, ~c" ,", {:asis, tag}, ~c")", :nl])
        []

      r_Externaltypereference(module: emod, type: etype) ->
        emit([~c"   '", emod, ~c"':'dec_", etype, ~c"'(", bytes, ~c", ", {:asis, tag}, ~c")", :nl])

        []
    end
  end

  defp is_already_generated(operation, name) do
    case :erlang.get(:class_default_type) do
      :undefined ->
        :erlang.put(:class_default_type, [{operation, name}])
        false

      generatedList ->
        case :lists.member(
               {operation, name},
               generatedList
             ) do
          true ->
            true

          false ->
            :erlang.put(
              :class_default_type,
              [{operation, name} | generatedList]
            )

            false
        end
    end
  end

  defp more_genfields([]) do
    false
  end

  defp more_genfields([field | fields]) do
    case :erlang.element(1, field) do
      :typefield ->
        true

      :objectfield ->
        true

      _ ->
        more_genfields(fields)
    end
  end

  def gen_objectset_code(erules, objSet) do
    objSetName = r_typedef(objSet, :name)
    def__ = r_typedef(objSet, :typespec)

    r_Externaltypereference(
      module: classModule,
      type: className
    ) = r_ObjectSet(def__, :class)

    classDef = :asn1_db.dbget(classModule, className)
    uniqueFName = r_ObjectSet(def__, :uniquefname)
    set = r_ObjectSet(def__, :set)

    emit([
      :nl,
      :nl,
      :nl,
      ~c"%%================================",
      :nl,
      ~c"%%  ",
      objSetName,
      :nl,
      ~c"%%================================",
      :nl
    ])

    case className do
      {_Module, extClassName} ->
        gen_objset_code(erules, objSetName, uniqueFName, set, extClassName, classDef)

      _ ->
        gen_objset_code(erules, objSetName, uniqueFName, set, className, classDef)
    end

    emit(:nl)
  end

  defp gen_objset_code(erules, objSetName, uniqueFName, set, className, classDef) do
    classFields = get_class_fields(classDef)

    internalFuncs =
      gen_objset_enc(erules, objSetName, uniqueFName, set, className, classFields, 1, [])

    gen_objset_dec(erules, objSetName, uniqueFName, set, className, classFields, 1)
    gen_internal_funcs(erules, internalFuncs)
  end

  defp gen_objset_enc(_, _, {:unique, :undefined}, _, _, _, _, _) do
    []
  end

  defp gen_objset_enc(
         erules,
         objSetName,
         uniqueName,
         [{objName, val, fields} | t],
         clName,
         clFields,
         nthObj,
         acc
       ) do
    currMod = :erlang.get(:currmod)

    {internalFunc, newNthObj} =
      case objName do
        {:no_mod, :no_name} ->
          gen_inlined_enc_funs(fields, clFields, objSetName, val, nthObj)

        {^currMod, name} ->
          emit([
            asis_atom([~c"getenc_", objSetName]),
            ~c"(Id) when Id =:= ",
            {:asis, val},
            ~c" ->",
            :nl,
            ~c"    fun ",
            asis_atom([~c"enc_", name]),
            ~c"/3;",
            :nl
          ])

          {[], nthObj}

        {moduleName, name} ->
          emit([
            asis_atom([~c"getenc_", objSetName]),
            ~c"(Id) when Id =:= ",
            {:asis, val},
            ~c" ->",
            :nl
          ])

          emit_ext_fun(:enc, moduleName, name)
          emit([~c";", :nl])
          {[], nthObj}

        _ ->
          emit([
            asis_atom([~c"getenc_", objSetName]),
            ~c"(",
            {:asis, val},
            ~c") ->",
            :nl,
            ~c"  fun ",
            asis_atom([~c"enc_", objName]),
            ~c"/3;",
            :nl
          ])

          {[], nthObj}
      end

    gen_objset_enc(
      erules,
      objSetName,
      uniqueName,
      t,
      clName,
      clFields,
      newNthObj,
      internalFunc ++ acc
    )
  end

  defp gen_objset_enc(
         _,
         objSetName,
         _UniqueName,
         [:EXTENSIONMARK],
         _ClName,
         _ClFields,
         _NthObj,
         acc
       ) do
    emit([
      asis_atom([~c"getenc_", objSetName]),
      ~c"(_) ->",
      :nl,
      indent(2),
      ~c"fun(_, Val, _RestPrimFieldName) ->",
      :nl
    ])

    emit_enc_open_type(4)
    emit([:nl, indent(2), ~c"end.", :nl, :nl])
    acc
  end

  defp gen_objset_enc(_, objSetName, uniqueName, [], _, _, _, acc) do
    emit_default_getenc(objSetName, uniqueName)
    emit([~c".", :nl, :nl])
    acc
  end

  defp emit_ext_fun(encDec, moduleName, name) do
    emit([
      indent(3),
      ~c"fun(T,V,O) -> '",
      moduleName,
      ~c"':'",
      encDec,
      ~c"_",
      name,
      ~c"'(T,V,O) end"
    ])
  end

  defp emit_default_getenc(objSetName, uniqueName) do
    emit([
      asis_atom([~c"getenc_", objSetName]),
      ~c"(ErrV) ->",
      :nl,
      indent(3),
      ~c"fun(C,V,_) ->",
      :nl,
      ~c"exit({'Type not compatible with table constraint',{component,C},{value,V}, {unique_name_and_value,",
      {:asis, uniqueName},
      ~c", ErrV}}) end"
    ])
  end

  defp gen_inlined_enc_funs(fields, [{:typefield, _, _} | _] = t, objSetName, val, nthObj) do
    emit([
      asis_atom([~c"getenc_", objSetName]),
      ~c"(",
      {:asis, val},
      ~c") ->",
      :nl,
      indent(3),
      ~c"fun(Type, Val, _RestPrimFieldName) ->",
      :nl,
      indent(6),
      ~c"case Type of",
      :nl
    ])

    gen_inlined_enc_funs1(fields, t, objSetName, [], nthObj, [])
  end

  defp gen_inlined_enc_funs(fields, [_ | rest], objSetName, val, nthObj) do
    gen_inlined_enc_funs(fields, rest, objSetName, val, nthObj)
  end

  defp gen_inlined_enc_funs(_, [], _, _, nthObj) do
    {[], nthObj}
  end

  defp gen_inlined_enc_funs1(
         fields,
         [{:typefield, name, _} | rest],
         objSetName,
         sep0,
         nthObj,
         acc0
       ) do
    emit(sep0)
    sep = [~c";", :nl]
    currMod = :erlang.get(:currmod)
    internalDefFunName = :asn1ct_gen.list2name([nthObj, name, objSetName])

    {acc, nAdd} =
      case :lists.keyfind(name, 1, fields) do
        {_, r_type() = type} ->
          {ret, n} = emit_inner_of_fun(type, internalDefFunName)
          {ret ++ acc0, n}

        {_, r_typedef() = type} ->
          emit([indent(9), {:asis, name}, ~c" ->", :nl])
          {ret, n} = emit_inner_of_fun(type, internalDefFunName)
          {ret ++ acc0, n}

        {_, r_Externaltypereference(module: m, type: t)} ->
          emit([indent(9), {:asis, name}, ~c" ->", :nl])

          cond do
            m === currMod ->
              emit([indent(12), ~c"'enc_", t, ~c"'(Val)"])

            true ->
              r_typedef(typespec: type) = :asn1_db.dbget(m, t)
              oTag = r_type(type, :tag)

              tag =
                for x <- oTag do
                  encode_tag_val(
                    decode_class(r_tag(x, :class)),
                    r_tag(x, :form),
                    r_tag(x, :number)
                  )
                end

              emit([indent(12), ~c"'", m, ~c"':'enc_", t, ~c"'(Val, ", {:asis, tag}, ~c")"])
          end

          {acc0, 0}

        false ->
          emit([indent(9), {:asis, name}, ~c" ->", :nl])
          emit_enc_open_type(11)
          {acc0, 0}
      end

    gen_inlined_enc_funs1(fields, rest, objSetName, sep, nthObj + nAdd, acc)
  end

  defp gen_inlined_enc_funs1(fields, [_ | rest], objSetName, sep, nthObj, acc) do
    gen_inlined_enc_funs1(fields, rest, objSetName, sep, nthObj, acc)
  end

  defp gen_inlined_enc_funs1(_, [], _, _, nthObj, acc) do
    emit([:nl, indent(6), ~c"end", :nl, indent(3), ~c"end;", :nl])
    {acc, nthObj}
  end

  defp emit_enc_open_type(i) do
    indent = indent(i)

    s = [
      indent,
      ~c"case Val of",
      :nl,
      indent,
      indent(2),
      ~c"{asn1_OPENTYPE,Bin} when is_binary(Bin) ->",
      :nl,
      indent,
      indent(4),
      ~c"{Bin,byte_size(Bin)}"
      | case :asn1ct.use_legacy_types() do
          false ->
            [:nl, indent, ~c"end"]

          true ->
            [
              ~c";",
              :nl,
              indent,
              indent(2),
              ~c"Bin when is_binary(Bin) ->",
              :nl,
              indent,
              indent(4),
              ~c"{Bin,byte_size(Bin)};",
              :nl,
              indent,
              indent(2),
              ~c"_ ->",
              :nl,
              indent,
              indent(4),
              ~c"{Val,length(Val)}",
              :nl,
              indent,
              ~c"end"
            ]
        end
    ]

    emit(s)
  end

  defp emit_inner_of_fun(
         tDef = r_typedef(name: {extMod, name}, typespec: type),
         internalDefFunName
       ) do
    oTag = r_type(type, :tag)

    tag =
      for x <- oTag do
        encode_tag_val(decode_class(r_tag(x, :class)), r_tag(x, :form), r_tag(x, :number))
      end

    case {extMod, name} do
      {:primitive, :bif} ->
        emit(indent(12))
        gen_encode_prim(:ber, type, [{:asis, :lists.reverse(tag)}], ~c"Val")
        {[], 0}

      {:constructed, :bif} ->
        emit([indent(12), ~c"'enc_", internalDefFunName, ~c"'(Val, ", {:asis, tag}, ~c")"])
        {[r_typedef(tDef, name: internalDefFunName)], 1}

      _ ->
        emit([indent(12), ~c"'", extMod, ~c"':'enc_", name, ~c"'(Val", {:asis, tag}, ~c")"])
        {[], 0}
    end
  end

  defp emit_inner_of_fun(r_typedef(name: name), _) do
    emit([indent(12), ~c"'enc_", name, ~c"'(Val)"])
    {[], 0}
  end

  defp emit_inner_of_fun(type, _) when elem(type, 0) === :type do
    currMod = :erlang.get(:currmod)

    case r_type(type, :def) do
      def__ when is_atom(def__) ->
        oTag = r_type(type, :tag)

        tag =
          for x <- oTag do
            encode_tag_val(decode_class(r_tag(x, :class)), r_tag(x, :form), r_tag(x, :number))
          end

        emit([indent(9), def__, ~c" ->", :nl, indent(12)])
        gen_encode_prim(:ber, type, {:asis, :lists.reverse(tag)}, ~c"Val")

      r_Externaltypereference(module: ^currMod, type: t) ->
        emit([indent(9), t, ~c" ->", :nl, indent(12), ~c"'enc_", t, ~c"'(Val)"])

      r_Externaltypereference(module: extMod, type: t) ->
        r_typedef(typespec: extType) = :asn1_db.dbget(extMod, t)
        oTag = r_type(extType, :tag)

        tag =
          for x <- oTag do
            encode_tag_val(decode_class(r_tag(x, :class)), r_tag(x, :form), r_tag(x, :number))
          end

        emit([
          indent(9),
          t,
          ~c" ->",
          :nl,
          indent(12),
          extMod,
          ~c":'enc_",
          t,
          ~c"'(Val, ",
          {:asis, tag},
          ~c")"
        ])
    end

    {[], 0}
  end

  defp indent(n) do
    :lists.duplicate(n, 32)
  end

  defp gen_objset_dec(_, _, {:unique, :undefined}, _, _, _, _) do
    :ok
  end

  defp gen_objset_dec(
         erules,
         objSName,
         uniqueName,
         [{objName, val, fields} | t],
         clName,
         clFields,
         nthObj
       ) do
    currMod = :erlang.get(:currmod)

    newNthObj =
      case objName do
        {:no_mod, :no_name} ->
          gen_inlined_dec_funs(fields, clFields, objSName, val, nthObj)

        {^currMod, name} ->
          emit([
            asis_atom([~c"getdec_", objSName]),
            ~c"(Id) when Id =:= ",
            {:asis, val},
            ~c" ->",
            :nl,
            ~c"    fun 'dec_",
            name,
            ~c"'/3;",
            :nl
          ])

          nthObj

        {moduleName, name} ->
          emit([
            asis_atom([~c"getdec_", objSName]),
            ~c"(Id) when Id =:= ",
            {:asis, val},
            ~c" ->",
            :nl
          ])

          emit_ext_fun(:dec, moduleName, name)
          emit([~c";", :nl])
          nthObj

        _ ->
          emit([
            asis_atom([~c"getdec_", objSName]),
            ~c"(",
            {:asis, val},
            ~c") ->",
            :nl,
            ~c"    fun 'dec_",
            objName,
            ~c"'/3;",
            :nl
          ])

          nthObj
      end

    gen_objset_dec(erules, objSName, uniqueName, t, clName, clFields, newNthObj)
  end

  defp gen_objset_dec(_, objSetName, _UniqueName, [:EXTENSIONMARK], _ClName, _ClFields, _NthObj) do
    emit([
      asis_atom([~c"getdec_", objSetName]),
      ~c"(_) ->",
      :nl,
      indent(2),
      ~c"fun(_,Bytes, _RestPrimFieldName) ->",
      :nl
    ])

    emit_dec_open_type(4)
    emit([:nl, indent(2), ~c"end.", :nl, :nl])
    :ok
  end

  defp gen_objset_dec(_, objSetName, uniqueName, [], _, _, _) do
    emit_default_getdec(objSetName, uniqueName)
    emit([~c".", :nl, :nl])
    :ok
  end

  defp emit_default_getdec(objSetName, uniqueName) do
    emit([~c"'getdec_", objSetName, ~c"'(ErrV) ->", :nl])

    emit([
      indent(2),
      ~c"fun(C,V,_) -> exit({{component,C},{value,V},{unique_name_and_value,",
      {:asis, uniqueName},
      ~c", ErrV}}) end"
    ])
  end

  defp gen_inlined_dec_funs(fields, [{:typefield, _, _} | _] = clFields, objSetName, val, nthObj) do
    emit([~c"'getdec_", objSetName, ~c"'(", {:asis, val}, ~c") ->", :nl])

    emit([
      indent(3),
      ~c"fun(Type, Bytes, _RestPrimFieldName) ->",
      :nl,
      indent(6),
      ~c"case Type of",
      :nl
    ])

    gen_inlined_dec_funs1(fields, clFields, objSetName, ~c"", nthObj)
  end

  defp gen_inlined_dec_funs(fields, [_ | clFields], objSetName, val, nthObj) do
    gen_inlined_dec_funs(fields, clFields, objSetName, val, nthObj)
  end

  defp gen_inlined_dec_funs(_, _, _, _, nthObj) do
    nthObj
  end

  defp gen_inlined_dec_funs1(fields, [{:typefield, name, prop} | rest], objSetName, sep0, nthObj) do
    emit(sep0)
    sep = [~c";", :nl]

    decProp =
      case prop do
        :OPTIONAL ->
          :opt_or_default

        {:DEFAULT, _} ->
          :opt_or_default

        _ ->
          :mandatory
      end

    internalDefFunName = [nthObj, name, objSetName]

    n =
      case :lists.keyfind(name, 1, fields) do
        {_, r_type() = type} ->
          emit_inner_of_decfun(type, decProp, internalDefFunName)

        {_, r_typedef() = type} ->
          emit([indent(9), {:asis, name}, ~c" ->", :nl])
          emit_inner_of_decfun(type, decProp, internalDefFunName)

        {_, r_Externaltypereference(module: m, type: t)} ->
          emit([indent(9), {:asis, name}, ~c" ->", :nl])
          currMod = :erlang.get(:currmod)

          cond do
            m === currMod ->
              emit([indent(12), ~c"'dec_", t, ~c"'(Bytes)"])

            true ->
              r_typedef(typespec: type) = :asn1_db.dbget(m, t)
              oTag = r_type(type, :tag)

              tag =
                for x <- oTag do
                  decode_class(r_tag(x, :class)) <<< (10 + r_tag(x, :number))
                end

              emit([indent(12), ~c"'", m, ~c"':'dec_", t, ~c"'(Bytes, ", {:asis, tag}, ~c")"])
          end

          0

        false ->
          emit([indent(9), {:asis, name}, ~c" ->", :nl])
          emit_dec_open_type(11)
          0
      end

    gen_inlined_dec_funs1(fields, rest, objSetName, sep, nthObj + n)
  end

  defp gen_inlined_dec_funs1(fields, [_ | rest], objSetName, sep, nthObj) do
    gen_inlined_dec_funs1(fields, rest, objSetName, sep, nthObj)
  end

  defp gen_inlined_dec_funs1(_, [], _, _, nthObj) do
    emit([:nl, indent(6), ~c"end", :nl, indent(3), ~c"end;", :nl])
    nthObj
  end

  defp emit_dec_open_type(i) do
    indent = indent(i)

    s =
      case :asn1ct.use_legacy_types() do
        false ->
          [
            indent,
            ~c"case Bytes of",
            :nl,
            indent,
            indent(2),
            ~c"Bin when is_binary(Bin) -> ",
            :nl,
            indent,
            indent(4),
            ~c"{asn1_OPENTYPE,Bin};",
            :nl,
            indent,
            indent(2),
            ~c"_ ->",
            :nl,
            indent,
            indent(4),
            ~c"{asn1_OPENTYPE,",
            {:call, :ber, :ber_encode, [~c"Bytes"]},
            ~c"}",
            :nl,
            indent,
            ~c"end"
          ]

        true ->
          [
            indent,
            ~c"case Bytes of",
            :nl,
            indent,
            indent(2),
            ~c"Bin when is_binary(Bin) -> ",
            :nl,
            indent,
            indent(4),
            ~c"Bin;",
            :nl,
            indent,
            indent(2),
            ~c"_ ->",
            :nl,
            indent,
            indent(4),
            {:call, :ber, :ber_encode, [~c"Bytes"]},
            :nl,
            indent,
            ~c"end"
          ]
      end

    emit(s)
  end

  defp emit_inner_of_decfun(
         r_typedef(name: {extName, name}, typespec: type),
         _Prop,
         internalDefFunName
       ) do
    oTag = r_type(type, :tag)

    tag =
      for x <- oTag do
        decode_class(r_tag(x, :class)) <<< (10 + r_tag(x, :number))
      end

    case {extName, name} do
      {:primitive, :bif} ->
        emit(indent(12))
        gen_dec_prim(type, ~c"Bytes", tag)
        0

      {:constructed, :bif} ->
        emit([
          indent(12),
          ~c"'dec_",
          :asn1ct_gen.list2name(internalDefFunName),
          ~c"'(Bytes, ",
          {:asis, tag},
          ~c")"
        ])

        1

      _ ->
        emit([indent(12), ~c"'", extName, ~c"':'dec_", name, ~c"'(Bytes, ", {:asis, tag}, ~c")"])
        0
    end
  end

  defp emit_inner_of_decfun(r_typedef(name: name), _Prop, _) do
    emit([indent(12), ~c"'dec_", name, ~c"'(Bytes)"])
    0
  end

  defp emit_inner_of_decfun(r_type() = type, _Prop, _) do
    oTag = r_type(type, :tag)

    tag =
      for x <- oTag do
        decode_class(r_tag(x, :class)) <<< (10 + r_tag(x, :number))
      end

    currMod = :erlang.get(:currmod)
    def__ = r_type(type, :def)
    innerType = :asn1ct_gen.get_inner(def__)
    whatKind = :asn1ct_gen.type(innerType)

    case whatKind do
      {:primitive, :bif} ->
        emit([indent(9), def__, ~c" ->", :nl, indent(12)])
        gen_dec_prim(type, ~c"Bytes", tag)

      r_Externaltypereference(module: ^currMod, type: t) ->
        emit([indent(9), t, ~c" ->", :nl, indent(12), ~c"'dec_", t, ~c"'(Bytes)"])

      r_Externaltypereference(module: extMod, type: t) ->
        emit([
          indent(9),
          t,
          ~c" ->",
          :nl,
          indent(12),
          extMod,
          ~c":'dec_",
          t,
          ~c"'(Bytes, ",
          {:asis, tag},
          ~c")"
        ])
    end

    0
  end

  defp gen_internal_funcs(_, []) do
    :ok
  end

  defp gen_internal_funcs(erules, [typeDef | rest]) do
    gen_encode_user(erules, typeDef, false)
    emit([:nl, :nl, ~c"'dec_", r_typedef(typeDef, :name), ~c"'(Tlv, TagIn) ->", :nl])
    gen_decode_user(erules, typeDef)
    gen_internal_funcs(erules, rest)
  end

  def decode_class(:UNIVERSAL) do
    0
  end

  def decode_class(:APPLICATION) do
    64
  end

  def decode_class(:CONTEXT) do
    128
  end

  def decode_class(:PRIVATE) do
    192
  end

  defp mkfuncname(r_Externaltypereference(module: mod, type: eType), decOrEnc) do
    currMod = :erlang.get(:currmod)

    case currMod do
      ^mod ->
        :lists.concat([~c"'", decOrEnc, ~c"_", eType, ~c"'"])

      _ ->
        :lists.concat([~c"'", mod, ~c"':'", decOrEnc, ~c"_", eType, ~c"'"])
    end
  end

  defp get_size_constraint(c) do
    case :lists.keyfind(:SizeConstraint, 1, c) do
      false ->
        []

      {_, {_, []}} ->
        []

      {_, {sv, sv}} ->
        sv

      {_, {_, _} = tc} ->
        tc
    end
  end

  defp get_class_fields(r_classdef(typespec: objClass)) do
    r_objectclass(objClass, :fields)
  end

  defp get_class_fields(r_objectclass(fields: fields)) do
    fields
  end

  defp get_class_fields(_) do
    []
  end

  defp get_object_field(name, objectFields) do
    case :lists.keysearch(name, 1, objectFields) do
      {:value, field} ->
        field

      false ->
        false
    end
  end

  def encode_tag_val(class, form, tagNo) when tagNo <= 30 do
    <<class >>> 6::size(2), form >>> 5::size(1), tagNo::size(5)>>
  end

  def encode_tag_val(class, form, tagNo) do
    {octets, _Len} = mk_object_val(tagNo)
    binOct = :erlang.list_to_binary(octets)
    <<class >>> 6::size(2), form >>> 5::size(1), 31::size(5), binOct::binary>>
  end

  defp mk_object_val(val) when val <= 127 do
    {[255 &&& val], 1}
  end

  defp mk_object_val(val) do
    mk_object_val(val >>> 7, [val &&& 127], 1)
  end

  defp mk_object_val(0, ack, len) do
    {ack, len}
  end

  defp mk_object_val(val, ack, len) do
    mk_object_val(val >>> 7, [(val &&& 127) ||| 128 | ack], len + 1)
  end

  def extaddgroup2sequence(extList) when is_list(extList) do
    :lists.filter(
      fn
        r_ExtensionAdditionGroup() ->
          false

        :ExtensionAdditionGroupEnd ->
          false

        _ ->
          true
      end,
      extList
    )
  end

  defp call(f, args) do
    :asn1ct_func.call(:ber, f, args)
  end

  defp enc_func(tname) do
    :erlang.list_to_atom(:lists.concat([~c"enc_", tname]))
  end

  defp dec_func(tname) do
    :erlang.list_to_atom(:lists.concat([~c"dec_", tname]))
  end

  defp asis_atom(list) do
    {:asis, :erlang.list_to_atom(:lists.concat(list))}
  end
end
