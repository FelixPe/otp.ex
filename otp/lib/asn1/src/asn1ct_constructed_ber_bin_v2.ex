defmodule :m_asn1ct_constructed_ber_bin_v2 do
  use Bitwise
  import :asn1ct_gen, only: [emit: 1, get_record_name_prefix: 1]
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

  def gen_encode_sequence(gen, typename, r_type() = d) do
    :asn1ct_name.start()
    :asn1ct_name.new(:term)
    :asn1ct_name.new(:bytes)

    valName =
      case typename do
        [:EXTERNAL] ->
          tr =
            case gen do
              r_gen(pack: :record) ->
                :transform_to_EXTERNAL1990

              r_gen(pack: :map) ->
                :transform_to_EXTERNAL1990_maps
            end

          emit([indent(4), ~c"NewVal = ", {:call, :ext, tr, [~c"Val"]}, :com, :nl])
          ~c"NewVal"

        _ ->
          ~c"Val"
      end

    {seqOrSet, tableConsInfo, compList0} =
      case r_type(d, :def) do
        r_SEQUENCE(tablecinf: tCI, components: cL) ->
          {:SEQUENCE, tCI, cL}

        r_SET(tablecinf: tCI, components: cL) ->
          {:SET, tCI, cL}
      end

    compList = filter_complist(compList0)
    ext = extensible(compList)

    compList1 =
      case compList do
        {rl1, el, rl2} ->
          rl1 ++ el ++ rl2

        {rl, el} ->
          rl ++ el

        _ ->
          compList
      end

    enc_match_input(gen, valName, compList1)

    encObj =
      case tableConsInfo do
        r_simpletableattributes(usedclassfield: used, uniqueclassfield: unique)
        when used != unique ->
          false

        r_simpletableattributes(
          objectsetname: objectSetRef,
          c_name: attrN,
          c_index: n,
          usedclassfield: uniqueFieldName,
          uniqueclassfield: uniqueFieldName,
          valueindex: valueIndex
        ) ->
          {objSetMod, objSetName} = objectSetRef
          oSDef = :asn1_db.dbget(objSetMod, objSetName)

          case r_ObjectSet(r_typedef(oSDef, :typespec), :gen) do
            true ->
              objectEncode = :asn1ct_gen.un_hyphen_var(:lists.concat([:Obj, attrN]))

              emit([
                objectEncode,
                ~c" = ",
                :nl,
                ~c"   ",
                {:asis, objSetMod},
                ~c":'getenc_",
                objSetName,
                ~c"'("
              ])

              valueMatch = value_match(gen, valueIndex, :lists.concat([~c"Cindex", n]))
              emit([indent(35), valueMatch, ~c"),", :nl])
              {attrN, objectEncode}

            _ ->
              false
          end

        _ ->
          case r_type(d, :tablecinf) do
            [{:objfun, _} | _] ->
              {~c"got objfun through args", ~c"ObjFun"}

            _ ->
              false
          end
      end

    gen_enc_sequence_call(gen, typename, compList1, 1, ext, encObj)
    emit([:nl, ~c"   BytesSoFar = "])

    case seqOrSet do
      :SET when r_SET(r_type(d, :def), :sorted) == :dynamic ->
        :asn1ct_func.need({:ber, :dynamicsort_SET_components, 1})
        emit(~c"dynamicsort_SET_components([")
        mkvlist(:asn1ct_name.all(:encBytes))
        emit([~c"]),", :nl])

      _ ->
        emit(~c"[")
        mkvlist(:asn1ct_name.all(:encBytes))
        emit([~c"],", :nl])
    end

    emit(~c"LenSoFar = ")

    case :asn1ct_name.all(:encLen) do
      [] ->
        emit(~c"0")

      allLengths ->
        mkvplus(allLengths)
    end

    emit([~c",", :nl])
    call(:encode_tags, [~c"TagIn", ~c"BytesSoFar", ~c"LenSoFar"])
    emit([~c".", :nl])
  end

  defp enc_match_input(r_gen(pack: :record), valName, compList) do
    len = length(compList)

    vars =
      for n <- :lists.seq(1, len) do
        :lists.concat([~c"Cindex", n])
      end

    recordName = ~c"_"
    emit([~c"{", :lists.join(~c",", [recordName | vars]), ~c"} = ", valName, :com, :nl])
  end

  defp enc_match_input(r_gen(pack: :map), valName, compList) do
    len = length(compList)

    vars =
      for n <- :lists.seq(1, len) do
        :lists.concat([~c"Cindex", n])
      end

    zipped = :lists.zip(compList, vars)

    m =
      for {r_ComponentType(prop: :mandatory, name: name), var} <- zipped do
        [{:asis, name}, ~c":=", var]
      end

    case m do
      [] ->
        :ok

      [_ | _] ->
        emit([~c"\#{", :lists.join(~c",", m), ~c"} = ", valName, :com, :nl])
    end

    os0 =
      for {r_ComponentType(prop: prop, name: name), var} <- zipped,
          prop !== :mandatory do
        {name, var}
      end

    f = fn {name, var} ->
      [
        var,
        ~c" = case ",
        valName,
        ~c" of\n  \#{",
        {:asis, name},
        ~c":=",
        var,
        ~c"_0} -> ",
        var,
        ~c"_0;\n  _ -> ",
        :erlang.atom_to_list(:asn1__MISSING_IN_MAP),
        ~c"\nend"
      ]
    end

    emit(
      :lists.join(
        ~c",\n",
        for e <- os0 do
          f.(e)
        end ++ [[]]
      )
    )
  end

  def gen_decode_sequence(gen, typename, r_type() = d) do
    :asn1ct_name.start()
    :asn1ct_name.new(:tag)

    r_SEQUENCE(
      tablecinf: tableConsInfo,
      components: cList0
    ) = r_type(d, :def)

    cList = filter_complist(cList0)
    ext = extensible(cList)

    {compList, compList2} =
      case cList do
        {rl1, el, rl2} ->
          {rl1 ++ el ++ rl2, cList}

        {rl, el} ->
          {rl ++ el, rl ++ el}

        _ ->
          {cList, cList}
      end

    emit([~c"   %%-------------------------------------------------", :nl])
    emit([~c"   %% decode tag and length ", :nl])
    emit([~c"   %%-------------------------------------------------", :nl])
    :asn1ct_name.new(:tlv)

    case compList do
      [] ->
        true

      _ ->
        emit([{:curr, :tlv}, ~c" = "])
    end

    call(:match_tags, [{:prev, :tlv}, ~c"TagIn"])
    emit([:com, :nl])
    :asn1ct_name.new(:tlv)
    :asn1ct_name.new(:v)

    {decObjInf, valueIndex} =
      case tableConsInfo do
        r_simpletableattributes(
          objectsetname: objectSetRef,
          c_name: attrN,
          usedclassfield: uniqueFieldName,
          uniqueclassfield: uniqueFieldName,
          valueindex: valIndex
        ) ->
          f = fn r_ComponentType(typespec: cT) ->
            case {:asn1ct_gen.get_constraint(
                    r_type(cT, :constraint),
                    :componentrelation
                  ), r_type(cT, :tablecinf)} do
              {:no, [{:objfun, _} | _]} ->
                true

              _ ->
                false
            end
          end

          case :lists.any(f, compList) do
            true ->
              {{attrN, {:deep, objectSetRef, uniqueFieldName, valIndex}}, valIndex}

            false ->
              {{attrN, objectSetRef}, valIndex}
          end

        _ ->
          {false, false}
      end

    recordName0 = :lists.concat([get_record_name_prefix(gen), :asn1ct_gen.list2rname(typename)])
    recordName = :erlang.list_to_atom(recordName0)

    case gen_dec_sequence_call(gen, typename, compList2, ext, decObjInf) do
      :no_terms ->
        :asn1ct_name.new(:rb)

        case gen do
          r_gen(pack: :record) ->
            emit([:nl, :nl, ~c"   {'", recordName, ~c"'}.", :nl, :nl])

          r_gen(pack: :map) ->
            emit([:nl, :nl, ~c"   \#{}.", :nl, :nl])
        end

      {leadingAttrTerm, postponedDecArgs} ->
        emit([:nl])

        case {leadingAttrTerm, postponedDecArgs} do
          {[], []} ->
            :ok

          {_, []} ->
            :ok

          {[{objSetRef, leadingAttr, term}], ^postponedDecArgs} ->
            decObj = :asn1ct_gen.un_hyphen_var(:lists.concat([:DecObj, leadingAttr, term]))
            valueMatch = value_match(gen, valueIndex, term)
            {objSetMod, objSetName} = objSetRef

            emit([
              decObj,
              ~c" =",
              :nl,
              ~c"   ",
              {:asis, objSetMod},
              ~c":'getdec_",
              objSetName,
              ~c"'(",
              valueMatch,
              ~c"),",
              :nl
            ])

            gen_dec_postponed_decs(decObj, postponedDecArgs)
        end

        case ext do
          {:ext, _, _} ->
            emit([
              ~c"case ",
              {:prev, :tlv},
              ~c" of [] -> true; _ -> true end, % ... extra fields skipped",
              :nl
            ])

          _ ->
            emit([
              ~c"case ",
              {:prev, :tlv},
              ~c" of",
              :nl,
              ~c"[] -> true;",
              ~c"_ -> exit({error,{asn1, {unexpected,",
              {:prev, :tlv},
              ~c"}}}) % extra fields not allowed",
              :nl,
              ~c"end,",
              :nl
            ])
        end

        :asn1ct_name.new(:rb)
        gen_dec_pack(gen, recordName, typename, compList)
        emit([~c".", :nl])
    end
  end

  defp gen_dec_pack(gen, recordName, typename, compList) do
    case typename do
      [:EXTERNAL] ->
        dec_external(gen, recordName)

      _ ->
        :asn1ct_name.new(:res)
        gen_dec_do_pack(gen, recordName, compList)
        emit([:com, :nl, {:curr, :res}])
    end
  end

  defp dec_external(r_gen(pack: :record), recordName) do
    all =
      for term <- :asn1ct_name.all(:term) do
        {:var, term}
      end

    record = [{:asis, recordName} | all]

    emit([
      ~c"OldFormat={",
      :lists.join(~c",", record),
      ~c"},",
      :nl,
      {:call, :ext, :transform_to_EXTERNAL1994, [~c"OldFormat"]}
    ])
  end

  defp dec_external(r_gen(pack: :map), _RecordName) do
    vars = :asn1ct_name.all(:term)
    names = [:"direct-reference", :"indirect-reference", :"data-value-descriptor", :encoding]
    zipped = :lists.zip(names, vars)

    mapInit =
      :lists.join(
        ~c",",
        for {n, v} <- zipped do
          [~c"'", n, ~c"'=>", {:var, v}]
        end
      )

    emit([
      ~c"OldFormat = \#{",
      mapInit,
      ~c"}",
      :com,
      :nl,
      ~c"ASN11994Format =",
      :nl,
      {:call, :ext, :transform_to_EXTERNAL1994_maps, [~c"OldFormat"]}
    ])
  end

  defp gen_dec_do_pack(r_gen(pack: :record), recordName, _CompList) do
    all = :asn1ct_name.all(:term)

    l = [
      {:asis, recordName}
      | for var <- all do
          {:var, var}
        end
    ]

    emit([{:curr, :res}, ~c" = {", :lists.join(~c",", l), ~c"}"])
  end

  defp gen_dec_do_pack(r_gen(pack: :map), _, compList) do
    zipped = :lists.zip(compList, :asn1ct_name.all(:term))

    pF = fn
      {r_ComponentType(prop: :OPTIONAL), _} ->
        false

      {_, _} ->
        true
    end

    {mandatory, optional} = :lists.partition(pF, zipped)

    l =
      for {r_ComponentType(name: name), var} <- mandatory do
        [{:asis, name}, ~c"=>", {:var, var}]
      end

    emit([{:curr, :res}, ~c" = \#{", :lists.join(~c",", l), ~c"}"])
    gen_dec_map_optional(optional)
  end

  defp gen_dec_map_optional([{r_ComponentType(name: name), var} | t]) do
    :asn1ct_name.new(:res)

    emit([
      :com,
      :nl,
      {:curr, :res},
      ~c" = case ",
      {:var, var},
      ~c" of",
      :nl,
      ~c"  asn1_NOVALUE -> ",
      {:prev, :res},
      ~c";",
      :nl,
      ~c"  _ -> ",
      {:prev, :res},
      ~c"\#{",
      {:asis, name},
      ~c"=>",
      {:var, var},
      ~c"}",
      :nl,
      ~c"end"
    ])

    gen_dec_map_optional(t)
  end

  defp gen_dec_map_optional([]) do
    :ok
  end

  defp gen_dec_postponed_decs(_, []) do
    emit(:nl)
  end

  defp gen_dec_postponed_decs(
         decObj,
         [
           {_Cname, {firstPFN, pFNList}, term, tmpTerm, _Tag, optOrMand}
           | rest
         ]
       ) do
    :asn1ct_name.new(:tmpterm)
    :asn1ct_name.new(:reason)
    :asn1ct_name.new(:tmptlv)
    emit([term, ~c" = ", :nl])

    n =
      case optOrMand do
        :mandatory ->
          0

        :OPTIONAL ->
          emit_opt_or_mand_check(:asn1_NOVALUE, tmpTerm)
          6

        {:DEFAULT, val} ->
          emit_opt_or_mand_check(val, tmpTerm)
          6
      end

    emit([
      indent(n + 3),
      ~c"case (catch ",
      decObj,
      ~c"(",
      {:asis, firstPFN},
      ~c", ",
      tmpTerm,
      ~c", ",
      {:asis, pFNList},
      ~c")) of",
      :nl
    ])

    emit([indent(n + 6), ~c"{'EXIT', ", {:curr, :reason}, ~c"} ->", :nl])

    emit([
      indent(n + 9),
      ~c"exit({'Type not compatible with table constraint',",
      {:curr, :reason},
      ~c"});",
      :nl
    ])

    emit([indent(n + 6), {:curr, :tmpterm}, ~c" ->", :nl])
    emit([indent(n + 9), {:curr, :tmpterm}, :nl])

    case optOrMand do
      :mandatory ->
        emit([indent(n + 3), ~c"end,", :nl])

      _ ->
        emit([indent(n + 3), ~c"end", :nl, indent(3), ~c"end,", :nl])
    end

    gen_dec_postponed_decs(decObj, rest)
  end

  defp emit_opt_or_mand_check(value, tmpTerm) do
    emit([
      indent(3),
      ~c"case ",
      tmpTerm,
      ~c" of",
      :nl,
      indent(6),
      {:asis, value},
      ~c" ->",
      {:asis, value},
      ~c";",
      :nl,
      indent(6),
      ~c"_ ->",
      :nl
    ])
  end

  def gen_encode_set(erules, typename, d) when elem(d, 0) === :type do
    gen_encode_sequence(erules, typename, d)
  end

  def gen_decode_set(gen, typename, r_type() = d) do
    :asn1ct_name.start()
    :asn1ct_name.new(:tag)

    r_SET(
      tablecinf: tableConsInfo,
      components: tCompList0
    ) = r_type(d, :def)

    tCompList = filter_complist(tCompList0)
    ext = extensible(tCompList)

    toOptional = fn
      :mandatory ->
        :OPTIONAL

      x ->
        x
    end

    compList =
      case tCompList do
        {rl1, el, rl2} ->
          rl1 ++
            for x = r_ComponentType(prop: y) <- el do
              r_ComponentType(x, prop: toOptional.(y))
            end ++ rl2

        {rl, el} ->
          rl ++ el

        _ ->
          tCompList
      end

    :asn1ct_name.new(:tlv)

    case compList do
      [] ->
        true

      _ ->
        emit([{:curr, :tlv}, ~c" = "])
    end

    call(:match_tags, [{:prev, :tlv}, ~c"TagIn"])
    emit([:com, :nl])
    :asn1ct_name.new(:v)

    {decObjInf, valueIndex} =
      case tableConsInfo do
        r_simpletableattributes(
          objectsetname: objectSetRef,
          c_name: attrN,
          usedclassfield: uniqueFieldName,
          uniqueclassfield: uniqueFieldName,
          valueindex: valIndex
        ) ->
          f = fn r_ComponentType(typespec: cT) ->
            case {:asn1ct_gen.get_constraint(
                    r_type(cT, :constraint),
                    :componentrelation
                  ), r_type(cT, :tablecinf)} do
              {:no, [{:objfun, _} | _]} ->
                true

              _ ->
                false
            end
          end

          case :lists.any(f, compList) do
            true ->
              {{attrN, {:deep, objectSetRef, uniqueFieldName, valIndex}}, valIndex}

            false ->
              {{attrN, objectSetRef}, valIndex}
          end

        _ ->
          {false, false}
      end

    case compList do
      [] ->
        true

      _ ->
        emit([~c"SetFun = fun(FunTlv) ->", :nl])
        emit([~c"case FunTlv of ", :nl])
        nextNum = gen_dec_set_cases(gen, typename, compList, 1)

        emit([
          indent(6),
          {:curr, :else},
          ~c" -> ",
          :nl,
          indent(9),
          ~c"{",
          nextNum,
          ~c", ",
          {:curr, :else},
          ~c"}",
          :nl
        ])

        emit([indent(3), ~c"end", :nl])
        emit([indent(3), ~c"end,", :nl])
        emit([~c"PositionList = [SetFun(TempTlv)|| TempTlv <- ", {:curr, :tlv}, ~c"],", :nl])
        :asn1ct_name.new(:tlv)
        emit([{:curr, :tlv}, ~c" = [Stlv || {_,Stlv} <- lists:sort(PositionList)],", :nl])
        :asn1ct_name.new(:tlv)
    end

    recordName0 = :lists.concat([get_record_name_prefix(gen), :asn1ct_gen.list2rname(typename)])
    recordName = :erlang.list_to_atom(recordName0)

    case gen_dec_sequence_call(gen, typename, compList, ext, decObjInf) do
      :no_terms ->
        case gen do
          r_gen(pack: :record) ->
            emit([:nl, :nl, ~c"   {'", recordName, ~c"'}.", :nl, :nl])

          r_gen(pack: :map) ->
            emit([:nl, :nl, ~c"   \#{}.", :nl, :nl])
        end

      {leadingAttrTerm, postponedDecArgs} ->
        emit([:nl])

        case {leadingAttrTerm, postponedDecArgs} do
          {[], []} ->
            :ok

          {_, []} ->
            :ok

          {[{objSetRef, leadingAttr, term}], ^postponedDecArgs} ->
            decObj = :asn1ct_gen.un_hyphen_var(:lists.concat([:DecObj, leadingAttr, term]))
            valueMatch = value_match(gen, valueIndex, term)
            {objSetMod, objSetName} = objSetRef

            emit([
              decObj,
              ~c" =",
              :nl,
              ~c"   ",
              {:asis, objSetMod},
              ~c":'getdec_",
              objSetName,
              ~c"'(",
              valueMatch,
              ~c"),",
              :nl
            ])

            gen_dec_postponed_decs(decObj, postponedDecArgs)
        end

        case ext do
          extnsn when extnsn !== :noext ->
            emit([
              ~c"case ",
              {:prev, :tlv},
              ~c" of [] -> true; _ -> true end, % ... extra fields skipped",
              :nl
            ])

          :noext ->
            emit([
              ~c"case ",
              {:prev, :tlv},
              ~c" of",
              :nl,
              ~c"[] -> true;",
              ~c"_ -> exit({error,{asn1, {unexpected,",
              {:prev, :tlv},
              ~c"}}}) % extra fields not allowed",
              :nl,
              ~c"end,",
              :nl
            ])
        end

        gen_dec_pack(gen, recordName, typename, compList)
        emit([~c".", :nl])
    end
  end

  def gen_encode_sof(erules, typename, _InnerTypename, d)
      when elem(d, 0) === :type do
    :asn1ct_name.start()
    {seqOrSetOf, cont} = r_type(d, :def)

    objfun =
      case r_type(d, :tablecinf) do
        [{:objfun, _} | _R] ->
          ~c", ObjFun"

        _ ->
          ~c""
      end

    emit([
      ~c"   {EncBytes,EncLen} = 'enc_",
      :asn1ct_gen.list2name(typename),
      ~c"_components'(Val",
      objfun,
      ~c",[],0),",
      :nl
    ])

    emit([
      ~c"   ",
      {:call, :ber, :encode_tags, [~c"TagIn", ~c"EncBytes", ~c"EncLen"]},
      ~c".",
      :nl,
      :nl
    ])

    gen_encode_sof_components(erules, typename, seqOrSetOf, cont)
  end

  def gen_decode_sof(erules, typeName, _InnerTypeName, d)
      when elem(d, 0) === :type do
    :asn1ct_name.start()

    {seqOrSetOf, _TypeTag, cont} =
      case r_type(d, :def) do
        {:"SET OF", _Cont} ->
          {:"SET OF", :SET, _Cont}

        {:"SEQUENCE OF", _Cont} ->
          {:"SEQUENCE OF", :SEQUENCE, _Cont}
      end

    typeNameSuffix =
      :asn1ct_gen.constructed_suffix(
        seqOrSetOf,
        r_type(cont, :def)
      )

    emit([~c"   %%-------------------------------------------------", :nl])
    emit([~c"   %% decode tag and length ", :nl])
    emit([~c"   %%-------------------------------------------------", :nl])
    :asn1ct_name.new(:tlv)

    emit([
      {:curr, :tlv},
      ~c" = ",
      {:call, :ber, :match_tags, [{:prev, :tlv}, ~c"TagIn"]},
      :com,
      :nl
    ])

    :asn1ct_name.new(:v)
    emit([~c"["])
    innerType = :asn1ct_gen.get_inner(r_type(cont, :def))

    contName =
      case :asn1ct_gen.type(innerType) do
        atom when is_atom(atom) ->
          atom

        _ ->
          typeNameSuffix
      end

    gen_dec_line(erules, typeName, contName, [], cont, :mandatory)
    emit([~c" || ", {:curr, :v}, ~c" <- ", {:curr, :tlv}, ~c"].", :nl, :nl, :nl])
  end

  defp gen_encode_sof_components(gen, typename, seqOrSetOf, r_type() = cont) do
    {objfun, objfun_novar, encObj} =
      case r_type(cont, :tablecinf) do
        [{:objfun, _} | _R] ->
          {~c", ObjFun", ~c", _", {:no_attr, ~c"ObjFun"}}

        _ ->
          {~c"", ~c"", false}
      end

    emit([
      ~c"'enc_",
      :asn1ct_gen.list2name(typename),
      ~c"_components'([]",
      objfun_novar,
      ~c", AccBytes, AccLen) -> ",
      :nl
    ])

    case {gen, seqOrSetOf} do
      {r_gen(der: true), :"SET OF"} ->
        :asn1ct_func.need({:ber, :dynamicsort_SETOF, 1})
        emit([indent(3), ~c"{dynamicsort_SETOF(AccBytes),AccLen};", :nl, :nl])

      {_, _} ->
        emit([indent(3), ~c"{lists:reverse(AccBytes),AccLen};", :nl, :nl])
    end

    emit([
      ~c"'enc_",
      :asn1ct_gen.list2name(typename),
      ~c"_components'([H|T]",
      objfun,
      ~c",AccBytes, AccLen) ->",
      :nl
    ])

    typeNameSuffix =
      :asn1ct_gen.constructed_suffix(
        seqOrSetOf,
        r_type(cont, :def)
      )

    gen_enc_line(gen, typename, typeNameSuffix, cont, ~c"H", 3, :mandatory, encObj)
    emit([~c",", :nl])

    emit([
      indent(3),
      ~c"'enc_",
      :asn1ct_gen.list2name(typename),
      ~c"_components'(T",
      objfun,
      ~c","
    ])

    emit([~c"[EncBytes|AccBytes], AccLen + EncLen).", :nl, :nl])
  end

  def gen_encode_choice(erules, typename, d) when elem(d, 0) === :type do
    choiceTag = r_type(d, :tag)
    {:CHOICE, compList} = r_type(d, :def)
    ext = extensible(compList)

    compList1 =
      case compList do
        {rl1, el, rl2} ->
          rl1 ++ el ++ rl2

        {rl, el} ->
          rl ++ el

        _ ->
          compList
      end

    gen_enc_choice(erules, typename, choiceTag, compList1, ext)
    emit([:nl, :nl])
  end

  def gen_decode_choice(erules, typename, d) when elem(d, 0) === :type do
    :asn1ct_name.start()
    :asn1ct_name.new(:bytes)
    choiceTag = r_type(d, :tag)
    {:CHOICE, compList} = r_type(d, :def)
    ext = extensible(compList)

    compList1 =
      case compList do
        {rl1, el, rl2} ->
          rl1 ++ el ++ rl2

        {rl, el} ->
          rl ++ el

        _ ->
          compList
      end

    gen_dec_choice(erules, typename, choiceTag, compList1, ext)
    emit([~c".", :nl])
  end

  defp gen_enc_sequence_call(
         erules,
         topType,
         [
           r_ComponentType(name: cname, typespec: type, prop: prop, textual_order: order)
           | rest
         ],
         pos,
         ext,
         encObj
       ) do
    :asn1ct_name.new(:encBytes)
    :asn1ct_name.new(:encLen)
    :asn1ct_name.new(:tmpBytes)
    :asn1ct_name.new(:tmpLen)

    cindexPos =
      case order do
        :undefined ->
          pos

        _ ->
          order
      end

    element =
      case topType do
        [:EXTERNAL] ->
          :io_lib.format(~c"Cindex~w", [cindexPos])

        _ ->
          :io_lib.format(~c"Cindex~w", [cindexPos])
      end

    innerType = :asn1ct_gen.get_inner(r_type(type, :def))
    print_attribute_comment(innerType, pos, cname, prop)
    gen_enc_line(erules, topType, cname, type, element, 3, prop, encObj)
    emit([:com, :nl])
    gen_enc_sequence_call(erules, topType, rest, pos + 1, ext, encObj)
  end

  defp gen_enc_sequence_call(_Erules, _TopType, [], _Num, _, _) do
    true
  end

  defp gen_dec_sequence_call(erules, topType, compList, ext, decObjInf)
       when is_list(compList) do
    gen_dec_sequence_call1(erules, topType, compList, 1, ext, decObjInf, [], [])
  end

  defp gen_dec_sequence_call(erules, topType, compList, ext, decObjInf) do
    gen_dec_sequence_call2(erules, topType, compList, ext, decObjInf)
  end

  defp gen_dec_sequence_call1(
         erules,
         topType,
         [
           r_ComponentType(name: cname, typespec: type, prop: prop, tags: tags)
           | rest
         ],
         num,
         ext,
         decObjInf,
         leadingAttrAcc,
         argsAcc
       ) do
    {lA, postponedDec} =
      gen_dec_component(erules, topType, cname, tags, type, num, prop, ext, decObjInf)

    emit([:com, :nl])

    case rest do
      [] ->
        {lA ++ leadingAttrAcc, postponedDec ++ argsAcc}

      _ ->
        :asn1ct_name.new(:bytes)

        gen_dec_sequence_call1(
          erules,
          topType,
          rest,
          num + 1,
          ext,
          decObjInf,
          lA ++ leadingAttrAcc,
          postponedDec ++ argsAcc
        )
    end
  end

  defp gen_dec_sequence_call1(_Erules, _TopType, [], 1, _, _, _, _) do
    :no_terms
  end

  defp gen_dec_sequence_call1(_, _, [], _Num, _, _, lA, postponedDec) do
    {lA, postponedDec}
  end

  defp gen_dec_sequence_call2(_Erules, _TopType, {[], [], []}, _Ext, _DecObjInf) do
    :no_terms
  end

  defp gen_dec_sequence_call2(erules, topType, {root1, eList, root2}, _Ext, decObjInf) do
    {lA, argsAcc} =
      case gen_dec_sequence_call1(
             erules,
             topType,
             root1 ++ eList,
             1,
             extensible({root1, eList}),
             decObjInf,
             [],
             []
           ) do
        :no_terms ->
          {[], []}

        res ->
          res
      end

    tagList = get_root2_taglist(root2, [])

    emit([
      {:curr, :tlv},
      ~c" = ",
      {:call, :ber, :skip_ExtensionAdditions, [{:prev, :tlv}, {:asis, tagList}]},
      :com,
      :nl
    ])

    :asn1ct_name.new(:tlv)

    gen_dec_sequence_call1(
      erules,
      topType,
      root2,
      length(root1) + length(eList),
      :noext,
      decObjInf,
      lA,
      argsAcc
    )
  end

  defp get_root2_taglist([], acc) do
    :lists.reverse(acc)
  end

  defp get_root2_taglist([r_ComponentType(prop: prop, typespec: type) | rest], acc) do
    firstTag =
      (fn
         [] ->
           []

         [h | _T] ->
           :asn1ct_gen_ber_bin_v2.decode_class(r_tag(h, :class)) <<< (10 + r_tag(h, :number))
       end).(r_type(type, :tag))

    case prop do
      :mandatory ->
        :lists.reverse([firstTag | acc])

      _ ->
        get_root2_taglist(rest, [firstTag | acc])
    end
  end

  defp gen_dec_component(erules, topType, cname, cTags, type, pos, prop, ext, decObjInf) do
    innerType =
      case r_type(type, :def) do
        r_ObjectClassFieldType(type: oCFTType) ->
          oCFTType

        _ ->
          :asn1ct_gen.get_inner(r_type(type, :def))
      end

    prop1 =
      case {prop, ext} do
        {:mandatory, {:ext, epos, _}} when pos >= epos ->
          :OPTIONAL

        _ ->
          prop
      end

    print_attribute_comment(innerType, pos, cname, prop1)
    :asn1ct_name.new(:term)
    emit_term_tlv(prop1, innerType, decObjInf)
    :asn1ct_name.new(:rb)
    postponedDec = gen_dec_line(erules, topType, cname, cTags, type, prop1, decObjInf)
    :asn1ct_name.new(:v)
    :asn1ct_name.new(:tlv)
    :asn1ct_name.new(:form)
    postponedDec
  end

  defp emit_term_tlv({:DEFAULT, _}, innerType, decObjInf) do
    emit_term_tlv(:opt_or_def, innerType, decObjInf)
  end

  defp emit_term_tlv(:OPTIONAL, innerType, decObjInf) do
    emit_term_tlv(:opt_or_def, innerType, decObjInf)
  end

  defp emit_term_tlv(prop, {:typefield, _}, decObjInf) do
    emit_term_tlv(prop, :type_or_object_field, decObjInf)
  end

  defp emit_term_tlv(:opt_or_def, :type_or_object_field, notFalse)
       when notFalse != false do
    :asn1ct_name.new(:tmpterm)
    emit([~c"{", {:curr, :tmpterm}, ~c",", {:curr, :tlv}, ~c"} = "])
  end

  defp emit_term_tlv(:opt_or_def, _, _) do
    emit([~c"{", {:curr, :term}, ~c",", {:curr, :tlv}, ~c"} = "])
  end

  defp emit_term_tlv(_, :type_or_object_field, false) do
    emit([
      ~c"[",
      {:curr, :v},
      ~c"|",
      {:curr, :tlv},
      ~c"] = ",
      {:prev, :tlv},
      ~c", ",
      :nl,
      {:curr, :term},
      ~c" = "
    ])
  end

  defp emit_term_tlv(_, :type_or_object_field, _) do
    :asn1ct_name.new(:tmpterm)
    emit([~c"[", {:curr, :v}, ~c"|", {:curr, :tlv}, ~c"] = ", {:prev, :tlv}, ~c", ", :nl])
    emit([:nl, ~c"  ", {:curr, :tmpterm}, ~c" = "])
  end

  defp emit_term_tlv(:mandatory, _, _) do
    emit([
      ~c"[",
      {:curr, :v},
      ~c"|",
      {:curr, :tlv},
      ~c"] = ",
      {:prev, :tlv},
      ~c", ",
      :nl,
      {:curr, :term},
      ~c" = "
    ])
  end

  defp gen_dec_set_cases(_Erules, _TopType, [], pos) do
    pos
  end

  defp gen_dec_set_cases(erules, topType, [comp | restComps], pos) do
    name = r_ComponentType(comp, :name)
    type = r_ComponentType(comp, :typespec)
    cTags = r_ComponentType(comp, :tags)
    emit([indent(6), ~c"%", name, :nl])

    tags =
      case r_type(type, :tag) do
        [] ->
          for {t1class, t1number} <- cTags do
            :asn1ct_gen_ber_bin_v2.decode_class(t1class) <<< (10 + t1number)
          end

        [firstTag | _] ->
          [
            :asn1ct_gen_ber_bin_v2.decode_class(r_tag(firstTag, :class)) <<<
              (10 + r_tag(firstTag, :number))
          ]
      end

    caseFun = fn
      tagList = [h | t], fun, n ->
        semicolon =
          case tagList do
            [_Tag1, _ | _] ->
              [~c";", :nl]

            _ ->
              ~c""
          end

        emit([~c"TTlv = {", h, ~c",_} ->", :nl])
        emit([indent(4), ~c"{", pos, ~c", TTlv}", semicolon])
        fun.(t, fun, n + 1)

      [], _, 0 ->
        true

      [], _, _ ->
        emit([~c";", :nl])
    end

    caseFun.(tags, caseFun, 0)
    gen_dec_set_cases(erules, topType, restComps, pos + 1)
  end

  defp gen_enc_choice(erules, topType, tag, compList, _Ext) do
    gen_enc_choice1(erules, topType, tag, compList, _Ext)
  end

  defp gen_enc_choice1(erules, topType, _Tag, compList, _Ext) do
    :asn1ct_name.clear()
    emit([~c"   {EncBytes,EncLen} = case element(1,Val) of", :nl])
    gen_enc_choice2(erules, topType, compList)
    emit([:nl, ~c"   end,", :nl, :nl])
    call(:encode_tags, [~c"TagIn", ~c"EncBytes", ~c"EncLen"])
    emit([~c".", :nl])
  end

  defp gen_enc_choice2(erules, topType, [h1 | t])
       when elem(h1, 0) === :ComponentType do
    cname = r_ComponentType(h1, :name)
    type = r_ComponentType(h1, :typespec)
    emit([~c"      ", {:asis, cname}, ~c" ->", :nl])

    {encobj, assign} =
      case {r_type(type, :def),
            :asn1ct_gen.get_constraint(
              r_type(type, :constraint),
              :componentrelation
            )} do
        {r_ObjectClassFieldType(), {:componentrelation, _, _}} ->
          :asn1ct_name.new(:tmpBytes)
          :asn1ct_name.new(:tmpLen)
          :asn1ct_name.new(:encBytes)
          :asn1ct_name.new(:encLen)
          emit = [~c"{", {:curr, :tmpBytes}, ~c", _} = "]
          {{:no_attr, ~c"ObjFun"}, emit}

        _ ->
          case r_type(type, :tablecinf) do
            [{:objfun, _}] ->
              {{:no_attr, ~c"ObjFun"}, []}

            _ ->
              {false, []}
          end
      end

    gen_enc_line(erules, topType, cname, type, ~c"element(2,Val)", 9, :mandatory, assign, encobj)

    case {r_type(type, :def), encobj} do
      {r_ObjectClassFieldType(), {:no_attr, ~c"ObjFun"}} ->
        emit([~c",", :nl, indent(9), ~c"{", {:curr, :encBytes}, ~c", ", {:curr, :encLen}, ~c"}"])

      _ ->
        :ok
    end

    emit([~c";", :nl])

    case t do
      [] ->
        emit([
          indent(6),
          ~c"Else -> ",
          :nl,
          indent(9),
          ~c"exit({error,{asn1,{invalid_choice_type,Else}}})"
        ])

      _ ->
        true
    end

    gen_enc_choice2(erules, topType, t)
  end

  defp gen_enc_choice2(_Erules, _TopType, []) do
    true
  end

  defp gen_dec_choice(erules, topType, _ChTag, compList, ext) do
    :asn1ct_name.clear()
    :asn1ct_name.new(:tlv)

    emit([
      {:curr, :tlv},
      ~c" = ",
      {:call, :ber, :match_tags, [{:prev, :tlv}, ~c"TagIn"]},
      :com,
      :nl
    ])

    :asn1ct_name.new(:tlv)
    :asn1ct_name.new(:v)

    emit([
      ~c"case (case ",
      {:prev, :tlv},
      ~c" of [Ctemp",
      {:prev, :tlv},
      ~c"] -> Ctemp",
      {:prev, :tlv},
      ~c"; _ -> ",
      {:prev, :tlv},
      ~c" end)",
      ~c" of",
      :nl
    ])

    :asn1ct_name.new(:tagList)
    :asn1ct_name.new(:choTags)
    :asn1ct_name.new(:res)
    gen_dec_choice_cases(erules, topType, compList)
    emit([indent(6), {:curr, :else}, ~c" -> ", :nl])

    case ext do
      :noext ->
        emit([
          indent(9),
          ~c"exit({error,{asn1,{invalid_choice_tag,",
          {:curr, :else},
          ~c"}}})",
          :nl
        ])

      _ ->
        emit([
          indent(9),
          ~c"{asn1_ExtAlt,",
          {:call, :ber, :ber_encode, [{:curr, :else}]},
          ~c"}",
          :nl
        ])
    end

    emit([indent(3), ~c"end", :nl])
    :asn1ct_name.new(:tag)
    :asn1ct_name.new(:else)
  end

  defp gen_dec_choice_cases(_Erules, _TopType, []) do
    :ok
  end

  defp gen_dec_choice_cases(erules, topType, [h | t]) do
    cname = r_ComponentType(h, :name)
    type = r_ComponentType(h, :typespec)
    prop = r_ComponentType(h, :prop)
    tags = r_type(type, :tag)

    fcases = fn
      [{t1class, t1number} | tail], fun ->
        emit([
          indent(4),
          {:curr, :v},
          ~c" = {",
          :asn1ct_gen_ber_bin_v2.decode_class(t1class) <<< (10 + t1number),
          ~c",_} -> ",
          :nl
        ])

        emit([indent(8), ~c"{", {:asis, cname}, ~c", "])
        gen_dec_line(erules, topType, cname, [], type, prop)
        emit([~c"};", :nl, :nl])
        fun.(tail, fun)

      [], _ ->
        :ok
    end

    emit([:nl, ~c"%% '", cname, ~c"'", :nl])

    case {tags, :asn1ct.get_gen_state_field(:namelist)} do
      {[], _} ->
        fcases.(r_ComponentType(h, :tags), fcases)

      {[firstT | _RestT], [{^cname, :undecoded} | names]} ->
        decTag =
          :asn1ct_gen_ber_bin_v2.decode_class(r_tag(firstT, :class)) <<<
            (10 + r_tag(firstT, :number))

        :asn1ct.add_generated_refed_func({[cname | topType], :undecoded, [decTag], type})
        :asn1ct.update_gen_state(:namelist, names)

        emit([
          indent(4),
          {:curr, :res},
          ~c" = ",
          match_tag(
            r_tag(firstT, :class),
            r_tag(firstT, :number)
          ),
          ~c" -> ",
          :nl
        ])

        emit([
          indent(8),
          ~c"{",
          {:asis, cname},
          ~c", {'",
          :asn1ct_gen.list2name([
            cname
            | topType
          ]),
          ~c"',",
          {:curr, :res},
          ~c"}};",
          :nl,
          :nl
        ])

      {[firstT | restT], _} ->
        emit([
          indent(4),
          ~c"{",
          :asn1ct_gen_ber_bin_v2.decode_class(r_tag(firstT, :class)) <<<
            (10 + r_tag(firstT, :number)),
          ~c", ",
          {:curr, :v},
          ~c"} -> ",
          :nl
        ])

        emit([indent(8), ~c"{", {:asis, cname}, ~c", "])
        gen_dec_line(erules, topType, cname, [], r_type(type, tag: restT), prop)
        emit([~c"};", :nl, :nl])
    end

    gen_dec_choice_cases(erules, topType, t)
  end

  defp match_tag(class, tagNo) when is_integer(tagNo) do
    match_tag1(
      :asn1ct_gen_ber_bin_v2.decode_class(class),
      tagNo
    )
  end

  defp match_tag1(class, tagNo) when tagNo <= 30 do
    :io_lib.format(~c"<<~p:2,_:1,~p:5,_/binary>>", [class >>> 6, tagNo])
  end

  defp match_tag1(class, tagNo) do
    octets = mk_object_val(tagNo)
    :io_lib.format(~c"<<~p:2,_:1,31:5,~s,_/binary>>", [class >>> 6, octets])
  end

  defp mk_object_val(val) when val < 128 do
    :erlang.integer_to_list(val)
  end

  defp mk_object_val(val) do
    mk_object_val(
      val >>> 7,
      [:erlang.integer_to_list(val &&& 127)]
    )
  end

  defp mk_object_val(0, acc) do
    acc
  end

  defp mk_object_val(val, acc) do
    i = :erlang.integer_to_list((val &&& 127) ||| 128)
    mk_object_val(val >>> 7, [i, ~c"," | acc])
  end

  defp gen_enc_line(
         erules,
         topType,
         cname,
         type = r_type(constraint: c, def: r_ObjectClassFieldType(type: {:typefield, _})),
         element,
         indent,
         optOrMand = :mandatory,
         encObj
       )
       when is_list(element) do
    case :asn1ct_gen.get_constraint(
           c,
           :componentrelation
         ) do
      {:componentrelation, _, _} ->
        gen_enc_line(
          erules,
          topType,
          cname,
          type,
          element,
          indent,
          optOrMand,
          [~c"{", {:curr, :tmpBytes}, ~c",_} = "],
          encObj
        )

      _ ->
        gen_enc_line(
          erules,
          topType,
          cname,
          type,
          element,
          indent,
          optOrMand,
          [~c"{", {:curr, :encBytes}, ~c",", {:curr, :encLen}, ~c"} = "],
          encObj
        )
    end
  end

  defp gen_enc_line(erules, topType, cname, type, element, indent, optOrMand, encObj)
       when is_list(element) do
    gen_enc_line(
      erules,
      topType,
      cname,
      type,
      element,
      indent,
      optOrMand,
      [~c"{", {:curr, :encBytes}, ~c",", {:curr, :encLen}, ~c"} = "],
      encObj
    )
  end

  defp gen_enc_line(erules, topType, cname, type, element, indent, optOrMand, assign, encObj)
       when is_list(element) do
    indDeep = indent(indent)

    tag =
      :lists.reverse(
        for x <- r_type(type, :tag) do
          :asn1ct_gen_ber_bin_v2.encode_tag_val(
            :asn1ct_gen_ber_bin_v2.decode_class(r_tag(x, :class)),
            r_tag(x, :form),
            r_tag(x, :number)
          )
        end
      )

    innerType = :asn1ct_gen.get_inner(r_type(type, :def))
    whatKind = :asn1ct_gen.type(innerType)
    emit(indDeep)
    emit(assign)
    gen_optormand_case(optOrMand, erules, topType, cname, type, element)

    case {type,
          :asn1ct_gen.get_constraint(
            r_type(type, :constraint),
            :componentrelation
          )} do
      {r_type(
         def:
           r_ObjectClassFieldType(
             type: {:typefield, _},
             fieldname: refedFieldName
           )
       ), {:componentrelation, _, _}} ->
        {_LeadingAttrName, fun} = encObj
        {name, restFieldNames} = refedFieldName
        true = is_atom(name)

        case optOrMand do
          :mandatory ->
            :ok

          _ ->
            emit([~c"{", {:curr, :tmpBytes}, ~c",_ } = "])
        end

        emit([
          fun,
          ~c"(",
          {:asis, name},
          ~c", ",
          element,
          ~c", ",
          {:asis, restFieldNames},
          ~c"),",
          :nl
        ])

        emit(indDeep)

        case optOrMand do
          :mandatory ->
            emit([
              ~c"{",
              {:curr, :encBytes},
              ~c",",
              {:curr, :encLen},
              ~c"} = ",
              {:call, :ber, :encode_open_type, [{:curr, :tmpBytes}, {:asis, tag}]},
              :nl
            ])

          _ ->
            emit([{:call, :ber, :encode_open_type, [{:curr, :tmpBytes}, {:asis, tag}]}])
        end

      _ ->
        case whatKind do
          {:primitive, :bif} ->
            :asn1ct_gen_ber_bin_v2.gen_encode_prim(:ber, type, {:asis, tag}, element)

          :ASN1_OPEN_TYPE ->
            case r_type(type, :def) do
              r_ObjectClassFieldType() ->
                :asn1ct_gen_ber_bin_v2.gen_encode_prim(
                  :ber,
                  r_type(def: :ASN1_OPEN_TYPE),
                  {:asis, tag},
                  element
                )

              _ ->
                :asn1ct_gen_ber_bin_v2.gen_encode_prim(:ber, type, {:asis, tag}, element)
            end

          _ ->
            {encFunName, _EncMod, _EncFun} = mkfuncname(topType, cname, whatKind, ~c"enc_", ~c"")

            case {whatKind, r_type(type, :tablecinf), encObj} do
              {{:constructed, :bif}, [{:objfun, _} | _R], {_, fun}} ->
                emit([encFunName, ~c"(", element, ~c", ", {:asis, tag}, ~c", ", fun, ~c")"])

              _ ->
                emit([encFunName, ~c"(", element, ~c", ", {:asis, tag}, ~c")"])
            end
        end
    end

    case optOrMand do
      :mandatory ->
        true

      _ ->
        emit([:nl, indent(7), ~c"end"])
    end
  end

  defp gen_optormand_case(:mandatory, _Gen, _TopType, _Cname, _Type, _Element) do
    :ok
  end

  defp gen_optormand_case(:OPTIONAL, gen, _TopType, _Cname, _Type, element) do
    emit([~c" case ", element, ~c" of", :nl])

    missing =
      case gen do
        r_gen(pack: :record) ->
          :asn1_NOVALUE

        r_gen(pack: :map) ->
          :asn1__MISSING_IN_MAP
      end

    emit([indent(9), missing, ~c" -> {", empty_lb(gen), ~c",0};", :nl])
    emit([indent(9), ~c"_ ->", :nl, indent(12)])
  end

  defp gen_optormand_case({:DEFAULT, defaultValue}, gen, _TopType, _Cname, type, element) do
    currMod = :erlang.get(:currmod)

    case gen do
      r_gen(erule: :ber, der: true) ->
        :asn1ct_gen_check.emit(gen, type, defaultValue, element)

      r_gen(erule: :ber, der: false, pack: pack) ->
        ind9 = indent(9)

        defMarker =
          case pack do
            :record ->
              :asn1_DEFAULT

            :map ->
              :asn1__MISSING_IN_MAP
          end

        emit([
          ~c" case ",
          element,
          ~c" of",
          :nl,
          ind9,
          {:asis, defMarker},
          ~c" ->",
          :nl,
          ind9,
          indent(3),
          ~c"{",
          empty_lb(gen),
          ~c",0};",
          :nl,
          ind9,
          ~c"_ when ",
          element,
          ~c" =:= "
        ])

        dv =
          case defaultValue do
            r_Externalvaluereference(module: ^currMod, value: v) ->
              [~c"?", {:asis, v}]

            _ ->
              [{:asis, defaultValue}]
          end

        emit(
          dv ++
            [
              ~c" ->",
              :nl,
              ind9,
              indent(3),
              ~c"{",
              empty_lb(gen),
              ~c",0};",
              :nl,
              ind9,
              ~c"_ ->",
              :nl,
              indent(12)
            ]
        )
    end
  end

  defp gen_dec_line(erules, topType, cname, cTags, type, optOrMand) do
    {[], []} = gen_dec_line(erules, topType, cname, cTags, type, optOrMand, false)
    :ok
  end

  defp gen_dec_line(erules, topType, cname, cTags, type, optOrMand, decObjInf) do
    bytesVar = :asn1ct_gen.mk_var(:asn1ct_name.curr(:v))

    tag =
      for x <- r_type(type, :tag) do
        :asn1ct_gen_ber_bin_v2.decode_class(r_tag(x, :class)) <<< (10 + r_tag(x, :number))
      end

    choiceTags =
      for {class, number} <- cTags do
        :asn1ct_gen_ber_bin_v2.decode_class(class) <<< (10 + number)
      end

    innerType =
      case r_type(type, :def) do
        r_ObjectClassFieldType(type: oCFTType) ->
          oCFTType

        _ ->
          :asn1ct_gen.get_inner(r_type(type, :def))
      end

    postpDec =
      case optOrMand do
        :mandatory ->
          gen_dec_call(
            innerType,
            erules,
            topType,
            cname,
            type,
            bytesVar,
            tag,
            :mandatory,
            ~c", mandatory, ",
            decObjInf,
            optOrMand
          )

        _ ->
          {firstTag, restTag} =
            case tag do
              [] ->
                {choiceTags, []}

              [ft | rt] ->
                {ft, rt}
            end

          emit([~c"case ", {:prev, :tlv}, ~c" of", :nl])

          postponedDec =
            case tag do
              [] when length(choiceTags) > 0 ->
                fcases = fn firstTag1 ->
                  emit([
                    ~c"[",
                    {:curr, :v},
                    ~c" = {",
                    {:asis, firstTag1},
                    ~c",_}|Temp",
                    {:curr, :tlv},
                    ~c"] ->",
                    :nl
                  ])

                  emit([indent(4), ~c"{"])

                  pdec =
                    gen_dec_call(
                      innerType,
                      erules,
                      topType,
                      cname,
                      type,
                      bytesVar,
                      restTag,
                      :mandatory,
                      ~c", mandatory, ",
                      decObjInf,
                      optOrMand
                    )

                  emit([~c", Temp", {:curr, :tlv}, ~c"}"])
                  emit([~c";", :nl])
                  pdec
                end

                hd(
                  for tmpTag <- firstTag do
                    fcases.(tmpTag)
                  end
                )

              [] ->
                emit([~c"[", {:curr, :v}, ~c"|Temp", {:curr, :tlv}, ~c"] ->", :nl])
                emit([indent(4), ~c"{"])

                pdec =
                  gen_dec_call(
                    innerType,
                    erules,
                    topType,
                    cname,
                    type,
                    bytesVar,
                    restTag,
                    :mandatory,
                    ~c", mandatory, ",
                    decObjInf,
                    optOrMand
                  )

                emit([~c", Temp", {:curr, :tlv}, ~c"}"])
                emit([~c";", :nl])
                pdec

              _ ->
                emit([
                  ~c"[{",
                  {:asis, firstTag},
                  ~c",",
                  {:curr, :v},
                  ~c"}|Temp",
                  {:curr, :tlv},
                  ~c"] ->",
                  :nl
                ])

                emit([indent(4), ~c"{"])

                pdec =
                  gen_dec_call(
                    innerType,
                    erules,
                    topType,
                    cname,
                    type,
                    bytesVar,
                    restTag,
                    :mandatory,
                    ~c", mandatory, ",
                    decObjInf,
                    optOrMand
                  )

                emit([~c", Temp", {:curr, :tlv}, ~c"}"])
                emit([~c";", :nl])
                pdec
            end

          emit([indent(4), ~c"_ ->", :nl])

          case optOrMand do
            {:DEFAULT, def0} ->
              def__ = :asn1ct_gen.conform_value(type, def0)
              emit([indent(8), ~c"{", {:asis, def__}, ~c",", {:prev, :tlv}, ~c"}", :nl])

            :OPTIONAL ->
              emit([indent(8), ~c"{ asn1_NOVALUE, ", {:prev, :tlv}, ~c"}", :nl])
          end

          emit([~c"end"])
          postponedDec
      end

    case decObjInf do
      {^cname, objSet} ->
        objSetName =
          case objSet do
            {:deep, oSName, _, _} ->
              oSName

            _ ->
              objSet
          end

        {[{objSetName, cname, :asn1ct_gen.mk_var(:asn1ct_name.curr(:term))}], postpDec}

      _ ->
        {[], postpDec}
    end
  end

  defp gen_dec_call({:typefield, _}, _, _, _Cname, type, bytesVar, tag, _, _, false, _) do
    :asn1ct_name.new(:reason)
    :asn1ct_name.new(:opendec)
    :asn1ct_name.new(:tmpterm)
    :asn1ct_name.new(:tmptlv)
    {firstPFName, restPFName} = r_ObjectClassFieldType(r_type(type, :def), :fieldname)
    emit([:nl, indent(6), ~c"begin", :nl])

    emit([
      indent(9),
      {:curr, :tmptlv},
      ~c" = ",
      {:call, :ber, :decode_open_type, [bytesVar, {:asis, tag}]},
      :com,
      :nl
    ])

    emit([
      indent(9),
      ~c"case (catch ObjFun(",
      {:asis, firstPFName},
      ~c", ",
      {:curr, :tmptlv},
      ~c", ",
      {:asis, restPFName},
      ~c")) of",
      :nl
    ])

    emit([indent(12), ~c"{'EXIT',", {:curr, :reason}, ~c"} ->", :nl])

    emit([
      indent(15),
      ~c"exit({'Type not ",
      ~c"compatible with table constraint', ",
      {:curr, :reason},
      ~c"});",
      :nl
    ])

    emit([indent(12), {:curr, :tmpterm}, ~c" ->", :nl])
    emit([indent(15), {:curr, :tmpterm}, :nl])
    emit([indent(9), ~c"end", :nl, indent(6), ~c"end", :nl])
    []
  end

  defp gen_dec_call(
         {:typefield, _},
         _,
         _,
         cname,
         type,
         bytesVar,
         tag,
         _,
         _,
         _DecObjInf,
         optOrMandComp
       ) do
    call(:decode_open_type, [bytesVar, {:asis, tag}])
    refedFieldName = r_ObjectClassFieldType(r_type(type, :def), :fieldname)

    [
      {cname, refedFieldName, :asn1ct_gen.mk_var(:asn1ct_name.curr(:term)),
       :asn1ct_gen.mk_var(:asn1ct_name.curr(:tmpterm)), tag, optOrMandComp}
    ]
  end

  defp gen_dec_call(
         innerType,
         gen,
         topType,
         cname,
         type,
         bytesVar,
         tag,
         _PrimOptOrMand,
         _OptOrMand,
         decObjInf,
         _
       ) do
    whatKind = :asn1ct_gen.type(innerType)
    gen_dec_call1(whatKind, innerType, topType, cname, type, bytesVar, tag)

    case decObjInf do
      {^cname, {_, oSet, _UniqueFName, valIndex}} ->
        term = :asn1ct_gen.mk_var(:asn1ct_name.curr(:term))
        valueMatch = value_match(gen, valIndex, term)
        {objSetMod, objSetName} = oSet

        emit([
          ~c",",
          :nl,
          ~c"ObjFun = ",
          {:asis, objSetMod},
          ~c":'getdec_",
          objSetName,
          ~c"'(",
          valueMatch,
          ~c")"
        ])

      _ ->
        :ok
    end

    []
  end

  defp gen_dec_call1({:primitive, :bif}, innerType, topType, cname, type, bytesVar, tag) do
    case {:asn1ct.get_gen_state_field(:namelist), innerType} do
      {[{^cname, :undecoded} | rest], _} ->
        :asn1ct.add_generated_refed_func({[cname | topType], :undecoded, tag, type})
        :asn1ct.update_gen_state(:namelist, rest)
        emit([~c"{'", :asn1ct_gen.list2name([cname | topType]), ~c"',", bytesVar, ~c"}"])

      _ ->
        :asn1ct_gen_ber_bin_v2.gen_dec_prim(type, bytesVar, tag)
    end
  end

  defp gen_dec_call1(:ASN1_OPEN_TYPE, _InnerType, topType, cname, type, bytesVar, tag) do
    case {:asn1ct.get_gen_state_field(:namelist), r_type(type, :def)} do
      {[{^cname, :undecoded} | rest], _} ->
        :asn1ct.add_generated_refed_func({[cname | topType], :undecoded, tag, type})
        :asn1ct.update_gen_state(:namelist, rest)
        emit([~c"{'", :asn1ct_gen.list2name([cname | topType]), ~c"',", bytesVar, ~c"}"])

      {_, r_ObjectClassFieldType(type: openType)} ->
        :asn1ct_gen_ber_bin_v2.gen_dec_prim(r_type(def: openType), bytesVar, tag)

      _ ->
        :asn1ct_gen_ber_bin_v2.gen_dec_prim(type, bytesVar, tag)
    end
  end

  defp gen_dec_call1(whatKind, _, topType, cname, type, bytesVar, tag) do
    case :asn1ct.get_gen_state_field(:namelist) do
      [{^cname, :undecoded} | rest] ->
        :asn1ct.add_generated_refed_func({[cname | topType], :undecoded, tag, type})
        :asn1ct.update_gen_state(:namelist, rest)
        emit([~c"{'", :asn1ct_gen.list2name([cname | topType]), ~c"',", bytesVar, ~c"}"])

      _ ->
        emitDecFunCall = fn funcName ->
          case {whatKind, r_type(type, :tablecinf)} do
            {{:constructed, :bif}, [{:objfun, _} | _Rest]} ->
              emit([funcName, ~c"(", bytesVar, ~c", ", {:asis, tag}, ~c", ObjFun)"])

            _ ->
              emit([funcName, ~c"(", bytesVar, ~c", ", {:asis, tag}, ~c")"])
          end
        end

        case :asn1ct.get_gen_state_field(:namelist) do
          [{^cname, list} | rest] when is_list(list) ->
            sindex =
              case whatKind do
                r_Externaltypereference() ->
                  sI = :asn1ct.maybe_saved_sindex(whatKind, list)
                  saves = {whatKind, sI, list}
                  :asn1ct.add_tobe_refed_func(saves)
                  sI

                _ ->
                  sI =
                    :asn1ct.maybe_saved_sindex(
                      [cname | topType],
                      list
                    )

                  saves = {[cname | topType], sI, list, type}
                  :asn1ct.add_tobe_refed_func(saves)
                  sI
              end

            :asn1ct.update_gen_state(:namelist, rest)
            prefix = :asn1ct.get_gen_state_field(:prefix)

            suffix =
              case sindex do
                i when is_integer(i) and i > 0 ->
                  :lists.concat([~c"_", i])

                _ ->
                  ~c""
              end

            {decFunName, _, _} = mkfuncname(topType, cname, whatKind, prefix, suffix)
            emitDecFunCall.(decFunName)

          [{^cname, :parts} | rest] ->
            :asn1ct.update_gen_state(:namelist, rest)
            :asn1ct.get_gen_state_field(:prefix)
            :asn1ct.add_generated_refed_func({[cname | topType], :parts, [], type})
            emit([~c"{'", :asn1ct_gen.list2name([cname | topType]), ~c"',"])
            :asn1ct_func.need({:ber, :match_tags, 2})
            emitDecFunCall.(~c"match_tags")
            emit(~c"}")

          _ ->
            {decFunName, _, _} = mkfuncname(topType, cname, whatKind, ~c"dec_", ~c"")
            emitDecFunCall.(decFunName)
        end
    end
  end

  defp indent(n) do
    :lists.duplicate(n, 32)
  end

  defp mkvlist([h, t1 | t], sep) do
    emit([{:var, h}, sep])
    mkvlist([t1 | t], sep)
  end

  defp mkvlist([h | t], sep) do
    emit([{:var, h}])
    mkvlist(t, sep)
  end

  defp mkvlist([], _) do
    true
  end

  defp mkvlist(l) do
    mkvlist(l, ~c", ")
  end

  defp mkvplus(l) do
    mkvlist(l, ~c" + ")
  end

  defp extensible(compList) when is_list(compList) do
    :noext
  end

  defp extensible({rootList, extList}) do
    {:ext, length(rootList) + 1, length(extList)}
  end

  defp extensible({_Rl1, _Ext, _Rl2}) do
    :extensible
  end

  defp filter_complist(compList) when is_list(compList) do
    :lists.filter(
      fn
        r_ExtensionAdditionGroup() ->
          false

        :ExtensionAdditionGroupEnd ->
          false

        _ ->
          true
      end,
      compList
    )
  end

  defp filter_complist({root, ext}) do
    {root, filter_complist(ext)}
  end

  defp filter_complist({root1, ext, root2}) do
    {root1, filter_complist(ext), root2}
  end

  defp print_attribute_comment(innerType, pos, cname, prop) do
    commentLine = ~c"%%-------------------------------------------------"
    emit([:nl, commentLine])

    case innerType do
      r_Externaltypereference(module: xModule, type: name) ->
        emit([:nl, ~c"%% attribute ", cname, ~c"(", pos, ~c")   External ", xModule, ~c":", name])

      _ when is_tuple(innerType) ->
        emit([
          :nl,
          ~c"%% attribute ",
          cname,
          ~c"(",
          pos,
          ~c") with type "
          | :erlang.tuple_to_list(innerType)
        ])

      _ ->
        emit([:nl, ~c"%% attribute ", cname, ~c"(", pos, ~c") with type ", innerType])
    end

    case prop do
      :mandatory ->
        :continue

      {:DEFAULT, def__} ->
        emit([~c" DEFAULT = ", {:asis, def__}])

      :OPTIONAL ->
        emit([~c" OPTIONAL"])
    end

    emit([:nl, commentLine, :nl])
  end

  defp mkfuncname(topType, cname, whatKind, prefix, suffix) do
    currMod = :erlang.get(:currmod)

    case whatKind do
      r_Externaltypereference(module: ^currMod, type: eType) ->
        f = :lists.concat([~c"'", prefix, eType, suffix, ~c"'"])
        {f, ~c"?MODULE", f}

      r_Externaltypereference(module: mod, type: eType) ->
        {:lists.concat([~c"'", mod, ~c"':'", prefix, eType, suffix, ~c"'"]), mod,
         :lists.concat([~c"'", prefix, eType, ~c"'"])}

      {:constructed, :bif} ->
        f =
          :lists.concat([~c"'", prefix, :asn1ct_gen.list2name([cname | topType]), suffix, ~c"'"])

        {f, ~c"?MODULE", f}
    end
  end

  defp empty_lb(r_gen(erule: :ber)) do
    ~c"<<>>"
  end

  defp value_match(r_gen(pack: :record), vIs, value) do
    value_match_rec(vIs, value)
  end

  defp value_match(r_gen(pack: :map), vIs, value) do
    value_match_map(vIs, value)
  end

  defp value_match_rec([], value) do
    value
  end

  defp value_match_rec([{vI, _} | vIs], value0) do
    value = value_match_rec(vIs, value0)
    :lists.concat([~c"element(", vI, ~c", ", value, ~c")"])
  end

  defp value_match_map([], value) do
    value
  end

  defp value_match_map([{_, name} | vIs], value0) do
    value = value_match_map(vIs, value0)
    :lists.concat([~c"maps:get(", name, ~c", ", value, ~c")"])
  end

  defp call(f, args) do
    :asn1ct_func.call(:ber, f, args)
  end
end
