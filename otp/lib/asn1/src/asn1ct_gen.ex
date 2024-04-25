defmodule :m_asn1ct_gen do
  use Bitwise
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

  def pgen(outFile, r_gen(options: options) = gen, code) do
    r_abst(name: module, types: types) = code

    n2nConvEnums =
      for {:n2n, cName} <- options do
        cName
      end

    case n2nConvEnums -- types do
      [] ->
        :ok

      unmatchedTypes ->
        exit({~c"Non existing ENUMERATION types used in n2n option", unmatchedTypes})
    end

    :erlang.put(:outfile, outFile)
    :erlang.put(:currmod, module)
    hrlGenerated = pgen_hrl(gen, code)
    :asn1ct_name.start()
    erlFile = :lists.concat([outFile, ~c".erl"])
    _ = open_output_file(erlFile)
    :asn1ct_func.start_link()
    gen_head(gen, module, hrlGenerated)
    pgen_exports(gen, code)
    pgen_dispatcher(gen, types)
    pgen_info()
    pgen_typeorval(gen, n2nConvEnums, code)
    pgen_partial_incomplete_decode(gen)
    emit([:nl, ~c"%%%", :nl, ~c"%%% Run-time functions.", :nl, ~c"%%%", :nl])
    dialyzer_suppressions(gen)
    fd = :erlang.get(:gen_file_out)
    :asn1ct_func.generate(fd)
    close_output_file()
    _ = :erlang.erase(:outfile)
    :asn1ct.verbose(~c"--~p--~n", [{:generated, erlFile}], gen)
    :ok
  end

  defp dialyzer_suppressions(erules) do
    emit([:nl, {:asis, :"dialyzer-suppressions"}, ~c"(Arg) ->", :nl])
    rtmod = ct_gen_module(erules)
    rtmod.dialyzer_suppressions(erules)
  end

  defp pgen_typeorval(erules, n2nConvEnums, code) do
    r_abst(name: module, types: types, values: values, objects: objects, objsets: objectSets) =
      code

    rtmod = ct_gen_module(erules)
    pgen_types(rtmod, erules, n2nConvEnums, module, types)

    case erules do
      r_gen(erule: :jer) ->
        pgen_objects(rtmod, erules, module, objects)
        pgen_objectsets(rtmod, erules, module, objectSets)

        emit([
          ~c"typeinfo(Type) ->",
          :nl,
          ~c"  exit({error,{asn1,{undefined_type,Type}}}).",
          :nl,
          :nl
        ])

        pgen_values(values, module)

      r_gen() ->
        pgen_values(values, module)
        pgen_objects(rtmod, erules, module, objects)
        pgen_objectsets(rtmod, erules, module, objectSets)
    end

    pgen_partial_decode(rtmod, erules, module)

    case r_gen(erules, :jer) do
      true ->
        newErules = r_gen(erules, erule: :jer, jer: false)
        jER_Rtmod = ct_gen_module(newErules)
        pgen_types(jER_Rtmod, r_gen(erules, erule: :jer, jer: false), [], module, types)

        emit([
          ~c"typeinfo(Type) ->",
          :nl,
          ~c"  exit({error,{asn1,{undefined_type,Type}}}).",
          :nl,
          :nl
        ])

      false ->
        :ok
    end
  end

  defp pgen_values([h | t], module) do
    r_valuedef(name: name, value: value) = :asn1_db.dbget(module, h)
    emit([{:asis, name}, ~c"() ->", :nl, {:asis, value}, ~c".", :nl, :nl])
    pgen_values(t, module)
  end

  defp pgen_values([], _) do
    :ok
  end

  defp pgen_types(_, _, _, _, []) do
    :ok
  end

  defp pgen_types(rtmod, erules, n2nConvEnums, module, [h | t]) do
    :asn1ct_name.clear()
    typedef = :asn1_db.dbget(module, h)
    rtmod.gen_encode(erules, typedef)
    :asn1ct_name.clear()
    rtmod.gen_decode(erules, typedef)

    case :lists.member(h, n2nConvEnums) do
      true ->
        pgen_n2nconversion(erules, typedef)

      _ ->
        true
    end

    pgen_types(rtmod, erules, n2nConvEnums, module, t)
  end

  defp pgen_n2nconversion(
         _Erules,
         r_typedef(
           name: typeName,
           typespec: r_type(def: {:ENUMERATED, {nN1, nN2}})
         )
       ) do
    nN = nN1 ++ nN2
    pgen_name2numfunc(typeName, nN, :extension_marker)
    pgen_num2namefunc(typeName, nN, :extension_marker)
  end

  defp pgen_n2nconversion(
         _Erules,
         r_typedef(
           name: typeName,
           typespec: r_type(def: {:ENUMERATED, nN})
         )
       ) do
    pgen_name2numfunc(typeName, nN, :no_extension_marker)
    pgen_num2namefunc(typeName, nN, :no_extension_marker)
  end

  defp pgen_n2nconversion(_Erules, _) do
    true
  end

  defp pgen_name2numfunc(typeNameAsAtom, mapping, ext)
       when is_atom(typeNameAsAtom) do
    funcName = :erlang.list_to_atom(~c"name2num_" ++ :erlang.atom_to_list(typeNameAsAtom))
    pgen_name2numfunc1(funcName, mapping, ext)
  end

  defp pgen_name2numfunc1(_FuncName, [], _) do
    true
  end

  defp pgen_name2numfunc1(funcName, [{atom, number}], :extension_marker) do
    emit([{:asis, funcName}, ~c"(", {:asis, atom}, ~c") ->", number, ~c";", :nl])
    emit([{:asis, funcName}, ~c"({asn1_enum, Num}) -> Num.", :nl, :nl])
  end

  defp pgen_name2numfunc1(funcName, [{atom, number}], _) do
    emit([{:asis, funcName}, ~c"(", {:asis, atom}, ~c") ->", number, ~c".", :nl, :nl])
  end

  defp pgen_name2numfunc1(funcName, [{atom, number} | nNRest], eM) do
    emit([{:asis, funcName}, ~c"(", {:asis, atom}, ~c") ->", number, ~c";", :nl])
    pgen_name2numfunc1(funcName, nNRest, eM)
  end

  defp pgen_num2namefunc(typeNameAsAtom, mapping, ext)
       when is_atom(typeNameAsAtom) do
    funcName = :erlang.list_to_atom(~c"num2name_" ++ :erlang.atom_to_list(typeNameAsAtom))
    pgen_num2namefunc1(funcName, mapping, ext)
  end

  defp pgen_num2namefunc1(_FuncName, [], _) do
    true
  end

  defp pgen_num2namefunc1(funcName, [{atom, number}], :extension_marker) do
    emit([{:asis, funcName}, ~c"(", number, ~c") ->", {:asis, atom}, ~c";", :nl])
    emit([{:asis, funcName}, ~c"(ExtensionNum) -> {asn1_enum, ExtensionNum}.", :nl, :nl])
  end

  defp pgen_num2namefunc1(funcName, [{atom, number}], _) do
    emit([{:asis, funcName}, ~c"(", number, ~c") ->", {:asis, atom}, ~c".", :nl, :nl])
  end

  defp pgen_num2namefunc1(funcName, [{atom, number} | nNRest], eM) do
    emit([{:asis, funcName}, ~c"(", number, ~c") ->", {:asis, atom}, ~c";", :nl])
    pgen_num2namefunc1(funcName, nNRest, eM)
  end

  defp pgen_objects(_, _, _, []) do
    true
  end

  defp pgen_objects(rtmod, erules, module, [h | t]) do
    :asn1ct_name.clear()
    typedef = :asn1_db.dbget(module, h)
    rtmod.gen_obj_code(erules, module, typedef)
    pgen_objects(rtmod, erules, module, t)
  end

  defp pgen_objectsets(_, _, _, []) do
    true
  end

  defp pgen_objectsets(rtmod, erules, module, [h | t]) do
    :asn1ct_name.clear()
    typeDef = :asn1_db.dbget(module, h)
    rtmod.gen_objectset_code(erules, typeDef)
    pgen_objectsets(rtmod, erules, module, t)
  end

  defp pgen_partial_decode(rtmod, r_gen(erule: :ber) = gen, module) do
    pgen_partial_inc_dec(rtmod, gen, module)
    pgen_partial_dec(rtmod, gen, module)
  end

  defp pgen_partial_decode(_, _, _) do
    :ok
  end

  defp pgen_partial_inc_dec(rtmod, erules, module) do
    case :asn1ct.get_gen_state_field(:inc_type_pattern) do
      :undefined ->
        :ok

      confList ->
        patternLists =
          :lists.map(
            fn {_, p} ->
              p
            end,
            confList
          )

        pgen_partial_inc_dec1(rtmod, erules, module, patternLists)
        gen_partial_inc_dec_refed_funcs(rtmod, erules)
    end
  end

  defp pgen_partial_inc_dec1(rtmod, erules, module, [p | ps]) do
    topTypeName = :asn1ct.partial_inc_dec_toptype(p)
    typeDef = :asn1_db.dbget(module, topTypeName)
    :asn1ct_name.clear()
    :asn1ct.update_gen_state(:namelist, p)
    :asn1ct.update_gen_state(:active, true)
    :asn1ct.update_gen_state(:prefix, ~c"dec-inc-")

    case :asn1ct.maybe_saved_sindex(topTypeName, p) do
      i when is_integer(i) and i > 0 ->
        :asn1ct.set_current_sindex(i)

      _I ->
        :asn1ct.set_current_sindex(0)
        :ok
    end

    rtmod.gen_decode(erules, typeDef)
    gen_dec_part_inner_constr(rtmod, erules, typeDef, [topTypeName])
    pgen_partial_inc_dec1(rtmod, erules, module, ps)
  end

  defp pgen_partial_inc_dec1(_, _, _, []) do
    :ok
  end

  defp gen_partial_inc_dec_refed_funcs(rtmod, r_gen(erule: :ber) = gen) do
    case :asn1ct.next_refed_func() do
      [] ->
        :ok

      {r_Externaltypereference(module: m, type: name), sindex, pattern} ->
        typeDef = :asn1_db.dbget(m, name)
        :asn1ct.update_gen_state(:namelist, pattern)
        :asn1ct.set_current_sindex(sindex)
        rtmod.gen_inc_decode(gen, typeDef)
        gen_dec_part_inner_constr(rtmod, gen, typeDef, [name])
        gen_partial_inc_dec_refed_funcs(rtmod, gen)

      {name, sindex, pattern, type} ->
        typeDef =
          r_typedef(
            name: :asn1ct_gen.list2name(name),
            typespec: type
          )

        :asn1ct.update_gen_state(:namelist, pattern)
        :asn1ct.set_current_sindex(sindex)
        rtmod.gen_inc_decode(gen, typeDef)
        gen_dec_part_inner_constr(rtmod, gen, typeDef, name)
        gen_partial_inc_dec_refed_funcs(rtmod, gen)
    end
  end

  defp pgen_partial_dec(_Rtmod, erules, _Module) do
    type_pattern = :asn1ct.get_gen_state_field(:type_pattern)
    pgen_partial_types(erules, type_pattern)
    :ok
  end

  defp pgen_partial_types(r_gen(options: options) = gen, typePattern) do
    case :lists.member(:asn1config, options) do
      true ->
        pgen_partial_types1(gen, typePattern)

      false ->
        :ok
    end
  end

  defp pgen_partial_types1(
         erules,
         [{funcName, [topType | restTypes]} | rest]
       ) do
    currMod = :erlang.get(:currmod)
    typeDef = :asn1_db.dbget(currMod, topType)
    traverse_type_structure(erules, typeDef, restTypes, funcName, r_typedef(typeDef, :name))
    pgen_partial_types1(erules, rest)
  end

  defp pgen_partial_types1(_, []) do
    :ok
  end

  defp pgen_partial_types1(_, :undefined) do
    :ok
  end

  defp traverse_type_structure(erules, type, [], funcName, topTypeName) do
    ctmod = ct_gen_module(erules)

    typeDef =
      case type do
        r_type() ->
          r_typedef(name: topTypeName, typespec: type)

        r_typedef() ->
          type
      end

    ctmod.gen_decode_selected(erules, typeDef, funcName)
  end

  defp traverse_type_structure(erules, r_type(def: def__), [[n]], funcName, topTypeName)
       when is_integer(n) do
    innerType = :asn1ct_gen.get_inner(def__)

    case innerType do
      :"SEQUENCE OF" ->
        {_, type} = def__
        traverse_type_structure(erules, type, [], funcName, topTypeName)

      wrongType ->
        exit(
          {:error,
           {:configuration_file_error, [n], ~c"only for SEQUENCE OF components", wrongType}}
        )
    end
  end

  defp traverse_type_structure(erules, type, [[n] | ts], funcName, topTypeName)
       when is_integer(n) do
    traverse_type_structure(erules, type, ts, funcName, topTypeName)
  end

  defp traverse_type_structure(erules, r_type(def: def__), [t | ts], funcName, topTypeName) do
    innerType = :asn1ct_gen.get_inner(def__)

    case innerType do
      :SET ->
        r_SET(components: components) = def__
        c = get_component(t, components)

        traverse_type_structure(erules, r_ComponentType(c, :typespec), ts, funcName, [
          t | topTypeName
        ])

      :SEQUENCE ->
        r_SEQUENCE(components: components) = def__
        c = get_component(t, components)

        traverse_type_structure(erules, r_ComponentType(c, :typespec), ts, funcName, [
          t | topTypeName
        ])

      :CHOICE ->
        {_, components} = def__
        c = get_component(t, components)

        traverse_type_structure(erules, r_ComponentType(c, :typespec), ts, funcName, [
          t | topTypeName
        ])

      :"SEQUENCE OF" ->
        {_, type} = def__
        traverse_SO_type_structure(erules, type, [t | ts], funcName, topTypeName)

      :"SET OF" ->
        {_, type} = def__
        traverse_SO_type_structure(erules, type, [t | ts], funcName, topTypeName)

      r_Externaltypereference(module: m, type: tName) ->
        typeDef = :asn1_db.dbget(m, tName)
        traverse_type_structure(erules, typeDef, [t | ts], funcName, [r_typedef(typeDef, :name)])

      _ ->
        traverse_type_structure(erules, def__, ts, funcName, [t | topTypeName])
    end
  end

  defp traverse_type_structure(
         erules,
         r_typedef(typespec: def__),
         [t | ts],
         funcName,
         topTypeName
       ) do
    innerType = :asn1ct_gen.get_inner(r_type(def__, :def))

    case innerType do
      :SET ->
        r_SET(components: components) = r_type(def__, :def)
        c = get_component(t, components)

        traverse_type_structure(erules, r_ComponentType(c, :typespec), ts, funcName, [
          t | topTypeName
        ])

      :SEQUENCE ->
        r_SEQUENCE(components: components) = r_type(def__, :def)
        c = get_component(t, components)

        traverse_type_structure(erules, r_ComponentType(c, :typespec), ts, funcName, [
          t | topTypeName
        ])

      :CHOICE ->
        {_, components} = r_type(def__, :def)
        c = get_component(t, components)

        traverse_type_structure(erules, r_ComponentType(c, :typespec), ts, funcName, [
          t | topTypeName
        ])

      :"SEQUENCE OF" ->
        {_, type} = r_type(def__, :def)
        traverse_SO_type_structure(erules, type, [t | ts], funcName, topTypeName)

      :"SET OF" ->
        {_, type} = r_type(def__, :def)
        traverse_SO_type_structure(erules, type, [t | ts], funcName, topTypeName)

      r_Externaltypereference(module: m, type: tName) ->
        typeDef = :asn1_db.dbget(m, tName)
        traverse_type_structure(erules, typeDef, [t | ts], funcName, [r_typedef(typeDef, :name)])

      _ ->
        traverse_type_structure(erules, def__, ts, funcName, [t | topTypeName])
    end
  end

  defp traverse_SO_type_structure(erules, type, [n | rest], funcName, topTypeName)
       when is_integer(n) do
    traverse_type_structure(erules, type, rest, funcName, topTypeName)
  end

  defp traverse_SO_type_structure(erules, type, typeList, funcName, topTypeName) do
    traverse_type_structure(erules, type, typeList, funcName, topTypeName)
  end

  defp get_component(name, {c1, c2})
       when is_list(c1) and
              is_list(c2) do
    get_component(name, c1 ++ c2)
  end

  defp get_component(name, [c = r_ComponentType(name: name) | _Cs]) do
    c
  end

  defp get_component(name, [_C | cs]) do
    get_component(name, cs)
  end

  defp gen_dec_part_inner_constr(rtmod, erules, typeDef, typeName) do
    def__ = r_typedef(typeDef, :typespec)
    innerType = :asn1ct_gen.get_inner(r_type(def__, :def))

    case innerType do
      :SET ->
        r_SET(components: components) = r_type(def__, :def)
        gen_dec_part_inner_types(rtmod, erules, components, typeName)

      :SEQUENCE ->
        r_SEQUENCE(components: components) = r_type(def__, :def)
        gen_dec_part_inner_types(rtmod, erules, components, typeName)

      :CHOICE ->
        {_, components} = r_type(def__, :def)
        gen_dec_part_inner_types(rtmod, erules, components, typeName)

      :"SEQUENCE OF" ->
        {_, type} = r_type(def__, :def)

        nameSuffix =
          constructed_suffix(
            innerType,
            r_type(type, :def)
          )

        :asn1ct_name.clear()
        rtmod.gen_decode(erules, [nameSuffix | typeName], type)

      :"SET OF" ->
        {_, type} = r_type(def__, :def)

        nameSuffix =
          constructed_suffix(
            innerType,
            r_type(type, :def)
          )

        :asn1ct_name.clear()
        rtmod.gen_decode(erules, [nameSuffix | typeName], type)

      _ ->
        :ok
    end
  end

  defp gen_dec_part_inner_types(rtmod, erules, [componentType | rest], typeName) do
    :asn1ct_name.clear()
    rtmod.gen_decode(erules, typeName, componentType)
    gen_dec_part_inner_types(rtmod, erules, rest, typeName)
  end

  defp gen_dec_part_inner_types(rtmod, erules, {comps1, comps2}, typeName)
       when is_list(comps1) and is_list(comps2) do
    gen_dec_part_inner_types(rtmod, erules, comps1 ++ comps2, typeName)
  end

  defp gen_dec_part_inner_types(_, _, [], _) do
    :ok
  end

  defp pgen_partial_incomplete_decode(erule) do
    case :asn1ct.get_gen_state_field(:active) do
      true ->
        pgen_partial_incomplete_decode1(erule)
        :asn1ct.reset_gen_state()

      _ ->
        :ok
    end
  end

  defp pgen_partial_incomplete_decode1(r_gen(erule: :ber)) do
    case :asn1ct.read_config_data(:partial_incomplete_decode) do
      :undefined ->
        :ok

      data ->
        :lists.foreach(&emit_partial_incomplete_decode/1, data)
    end

    generatedFs = :asn1ct.get_gen_state_field(:gen_refed_funcs)
    gen_part_decode_funcs(generatedFs, 0)
  end

  defp pgen_partial_incomplete_decode1(r_gen()) do
    :ok
  end

  defp emit_partial_incomplete_decode({funcName, topType, pattern}) do
    typePattern = :asn1ct.get_gen_state_field(:inc_type_pattern)

    tPattern =
      case :lists.keysearch(funcName, 1, typePattern) do
        {:value, {_, tP}} ->
          tP

        _ ->
          exit({:error, {:asn1_internal_error, :exclusive_decode}})
      end

    topTypeName =
      case :asn1ct.maybe_saved_sindex(
             topType,
             tPattern
           ) do
        i when is_integer(i) and i > 0 ->
          :lists.concat([topType, ~c"_", i])

        _ ->
          :erlang.atom_to_list(topType)
      end

    emit([
      {:asis, funcName},
      ~c"(Bytes) ->",
      :nl,
      ~c"  decode_partial_incomplete('",
      topTypeName,
      ~c"',Bytes,",
      {:asis, pattern},
      ~c").",
      :nl
    ])
  end

  defp emit_partial_incomplete_decode(d) do
    throw({:error, {:asn1, {~c"bad data in asn1config file", d}}})
  end

  defp gen_part_decode_funcs([data = {name, _, _, type} | generatedFs], n) do
    innerType =
      case r_type(type, :def) do
        r_ObjectClassFieldType(type: oCFTType) ->
          oCFTType

        _ ->
          get_inner(r_type(type, :def))
      end

    whatKind = type(innerType)
    typeName = list2name(name)

    cond do
      n > 0 ->
        emit([~c";", :nl])

      true ->
        :ok
    end

    emit([~c"decode_inc_disp('", typeName, ~c"',Data) ->", :nl])
    gen_part_decode_funcs(whatKind, typeName, data)
    gen_part_decode_funcs(generatedFs, n + 1)
  end

  defp gen_part_decode_funcs([_H | t], n) do
    gen_part_decode_funcs(t, n)
  end

  defp gen_part_decode_funcs([], n) do
    cond do
      n > 0 ->
        emit([~c".", :nl])

      true ->
        :ok
    end
  end

  defp gen_part_decode_funcs(r_Externaltypereference(module: m, type: t), _TypeName, data) do
    r_typedef(typespec: tS) = :asn1_db.dbget(m, t)

    innerType =
      case r_type(tS, :def) do
        r_ObjectClassFieldType(type: oCFTType) ->
          oCFTType

        _ ->
          get_inner(r_type(tS, :def))
      end

    whatKind = type(innerType)
    gen_part_decode_funcs(whatKind, [t], data)
  end

  defp gen_part_decode_funcs({:constructed, :bif}, typeName, {_Name, :parts, tag, _Type}) do
    emit([
      ~c"  case Data of",
      :nl,
      ~c"    L when is_list(L) ->",
      :nl,
      ~c"      'dec_",
      typeName,
      ~c"'(lists:map(fun(X) -> element(1, ",
      {:call, :ber, :ber_decode_erlang, [~c"X"]},
      ~c") end, L),",
      {:asis, tag},
      ~c");",
      :nl,
      ~c"    _ ->",
      :nl,
      ~c"      [Res] = 'dec_",
      typeName,
      ~c"'([Data],",
      {:asis, tag},
      ~c"),",
      :nl,
      ~c"      Res",
      :nl,
      ~c"  end"
    ])
  end

  defp gen_part_decode_funcs(whatKind, _TypeName, {_Name, :parts, _Tag, _Type}) do
    throw(
      {:error,
       {:asn1,
        {~c"only SEQUENCE OF/SET OF may have the partial incomplete directive 'parts'.", whatKind}}}
    )
  end

  defp gen_part_decode_funcs({:constructed, :bif}, typeName, {_Name, :undecoded, tag, _Type}) do
    emit([~c"  'dec_", typeName, ~c"'(Data,", {:asis, tag}, ~c")"])
  end

  defp gen_part_decode_funcs({:primitive, :bif}, _TypeName, {_Name, :undecoded, tag, type}) do
    :asn1ct_gen_ber_bin_v2.gen_dec_prim(type, ~c"Data", tag)
  end

  defp gen_part_decode_funcs(whatKind, _TypeName, {_, directive, _, _}) do
    throw(
      {:error,
       {:asn1, {~c"Not implemented yet", whatKind, ~c" partial incomplete directive:", directive}}}
    )
  end

  defp gen_types(erules, tname, {rootL1, extList, rootL2}, encDec)
       when is_list(rootL1) and is_list(rootL2) do
    gen_types(erules, tname, rootL1, encDec)
    rtmod = ct_gen_module(erules)
    gen_types(erules, tname, rtmod.extaddgroup2sequence(extList), encDec)
    gen_types(erules, tname, rootL2, encDec)
  end

  defp gen_types(erules, tname, {rootList, extList}, encDec)
       when is_list(rootList) do
    gen_types(erules, tname, rootList, encDec)
    rtmod = ct_gen_module(erules)
    gen_types(erules, tname, rtmod.extaddgroup2sequence(extList), encDec)
  end

  defp gen_types(erules, tname, [{:EXTENSIONMARK, _, _} | t], encDec) do
    gen_types(erules, tname, t, encDec)
  end

  defp gen_types(erules, tname, [componentType | t], encDec) do
    :asn1ct_name.clear()
    rtmod = ct_gen_module(erules)
    apply(rtmod, encDec, [erules, tname, componentType])
    gen_types(erules, tname, t, encDec)
  end

  defp gen_types(_, _, [], _) do
    :ok
  end

  defp gen_types(erules, tname, r_type() = type, encDec) do
    :asn1ct_name.clear()
    rtmod = ct_gen_module(erules)
    apply(rtmod, encDec, [erules, tname, type])
  end

  def mk_var(x) when is_atom(x) do
    :erlang.list_to_atom(mk_var(:erlang.atom_to_list(x)))
  end

  def mk_var([h | t]) do
    [h - 32 | t]
  end

  def un_hyphen_var(x) when is_atom(x) do
    :erlang.list_to_atom(un_hyphen_var(:erlang.atom_to_list(x)))
  end

  def un_hyphen_var([45 | t]) do
    [95 | un_hyphen_var(t)]
  end

  def un_hyphen_var([h | t]) do
    [h | un_hyphen_var(t)]
  end

  def un_hyphen_var([]) do
    []
  end

  def gen_encode_constructed(erules, typename, innerType, d)
      when elem(d, 0) === :type do
    rtmod = ct_constructed_module(erules)

    case innerType do
      :SET ->
        rtmod.gen_encode_set(erules, typename, d)
        r_SET(components: components) = r_type(d, :def)
        gen_types(erules, typename, components, :gen_encode)

      :SEQUENCE ->
        rtmod.gen_encode_sequence(erules, typename, d)
        r_SEQUENCE(components: components) = r_type(d, :def)
        gen_types(erules, typename, components, :gen_encode)

      :CHOICE ->
        rtmod.gen_encode_choice(erules, typename, d)
        {_, components} = r_type(d, :def)
        gen_types(erules, typename, components, :gen_encode)

      :"SEQUENCE OF" ->
        rtmod.gen_encode_sof(erules, typename, innerType, d)
        {_, type} = r_type(d, :def)

        nameSuffix =
          :asn1ct_gen.constructed_suffix(
            innerType,
            r_type(type, :def)
          )

        gen_types(erules, [nameSuffix | typename], type, :gen_encode)

      :"SET OF" ->
        rtmod.gen_encode_sof(erules, typename, innerType, d)
        {_, type} = r_type(d, :def)

        nameSuffix =
          :asn1ct_gen.constructed_suffix(
            innerType,
            r_type(type, :def)
          )

        gen_types(erules, [nameSuffix | typename], type, :gen_encode)
    end
  end

  def gen_encode_constructed(erules, typename, innerType, d)
      when elem(d, 0) === :typedef do
    gen_encode_constructed(erules, typename, innerType, r_typedef(d, :typespec))
  end

  def gen_decode_constructed(erules, typename, innerType, d)
      when elem(d, 0) === :type do
    rtmod = ct_constructed_module(erules)
    :asn1ct.step_in_constructed()

    case innerType do
      :SET ->
        rtmod.gen_decode_set(erules, typename, d)
        r_SET(components: components) = r_type(d, :def)
        gen_types(erules, typename, components, :gen_decode)

      :SEQUENCE ->
        rtmod.gen_decode_sequence(erules, typename, d)
        r_SEQUENCE(components: components) = r_type(d, :def)
        gen_types(erules, typename, components, :gen_decode)

      :CHOICE ->
        rtmod.gen_decode_choice(erules, typename, d)
        {_, components} = r_type(d, :def)
        gen_types(erules, typename, components, :gen_decode)

      :"SEQUENCE OF" ->
        rtmod.gen_decode_sof(erules, typename, innerType, d)
        {_, r_type(def: def__) = type} = r_type(d, :def)

        nameSuffix =
          :asn1ct_gen.constructed_suffix(
            innerType,
            def__
          )

        gen_types(erules, [nameSuffix | typename], type, :gen_decode)

      :"SET OF" ->
        rtmod.gen_decode_sof(erules, typename, innerType, d)
        {_, r_type(def: def__) = type} = r_type(d, :def)

        nameSuffix =
          :asn1ct_gen.constructed_suffix(
            innerType,
            def__
          )

        gen_types(erules, [nameSuffix | typename], type, :gen_decode)
    end
  end

  def gen_decode_constructed(erules, typename, innerType, d)
      when elem(d, 0) === :typedef do
    gen_decode_constructed(erules, typename, innerType, r_typedef(d, :typespec))
  end

  defp pgen_exports(r_gen(options: options) = gen, code) do
    r_abst(types: types, values: values, objects: objects, objsets: objectSets) = code

    emit([
      ~c"-export([encoding_rule/0,maps/0,bit_string_format/0,",
      :nl,
      ~c"         legacy_erlang_types/0]).",
      :nl
    ])

    emit([~c"-export([", {:asis, :"dialyzer-suppressions"}, ~c"/1]).", :nl])

    case gen do
      r_gen(erule: erule, jer: jer) when erule === :jer or jer ->
        emit([~c"-export([typeinfo/1]).", :nl])

      r_gen() ->
        :ok
    end

    case gen do
      r_gen(erule: :ber) ->
        gen_exports(types, ~c"enc_", 2)
        gen_exports(types, ~c"dec_", 2)
        gen_exports(objects, ~c"enc_", 3)
        gen_exports(objects, ~c"dec_", 3)
        gen_exports(objectSets, ~c"getenc_", 1)
        gen_exports(objectSets, ~c"getdec_", 1)

      r_gen(erule: :per) ->
        gen_exports(types, ~c"enc_", 1)
        gen_exports(types, ~c"dec_", 1)

      r_gen(erule: :jer) ->
        :ok
    end

    a2nNames =
      for {:n2n, x} <- options do
        x
      end

    gen_exports(a2nNames, ~c"name2num_", 1)
    gen_exports(a2nNames, ~c"num2name_", 1)
    gen_exports(values, ~c"", 0)
    emit([~c"-export([info/0]).", :nl, :nl])
    gen_partial_inc_decode_exports()
    gen_selected_decode_exports()
  end

  defp gen_partial_inc_decode_exports() do
    case {:asn1ct.read_config_data(:partial_incomplete_decode),
          :asn1ct.get_gen_state_field(:inc_type_pattern)} do
      {:undefined, _} ->
        :ok

      {_, :undefined} ->
        :ok

      {data0, _} ->
        data =
          for {name, _, _} <- data0 do
            name
          end

        gen_exports(data, ~c"", 1)
        emit([~c"-export([decode_part/2]).", :nl, :nl])
    end
  end

  defp gen_selected_decode_exports() do
    case :asn1ct.get_gen_state_field(:type_pattern) do
      :undefined ->
        :ok

      data0 ->
        data =
          for {name, _} <- data0 do
            name
          end

        gen_exports(data, ~c"", 1)
    end
  end

  defp gen_exports([], _Prefix, _Arity) do
    :ok
  end

  defp gen_exports([_ | _] = l0, prefix, arity) do
    fF = fn f0 ->
      f = :erlang.list_to_atom(:lists.concat([prefix, f0]))
      [{:asis, f}, ~c"/", arity]
    end

    l =
      :lists.join(
        ~c",\n",
        for f <- l0 do
          fF.(f)
        end
      )

    emit([~c"-export([", :nl, l, :nl, ~c"]).", :nl, :nl])
  end

  defp pgen_dispatcher(erules, []) do
    gen_info_functions(erules)
  end

  defp pgen_dispatcher(gen, types) do
    emit([~c"-export([encode/2,decode/2]).", :nl])

    case r_gen(gen, :jer) do
      true ->
        emit([~c"-export([jer_encode/2,jer_decode/2]).", :nl])

      false ->
        :ok
    end

    emit([:nl])
    gen_info_functions(gen)
    options = r_gen(gen, :options)

    noFinalPadding =
      :lists.member(
        :no_final_padding,
        options
      )

    noOkWrapper =
      :proplists.get_bool(
        :no_ok_wrapper,
        options
      )

    currMod = :lists.concat([~c"'", :erlang.get(:currmod), ~c"'"])

    call =
      case gen do
        r_gen(erule: :per, aligned: true) ->
          :asn1ct_func.need({:per, :complete, 1})
          ~c"complete(encode_disp(Type, Data))"

        r_gen(erule: :ber) ->
          ~c"iolist_to_binary(element(1, encode_disp(Type, Data)))"

        r_gen(erule: :jer) ->
          [~c"?JSON_ENCODE(", {:call, :jer, :encode_jer, [currMod, ~c"Type", ~c"Data"]}, ~c")"]

        r_gen(erule: :per, aligned: false) when noFinalPadding ->
          :asn1ct_func.need({:uper, :complete_NFP, 1})
          ~c"complete_NFP(encode_disp(Type, Data))"

        r_gen(erule: :per, aligned: false) ->
          :asn1ct_func.need({:uper, :complete, 1})
          ~c"complete(encode_disp(Type, Data))"
      end

    emit([~c"encode(Type, Data) ->", :nl])

    case noOkWrapper do
      true ->
        emit([~c"  ", call, ~c"."])

      false ->
        emit([
          ~c"try ",
          call,
          ~c" of",
          :nl,
          ~c"  Bytes ->",
          :nl,
          ~c"    {ok,Bytes}",
          :nl,
          try_catch()
        ])
    end

    emit([:nl, :nl])

    case r_gen(gen, :jer) do
      true ->
        emit([~c"jer_encode(Type, Data) ->", :nl])

        jerCall = [
          ~c"?JSON_ENCODE(",
          {:call, :jer, :encode_jer, [currMod, ~c"Type", ~c"Data"]},
          ~c")"
        ]

        case noOkWrapper do
          true ->
            emit([~c"  ", jerCall, ~c"."])

          false ->
            emit([
              ~c"try ",
              jerCall,
              ~c" of",
              :nl,
              ~c"  Bytes ->",
              :nl,
              ~c"    {ok,Bytes}",
              :nl,
              try_catch()
            ])
        end

        emit([:nl, :nl])

      false ->
        :ok
    end

    returnRest =
      :proplists.get_bool(
        :undec_rest,
        r_gen(gen, :options)
      )

    data =
      case r_gen(gen, :erule) === :ber and returnRest do
        true ->
          ~c"Data0"

        false ->
          ~c"Data"
      end

    emit([~c"decode(Type, ", data, ~c") ->", :nl])

    case noOkWrapper do
      false ->
        emit([~c"try", :nl])

      true ->
        :ok
    end

    decWrap =
      case {gen, returnRest} do
        {r_gen(erule: :ber), false} ->
          :asn1ct_func.need({:ber, :ber_decode_nif, 1})
          ~c"element(1, ber_decode_nif(Data))"

        {r_gen(erule: :ber), true} ->
          :asn1ct_func.need({:ber, :ber_decode_nif, 1})
          emit([~c"   {Data,Rest} = ber_decode_nif(Data0),", :nl])
          ~c"Data"

        {r_gen(erule: :jer), false} ->
          ~c"?JSON_DECODE(Data)"

        {r_gen(erule: :jer), true} ->
          exit(~c"JER + return rest not supported")

        {_, _} ->
          ~c"Data"
      end

    decodeDisp = [~c"decode_disp(Type, ", decWrap, ~c")"]

    case {gen, returnRest} do
      {r_gen(erule: :ber), true} ->
        emit([~c"   Result = ", decodeDisp, ~c",", :nl])
        result_line(noOkWrapper, [~c"Result", ~c"Rest"])

      {r_gen(erule: :ber), false} ->
        emit([~c"   Result = ", decodeDisp, ~c",", :nl])
        result_line(noOkWrapper, [~c"Result"])

      {r_gen(erule: :jer), false} ->
        emit([
          ~c"   Result = ",
          {:call, :jer, :decode_jer, [currMod, ~c"Type", decWrap]},
          ~c",",
          :nl
        ])

        result_line(noOkWrapper, [~c"Result"])

      {r_gen(erule: :per), true} ->
        emit([~c"   {Result,Rest} = ", decodeDisp, ~c",", :nl])
        result_line(noOkWrapper, [~c"Result", ~c"Rest"])

      {r_gen(erule: :per), false} ->
        emit([~c"   {Result,_Rest} = ", decodeDisp, ~c",", :nl])
        result_line(noOkWrapper, [~c"Result"])
    end

    case noOkWrapper do
      false ->
        emit([:nl, try_catch(), :nl, :nl])

      true ->
        emit([~c".", :nl, :nl])
    end

    case r_gen(gen, :jer) do
      true ->
        emit([~c"jer_decode(Type, ", data, ~c") ->", :nl])

        case noOkWrapper do
          false ->
            emit([~c"try", :nl])

          true ->
            :ok
        end

        jerDecWrap = ~c"?JSON_DECODE(Data)"

        emit([
          ~c"   Result = ",
          {:call, :jer, :decode_jer, [currMod, ~c"Type", jerDecWrap]},
          ~c",",
          :nl
        ])

        result_line(false, [~c"Result"])

        case noOkWrapper do
          false ->
            emit([:nl, try_catch(), :nl, :nl])

          true ->
            emit([~c".", :nl, :nl])
        end

      false ->
        :ok
    end

    gen_decode_partial_incomplete(gen)
    gen_partial_inc_dispatcher(gen)

    case gen do
      r_gen(erule: :jer) ->
        :ok

      _ ->
        gen_dispatcher(types, ~c"encode_disp", ~c"enc_")
        gen_dispatcher(types, ~c"decode_disp", ~c"dec_")
    end
  end

  defp result_line(noOkWrapper, items) do
    s = [
      ~c"   "
      | case noOkWrapper do
          false ->
            result_line_1([~c"ok" | items])

          true ->
            result_line_1(items)
        end
    ]

    emit(:lists.flatten(s))
  end

  defp result_line_1([singleItem]) do
    singleItem
  end

  defp result_line_1(items) do
    [~c"{", :lists.join(~c",", items), ~c"}"]
  end

  defp try_catch() do
    [
      ~c"  catch",
      :nl,
      ~c"    Class:Exception:Stk when Class =:= error; Class =:= exit ->",
      :nl,
      ~c"      case Exception of",
      :nl,
      ~c"        {error,{asn1,Reason}} ->",
      :nl,
      ~c"          {error,{asn1,{Reason,Stk}}};",
      :nl,
      ~c"        Reason ->",
      :nl,
      ~c"         {error,{asn1,{Reason,Stk}}}",
      :nl,
      ~c"      end",
      :nl,
      ~c"end."
    ]
  end

  defp gen_info_functions(gen) do
    erule =
      case gen do
        r_gen(erule: :ber) ->
          :ber

        r_gen(erule: :per, aligned: false) ->
          :uper

        r_gen(erule: :per, aligned: true) ->
          :per

        r_gen(erule: :jer) ->
          :jer
      end

    maps =
      case gen do
        r_gen(pack: :record) ->
          false

        r_gen(pack: :map) ->
          true
      end

    emit([
      ~c"encoding_rule() -> ",
      {:asis, erule},
      ~c".",
      :nl,
      :nl,
      ~c"maps() -> ",
      {:asis, maps},
      ~c".",
      :nl,
      :nl,
      ~c"bit_string_format() -> ",
      {:asis, :asn1ct.get_bit_string_format()},
      ~c".",
      :nl,
      :nl,
      ~c"legacy_erlang_types() -> ",
      {:asis, :asn1ct.use_legacy_types()},
      ~c".",
      :nl,
      :nl
    ])
  end

  defp gen_decode_partial_incomplete(r_gen(erule: :ber)) do
    case {:asn1ct.read_config_data(:partial_incomplete_decode),
          :asn1ct.get_gen_state_field(:inc_type_pattern)} do
      {:undefined, _} ->
        :ok

      {_, :undefined} ->
        :ok

      _ ->
        emitCaseClauses = fn ->
          emit([
            ~c"   {'EXIT',{error,Reason}} ->",
            :nl,
            ~c"      {error,Reason};",
            :nl,
            ~c"    {'EXIT',Reason} ->",
            :nl,
            ~c"      {error,{asn1,Reason}};",
            :nl,
            ~c"    Result ->",
            :nl,
            ~c"      {ok,Result}",
            :nl,
            ~c"  end"
          ])
        end

        emit([~c"decode_partial_incomplete(Type,Data0,", ~c"Pattern) ->", :nl])

        emit([
          ~c"  {Data,_RestBin} =",
          :nl,
          ~c"    ",
          {:call, :ber, :decode_primitive_incomplete, [~c"Pattern", ~c"Data0"]},
          :com,
          :nl,
          ~c"  case catch decode_partial_inc_disp(Type,",
          ~c"Data) of",
          :nl
        ])

        emitCaseClauses.()
        emit([~c".", :nl, :nl])
        emit([~c"decode_part(Type, Data0) when is_binary(Data0) ->", :nl])

        emit([
          ~c"  case catch decode_inc_disp(Type,element(1, ",
          {:call, :ber, :ber_decode_nif, [~c"Data0"]},
          ~c")) of",
          :nl
        ])

        emitCaseClauses.()
        emit([~c";", :nl])
        emit([~c"decode_part(Type, Data0) ->", :nl])
        emit([~c"  case catch decode_inc_disp(Type, Data0) of", :nl])
        emitCaseClauses.()
        emit([~c".", :nl, :nl])
    end
  end

  defp gen_decode_partial_incomplete(r_gen()) do
    :ok
  end

  defp gen_partial_inc_dispatcher(r_gen(erule: :ber)) do
    case {:asn1ct.read_config_data(:partial_incomplete_decode),
          :asn1ct.get_gen_state_field(:inc_type_pattern)} do
      {:undefined, _} ->
        :ok

      {_, :undefined} ->
        :ok

      {data1, data2} ->
        gen_partial_inc_dispatcher(data1, data2, ~c"")
    end
  end

  defp gen_partial_inc_dispatcher(r_gen()) do
    :ok
  end

  defp gen_partial_inc_dispatcher([{funcName, topType, _Pattern} | rest], typePattern, sep) do
    tPattern =
      case :lists.keysearch(funcName, 1, typePattern) do
        {:value, {_, tP}} ->
          tP

        _ ->
          exit({:error, {:asn1_internal_error, :exclusive_decode}})
      end

    funcName2 = :asn1ct.maybe_rename_function(:inc_disp, topType, tPattern)

    topTypeName =
      case :asn1ct.maybe_saved_sindex(
             topType,
             tPattern
           ) do
        i when is_integer(i) and i > 0 ->
          :lists.concat([topType, ~c"_", i])

        _ ->
          :erlang.atom_to_list(topType)
      end

    emit([
      sep,
      ~c"decode_partial_inc_disp('",
      topTypeName,
      ~c"',Data) ->",
      :nl,
      ~c"  ",
      {:asis, :erlang.list_to_atom(:lists.concat([~c"dec-inc-", funcName2]))},
      ~c"(Data)"
    ])

    gen_partial_inc_dispatcher(rest, typePattern, ~c";\n")
  end

  defp gen_partial_inc_dispatcher([], _, _) do
    emit([~c".", :nl])
  end

  defp gen_dispatcher(l, dispFunc, prefix) do
    gen_dispatcher_1(l, dispFunc, prefix)

    emit([
      dispFunc,
      ~c"(",
      ~c"Type",
      ~c", _Data) -> exit({error,{asn1,{undefined_type,Type}}}).",
      :nl,
      :nl
    ])
  end

  defp gen_dispatcher_1([f | t], funcName, prefix) do
    func = :erlang.list_to_atom(:lists.concat([prefix, f]))
    emit([funcName, ~c"(", {:asis, f}, ~c", Data) -> ", {:asis, func}, ~c"(Data)", ~c";", :nl])
    gen_dispatcher_1(t, funcName, prefix)
  end

  defp gen_dispatcher_1([], _, _) do
    :ok
  end

  defp pgen_info() do
    emit([
      ~c"info() ->",
      :nl,
      ~c"   case ?MODULE:module_info(attributes) of",
      :nl,
      ~c"     Attributes when is_list(Attributes) ->",
      :nl,
      ~c"       case lists:keyfind(asn1_info, 1, Attributes) of",
      :nl,
      ~c"         {_,Info} when is_list(Info) ->",
      :nl,
      ~c"           Info;",
      :nl,
      ~c"         _ ->",
      :nl,
      ~c"           []",
      :nl,
      ~c"       end;",
      :nl,
      ~c"     _ ->",
      :nl,
      ~c"       []",
      :nl,
      ~c"   end.",
      :nl
    ])
  end

  defp open_hrl(outFile, module) do
    file = :lists.concat([outFile, ~c".hrl"])
    _ = open_output_file(file)
    gen_hrlhead(module)
    protector = hrl_protector(outFile)
    emit([~c"-ifndef(", protector, ~c").\n", ~c"-define(", protector, ~c", true).\n\n"])
  end

  defp hrl_protector(outFile) do
    baseName = :filename.basename(outFile)
    p = ~c"_" ++ :string.uppercase(baseName) ++ ~c"_HRL_"

    for c <- p do
      cond do
        ?A <= c and c <= ?Z ->
          c

        ?a <= c and c <= ?a ->
          c

        ?0 <= c and c <= ?9 ->
          c

        true ->
          ?_
      end
    end
  end

  def emit(term) do
    :ok =
      :file.write(
        :erlang.get(:gen_file_out),
        do_emit(term)
      )
  end

  defp do_emit({:prev, variable}) when is_atom(variable) do
    do_emit({:var, :asn1ct_name.prev(variable)})
  end

  defp do_emit({:next, variable}) when is_atom(variable) do
    do_emit({:var, :asn1ct_name.next(variable)})
  end

  defp do_emit({:curr, variable}) when is_atom(variable) do
    do_emit({:var, :asn1ct_name.curr(variable)})
  end

  defp do_emit({:var, variable}) when is_atom(variable) do
    [head | v] = :erlang.atom_to_list(variable)
    [head - 32 | v]
  end

  defp do_emit({:asis, what}) do
    :io_lib.format(~c"~w", [what])
  end

  defp do_emit({:asisp, what}) do
    :io_lib.format(~c"~p", [what])
  end

  defp do_emit({:call, m, f, a}) do
    mFA = {m, f, length(a)}
    :asn1ct_func.need(mFA)
    [:erlang.atom_to_list(f), ~c"(", call_args(a, ~c"") | ~c")"]
  end

  defp do_emit(:nl) do
    ~c"\n"
  end

  defp do_emit(:com) do
    ~c","
  end

  defp do_emit([c | _] = str) when is_integer(c) do
    str
  end

  defp do_emit([_ | _] = l) do
    for e <- l do
      do_emit(e)
    end
  end

  defp do_emit([]) do
    []
  end

  defp do_emit(what) when is_integer(what) do
    :erlang.integer_to_list(what)
  end

  defp do_emit(what) when is_atom(what) do
    :erlang.atom_to_list(what)
  end

  defp call_args([a | as], sep) do
    [sep, do_emit(a) | call_args(as, ~c", ")]
  end

  defp call_args([], _) do
    []
  end

  def open_output_file(f) do
    case :file.open(f, [:write, :raw, :delayed_write]) do
      {:ok, fd} ->
        :erlang.put(:gen_file_out, fd)
        fd

      {:error, reason} ->
        :io.format(~c"** Can't open file ~p ~n", [f])
        exit({:error, reason})
    end
  end

  def close_output_file() do
    :ok = :file.close(:erlang.erase(:gen_file_out))
  end

  defp pgen_hrl(r_gen(pack: :record) = gen, code) do
    r_abst(name: module, types: types, values: values, ptypes: ptypes) = code

    ret =
      case pgen_hrltypes(gen, module, ptypes ++ types, 0) do
        0 ->
          case values do
            [] ->
              0

            _ ->
              open_hrl(:erlang.get(:outfile), module)
              pgen_macros(gen, module, values)
              1
          end

        x ->
          pgen_macros(gen, module, values)
          x
      end

    case ret do
      0 ->
        0

      y ->
        protector = hrl_protector(:erlang.get(:outfile))
        emit([~c"-endif. %% ", protector, ~c"\n"])
        close_output_file()

        :asn1ct.verbose(
          ~c"--~p--~n",
          [{:generated, :lists.concat([:erlang.get(:outfile), ~c".hrl"])}],
          gen
        )

        y
    end
  end

  defp pgen_hrl(r_gen(pack: :map), _) do
    0
  end

  defp pgen_macros(_, _, []) do
    true
  end

  defp pgen_macros(gen, module, [h | t]) do
    valuedef = :asn1_db.dbget(module, h)
    gen_macro(gen, valuedef)
    pgen_macros(gen, module, t)
  end

  defp pgen_hrltypes(_, _, [], numRecords) do
    numRecords
  end

  defp pgen_hrltypes(gen, module, [h | t], numRecords) do
    typedef = :asn1_db.dbget(module, h)
    addNumRecords = gen_record(gen, typedef, numRecords)
    pgen_hrltypes(gen, module, t, numRecords + addNumRecords)
  end

  defp gen_macro(gen, r_valuedef(name: name, value: value)) do
    prefix = get_macro_name_prefix(gen)
    emit([~c"-define('", prefix, name, ~c"', ", {:asis, value}, ~c").", :nl])
  end

  defp gen_record(gen, r_typedef() = tdef, numRecords) do
    name = [r_typedef(tdef, :name)]
    type = r_typedef(tdef, :typespec)
    gen_record(gen, :type, name, type, numRecords)
  end

  defp gen_record(gen, r_ptypedef() = tdef, numRecords) do
    name = [r_ptypedef(tdef, :name)]
    type = r_ptypedef(tdef, :typespec)
    gen_record(gen, :ptype, name, type, numRecords)
  end

  defp gen_record(gen, torPtype, name, [r_ComponentType(name: cname, typespec: type) | t], num) do
    num2 = gen_record(gen, torPtype, [cname | name], type, num)
    gen_record(gen, torPtype, name, t, num2)
  end

  defp gen_record(gen, torPtype, name, {clist1, clist2}, num)
       when is_list(clist1) and is_list(clist2) do
    gen_record(gen, torPtype, name, clist1 ++ clist2, num)
  end

  defp gen_record(gen, torPtype, name, {clist1, eClist, clist2}, num)
       when is_list(clist1) and is_list(eClist) and
              is_list(clist2) do
    gen_record(gen, torPtype, name, clist1 ++ eClist ++ clist2, num)
  end

  defp gen_record(gen, torPtype, name, [_ | t], num) do
    gen_record(gen, torPtype, name, t, num)
  end

  defp gen_record(_Gen, _TorPtype, _Name, [], num) do
    num
  end

  defp gen_record(gen, torPtype, name, r_type() = type, num) do
    def__ = r_type(type, :def)

    rec =
      case def__ do
        seq when elem(seq, 0) === :SEQUENCE ->
          case r_SEQUENCE(seq, :pname) do
            false ->
              {:record, r_SEQUENCE(seq, :components)}

            _ ->
              {:record, r_SEQUENCE(seq, :components)}
          end

        set when elem(set, 0) === :SET ->
          case r_SET(set, :pname) do
            false ->
              {:record, to_textual_order(r_SET(set, :components))}

            _Pname when torPtype == :type ->
              false

            _ ->
              {:record, to_textual_order(r_SET(set, :components))}
          end

        {:CHOICE, _CompList} ->
          {:inner, def__}

        {:"SEQUENCE OF", _CompList} ->
          {[:SEQOF | name], def__}

        {:"SET OF", _CompList} ->
          {[:SETOF | name], def__}

        _ ->
          false
      end

    case rec do
      false ->
        num

      {:record, compList} ->
        case num do
          0 ->
            open_hrl(:erlang.get(:outfile), :erlang.get(:currmod))

          _ ->
            true
        end

        do_gen_record(gen, name, compList)

        newCompList =
          case compList do
            {compList1, []} ->
              compList1

            {tr, extensionList2} ->
              tr ++ extensionList2

            {rootl1, extl, rootl2} ->
              rootl1 ++ extl ++ rootl2

            _ ->
              compList
          end

        gen_record(gen, torPtype, name, newCompList, num + 1)

      {:inner, {:CHOICE, compList}} ->
        gen_record(gen, torPtype, name, compList, num)

      {newName, {_, compList}} ->
        gen_record(gen, torPtype, newName, compList, num)
    end
  end

  defp gen_record(_, _, _, _, numRecords) do
    numRecords
  end

  defp do_gen_record(gen, name, cL0) when is_list(cL0) do
    do_gen_record_0(gen, name, complist_as_tuple(cL0))
  end

  defp do_gen_record(gen, name, cL0) do
    do_gen_record_0(gen, name, cL0)
  end

  defp do_gen_record_0(gen, name, cL0) do
    cL =
      case cL0 do
        {root, []} ->
          root ++ [{:comment, ~c"with extension mark"}]

        {root, ext} ->
          root ++ [{:comment, ~c"with extensions"}] ++ only_components(ext)

        {root1, ext, root2} ->
          root1 ++
            [{:comment, ~c"with extensions"}] ++
            only_components(ext) ++ [{:comment, ~c"end of extensions"}] ++ root2

        _ when is_list(cL0) ->
          only_components(cL0)
      end

    prefix = get_record_name_prefix(gen)

    emit(
      [~c"-record('", prefix, list2name(name), ~c"', {"] ++
        do_gen_record_1(cL) ++ [:nl, ~c"}).", :nl, :nl]
    )
  end

  defp only_components(cL) do
    for r_ComponentType() = c <- cL do
      c
    end
  end

  defp do_gen_record_1([r_ComponentType(name: name, prop: prop) | t]) do
    val =
      case prop do
        :OPTIONAL ->
          ~c" = asn1_NOVALUE"

        {:DEFAULT, _} ->
          ~c" = asn1_DEFAULT"

        _ ->
          []
      end

    com =
      case needs_trailing_comma(t) do
        true ->
          [:com]

        false ->
          []
      end

    [:nl, ~c"  ", {:asis, name}, val, com | do_gen_record_1(t)]
  end

  defp do_gen_record_1([{:comment, text} | t]) do
    [:nl, ~c"  %% ", text | do_gen_record_1(t)]
  end

  defp do_gen_record_1([]) do
    []
  end

  defp needs_trailing_comma([r_ComponentType() | _]) do
    true
  end

  defp needs_trailing_comma([_ | t]) do
    needs_trailing_comma(t)
  end

  defp needs_trailing_comma([]) do
    false
  end

  defp gen_head(r_gen(options: options) = gen, mod, hrl) do
    name =
      case gen do
        r_gen(erule: :per, aligned: false) ->
          ~c"PER (unaligned)"

        r_gen(erule: :per, aligned: true) ->
          ~c"PER (aligned)"

        r_gen(erule: :ber) ->
          ~c"BER"

        r_gen(erule: :jer) ->
          ~c"JER (JSON)"
      end

    emit([
      ~c"%% Generated by the Erlang ASN.1 ",
      name,
      ~c" compiler. Version: ",
      :asn1ct.vsn(),
      :nl,
      ~c"%% Purpose: Encoding and decoding of the types in ",
      mod,
      ~c".",
      :nl,
      :nl,
      ~c"-module('",
      mod,
      ~c"').",
      :nl,
      ~c"-compile(nowarn_unused_vars).",
      :nl,
      ~c"-dialyzer(no_improper_lists).",
      :nl,
      ~c"-dialyzer(no_match).",
      :nl
    ])

    case hrl do
      0 ->
        :ok

      _ ->
        emit([~c"-include(\"", mod, ~c".hrl\").", :nl])
    end

    deterministic =
      :proplists.get_bool(
        :deterministic,
        options
      )

    options1 =
      case deterministic do
        true ->
          :lists.filter(
            fn
              {:cwd, _} ->
                false

              {:outdir, _} ->
                false

              {:i, _} ->
                false

              _ ->
                true
            end,
            options
          )

        false ->
          options
      end

    emit([
      ~c"-asn1_info([{vsn,'",
      :asn1ct.vsn(),
      ~c"'},",
      :nl,
      ~c"            {module,'",
      mod,
      ~c"'},",
      :nl,
      ~c"            {options,",
      :io_lib.format(
        ~c"~p",
        [options1]
      ),
      ~c"}]).",
      :nl,
      :nl
    ])

    jerDefines =
      case gen do
        r_gen(erule: :jer) ->
          true

        r_gen(jer: true) ->
          true

        _ ->
          false
      end

    jerDefines and
      emit([
        ~c"-ifdef(jsone).",
        :nl,
        ~c"-define(JSON_DECODE(Data),jsone:decode(Data)).",
        :nl,
        ~c"-define(JSON_ENCODE(Term),jsone:encode(Term)).",
        :nl,
        ~c"-else.",
        :nl,
        ~c"-define(JSON_DECODE(Data),jsx:decode(Data,[return_maps])).",
        :nl,
        ~c"-define(JSON_ENCODE(Term),jsx:encode(Term)).",
        :nl,
        ~c"-endif.",
        :nl
      ])
  end

  defp gen_hrlhead(mod) do
    emit([
      ~c"%% Generated by the Erlang ASN.1 compiler. Version: ",
      :asn1ct.vsn(),
      :nl,
      ~c"%% Purpose: Erlang record definitions for each named and unnamed",
      :nl,
      ~c"%% SEQUENCE and SET, and macro definitions for each value",
      :nl,
      ~c"%% definition in module ",
      mod,
      ~c".",
      :nl,
      :nl
    ])
  end

  defp to_textual_order({root, ext}) do
    {to_textual_order(root), ext}
  end

  defp to_textual_order(cs = {_R1, _Ext, _R2}) do
    cs
  end

  defp to_textual_order(cs = [r_ComponentType(textual_order: :undefined) | _]) do
    cs
  end

  defp to_textual_order(cs) when is_list(cs) do
    :lists.keysort(r_ComponentType(:textual_order), cs)
  end

  def insert_once(table, object) do
    case :asn1ct_table.lookup(
           table,
           :erlang.element(1, object)
         ) do
      [] ->
        :asn1ct_table.insert(table, object)

      _ ->
        false
    end
  end

  def unify_if_string(primType) do
    case primType do
      :NumericString ->
        :restrictedstring

      :PrintableString ->
        :restrictedstring

      :TeletexString ->
        :restrictedstring

      :T61String ->
        :restrictedstring

      :VideotexString ->
        :restrictedstring

      :IA5String ->
        :restrictedstring

      :UTCTime ->
        :restrictedstring

      :GeneralizedTime ->
        :restrictedstring

      :GraphicString ->
        :restrictedstring

      :VisibleString ->
        :restrictedstring

      :GeneralString ->
        :restrictedstring

      :UniversalString ->
        :restrictedstring

      :BMPString ->
        :restrictedstring

      :UTF8String ->
        :restrictedstring

      other ->
        other
    end
  end

  def conform_value(r_type(def: {:"BIT STRING", []}), bs) do
    case :asn1ct.get_bit_string_format() do
      :compact when is_binary(bs) ->
        {0, bs}

      :compact when is_bitstring(bs) ->
        sz = bit_size(bs)
        unused = 8 - bit_size(bs)
        {unused, <<bs::size(sz)-bits, 0::size(unused)>>}

      :legacy ->
        for <<(<<b::size(1)>> <- bs)>> do
          b
        end

      :bitstring when is_bitstring(bs) ->
        bs
    end
  end

  def conform_value(r_type(def: :"OCTET STRING"), string) do
    case :asn1ct.use_legacy_types() do
      false ->
        string

      true ->
        :erlang.binary_to_list(string)
    end
  end

  def conform_value(_, value) do
    value
  end

  def named_bitstring_value(list, names) do
    int =
      :lists.foldl(
        fn n, a ->
          {^n, pos} = :lists.keyfind(n, 1, names)
          a ||| 1 <<< pos
        end,
        0,
        list
      )

    named_bitstring_value_1(<<>>, int)
  end

  defp named_bitstring_value_1(bs, 0) do
    bs
  end

  defp named_bitstring_value_1(bs, int) do
    b = int &&& 1

    named_bitstring_value_1(
      <<bs::bitstring, b::size(1)>>,
      int >>> 1
    )
  end

  def get_inner(a) when is_atom(a) do
    a
  end

  def get_inner(ext)
      when elem(ext, 0) === :Externaltypereference do
    ext
  end

  def get_inner({:fixedtypevaluefield, _, type}) do
    cond do
      elem(type, 0) === :type ->
        get_inner(r_type(type, :def))

      true ->
        get_inner(type)
    end
  end

  def get_inner({:typefield, typeName}) do
    typeName
  end

  def get_inner(r_ObjectClassFieldType(type: type)) do
    type
  end

  def get_inner(t) when is_tuple(t) do
    case :erlang.element(1, t) do
      tuple
      when is_tuple(tuple) and
             :erlang.element(1, tuple) == :objectclass ->
        case (try do
                :lists.last(:erlang.element(2, t))
              catch
                :error, e -> {:EXIT, {e, __STACKTRACE__}}
                :exit, e -> {:EXIT, e}
                e -> e
              end) do
          {:valuefieldreference, fieldName} ->
            get_fieldtype(:erlang.element(2, tuple), fieldName)

          {:typefieldreference, fieldName} ->
            get_fieldtype(:erlang.element(2, tuple), fieldName)
        end

      _ ->
        :erlang.element(1, t)
    end
  end

  def type(x) when elem(x, 0) === :Externaltypereference do
    x
  end

  def type(:ASN1_OPEN_TYPE) do
    :ASN1_OPEN_TYPE
  end

  def type({:fixedtypevaluefield, _Name, type})
      when elem(type, 0) === :type do
    type(get_inner(r_type(type, :def)))
  end

  def type({:typefield, _}) do
    :ASN1_OPEN_TYPE
  end

  def type(x) do
    case prim_bif(x) do
      true ->
        {:primitive, :bif}

      false ->
        case construct_bif(x) do
          true ->
            {:constructed, :bif}

          false ->
            {:undefined, :user}
        end
    end
  end

  def prim_bif(x) do
    :lists.member(
      x,
      [
        :INTEGER,
        :ENUMERATED,
        :REAL,
        :"OBJECT IDENTIFIER",
        :"RELATIVE-OID",
        :NULL,
        :"BIT STRING",
        :"OCTET STRING",
        :ObjectDescriptor,
        :NumericString,
        :TeletexString,
        :T61String,
        :VideotexString,
        :UTCTime,
        :GeneralizedTime,
        :GraphicString,
        :VisibleString,
        :GeneralString,
        :PrintableString,
        :IA5String,
        :UniversalString,
        :UTF8String,
        :BMPString,
        :ENUMERATED,
        :BOOLEAN
      ]
    )
  end

  defp construct_bif(t) do
    :lists.member(t, [:SEQUENCE, :"SEQUENCE OF", :CHOICE, :SET, :"SET OF"])
  end

  def def_to_tag(r_tag(class: class, number: number)) do
    {class, number}
  end

  def def_to_tag(r_ObjectClassFieldType(type: type)) do
    case type do
      t
      when is_tuple(t) and
             :erlang.element(1, t) == :fixedtypevaluefield ->
        {:UNIVERSAL, get_inner(type)}

      _ ->
        []
    end
  end

  def def_to_tag(def__) do
    {:UNIVERSAL, get_inner(def__)}
  end

  defp get_fieldtype([], _FieldName) do
    {:no_type, :no_name}
  end

  defp get_fieldtype([field | rest], fieldName) do
    case :erlang.element(2, field) do
      ^fieldName ->
        case :erlang.element(1, field) do
          :fixedtypevaluefield ->
            {:erlang.element(1, field), fieldName, :erlang.element(3, field)}

          _ ->
            {:erlang.element(1, field), fieldName}
        end

      _ ->
        get_fieldtype(rest, fieldName)
    end
  end

  def list2name(l) do
    newL = list2name1(l)
    :lists.concat(:lists.reverse(newL))
  end

  defp list2name1([{:ptype, h1}, h2 | t]) do
    [h1, ~c"_", list2name([h2 | t])]
  end

  defp list2name1([h1, h2 | t]) do
    [h1, ~c"_", list2name([h2 | t])]
  end

  defp list2name1([{:ptype, h} | _T]) do
    [h]
  end

  defp list2name1([h | _T]) do
    [h]
  end

  defp list2name1(h) do
    h
  end

  def list2rname(l) do
    newL = list2rname1(l)
    :lists.concat(:lists.reverse(newL))
  end

  defp list2rname1([{:ptype, h1}, _H2 | _T]) do
    [h1]
  end

  defp list2rname1([h1, h2 | t]) do
    [h1, ~c"_", list2name([h2 | t])]
  end

  defp list2rname1([{:ptype, h} | _T]) do
    [h]
  end

  defp list2rname1([h | _T]) do
    [h]
  end

  defp list2rname1([]) do
    []
  end

  def complist_as_tuple(compList) do
    complist_as_tuple(compList, [], [], [], :root)
  end

  defp complist_as_tuple([r_EXTENSIONMARK() | t], acc, ext, acc2, :root) do
    complist_as_tuple(t, acc, ext, acc2, :ext)
  end

  defp complist_as_tuple([r_EXTENSIONMARK() | t], acc, ext, acc2, :ext) do
    complist_as_tuple(t, acc, ext, acc2, :root2)
  end

  defp complist_as_tuple([c | t], acc, ext, acc2, :root) do
    complist_as_tuple(t, [c | acc], ext, acc2, :root)
  end

  defp complist_as_tuple([c | t], acc, ext, acc2, :ext) do
    complist_as_tuple(t, acc, [c | ext], acc2, :ext)
  end

  defp complist_as_tuple([c | t], acc, ext, acc2, :root2) do
    complist_as_tuple(t, acc, ext, [c | acc2], :root2)
  end

  defp complist_as_tuple([], acc, _Ext, _Acc2, :root) do
    :lists.reverse(acc)
  end

  defp complist_as_tuple([], acc, ext, _Acc2, :ext) do
    {:lists.reverse(acc), :lists.reverse(ext)}
  end

  defp complist_as_tuple([], acc, ext, acc2, :root2) do
    {:lists.reverse(acc), :lists.reverse(ext), :lists.reverse(acc2)}
  end

  def constructed_suffix(_, r_SEQUENCE(pname: ptypename))
      when ptypename !== false do
    {:ptype, ptypename}
  end

  def constructed_suffix(_, r_SET(pname: ptypename))
      when ptypename !== false do
    {:ptype, ptypename}
  end

  def constructed_suffix(:"SEQUENCE OF", _) do
    :SEQOF
  end

  def constructed_suffix(:"SET OF", _) do
    :SETOF
  end

  def index2suffix(0) do
    ~c""
  end

  def index2suffix(n) do
    :lists.concat([~c"_", n])
  end

  def ct_gen_module(r_gen(erule: :ber)) do
    :asn1ct_gen_ber_bin_v2
  end

  def ct_gen_module(r_gen(erule: :per)) do
    :asn1ct_gen_per
  end

  def ct_gen_module(r_gen(erule: :jer)) do
    :asn1ct_gen_jer
  end

  defp ct_constructed_module(r_gen(erule: :ber)) do
    :asn1ct_constructed_ber_bin_v2
  end

  defp ct_constructed_module(r_gen(erule: :jer)) do
    :asn1ct_gen_jer
  end

  defp ct_constructed_module(r_gen(erule: :per)) do
    :asn1ct_constructed_per
  end

  def get_constraint(c, key) do
    case :lists.keysearch(key, 1, c) do
      false ->
        :no

      {:value, {_, v}} ->
        v

      {:value, cnstr} ->
        cnstr
    end
  end

  def get_record_name_prefix(r_gen(rec_prefix: prefix)) do
    prefix
  end

  defp get_macro_name_prefix(r_gen(macro_prefix: prefix)) do
    prefix
  end
end
