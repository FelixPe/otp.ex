defmodule :m_erl_lint do
  use Bitwise

  import :lists,
    only: [all: 2, any: 2, foldl: 3, foldr: 3, map: 2, mapfoldl: 3, member: 2, reverse: 1]

  def bool_option(on, off, default, opts) do
    foldl(
      fn
        opt, _Def when opt === on ->
          true

        opt, _Def when opt === off ->
          false

        _Opt, def__ ->
          def__
      end,
      default,
      opts
    )
  end

  def value_option(flag, default, opts) do
    foldl(
      fn
        {opt, val}, _Def when opt === flag ->
          val

        _Opt, def__ ->
          def__
      end,
      default,
      opts
    )
  end

  def value_option(flag, default, on, onVal, off, offVal, opts) do
    foldl(
      fn
        {opt, val}, _Def when opt === flag ->
          val

        opt, _Def when opt === on ->
          onVal

        opt, _Def when opt === off ->
          offVal

        _Opt, def__ ->
          def__
      end,
      default,
      opts
    )
  end

  require Record

  Record.defrecord(:r_bittype, :bittype,
    type: :undefined,
    unit: :undefined,
    sign: :undefined,
    endian: :undefined
  )

  Record.defrecord(:r_typeinfo, :typeinfo,
    attr: :undefined,
    anno: :undefined
  )

  Record.defrecord(:r_used_type, :used_type,
    anno: :undefined,
    at: {:export, []}
  )

  Record.defrecord(:r_usage, :usage,
    calls: :maps.new(),
    imported: [],
    used_records: :gb_sets.new(),
    used_types: :maps.new()
  )

  Record.defrecord(:r_lint, :lint,
    state: :start,
    module: :"",
    behaviour: [],
    exports: :gb_sets.empty(),
    imports: [],
    compile: [],
    records: :maps.new(),
    locals: :gb_sets.empty(),
    no_auto: :gb_sets.empty(),
    defined: :gb_sets.empty(),
    on_load: [],
    on_load_anno: :erl_anno.new(0),
    clashes: [],
    not_deprecated: [],
    not_removed: :gb_sets.empty(),
    func: [],
    type_id: [],
    warn_format: 0,
    enabled_warnings: [],
    nowarn_bif_clash: [],
    errors: [],
    warnings: [],
    file: ~c"",
    recdef_top: false,
    xqlc: false,
    called: [],
    fun_used_vars: :undefined,
    usage: :EFE_TODO_NESTED_RECORD,
    specs: :maps.new(),
    callbacks: :maps.new(),
    optional_callbacks: :maps.new(),
    types: :maps.new(),
    exp_types: :gb_sets.empty(),
    feature_keywords: feature_keywords(),
    bvt: :none,
    gexpr_context: :guard,
    load_nif: false
  )

  def format_error(:undefined_module) do
    ~c"no module definition"
  end

  def format_error(:redefine_module) do
    ~c"redefining module"
  end

  def format_error(:pmod_unsupported) do
    ~c"parameterized modules are no longer supported"
  end

  def format_error(:non_latin1_module_unsupported) do
    ~c"module names with non-latin1 characters are not supported"
  end

  def format_error(:empty_module_name) do
    ~c"the module name must not be empty"
  end

  def format_error(:blank_module_name) do
    ~c"the module name must contain at least one visible character"
  end

  def format_error(:ctrl_chars_in_module_name) do
    ~c"the module name must not contain control characters"
  end

  def format_error(:invalid_call) do
    ~c"invalid function call"
  end

  def format_error(:invalid_record) do
    ~c"invalid record expression"
  end

  def format_error({:future_feature, ftr, atom}) do
    :io_lib.format(~c"atom '~p' is reserved in the experimental feature '~p'", [atom, ftr])
  end

  def format_error({:attribute, a}) do
    :io_lib.format(~c"attribute ~tw after function definitions", [a])
  end

  def format_error({:missing_qlc_hrl, a}) do
    :io_lib.format(~c"qlc:q/~w called, but \"qlc.hrl\" not included", [a])
  end

  def format_error({:redefine_import, {{f, a}, m}}) do
    :io_lib.format(~c"function ~tw/~w already imported from ~w", [f, a, m])
  end

  def format_error({:bad_inline, {f, a}}) do
    :io_lib.format(~c"inlined function ~tw/~w undefined", [f, a])
  end

  def format_error({:undefined_nif, {f, a}}) do
    :io_lib.format(~c"nif ~tw/~w undefined", [f, a])
  end

  def format_error(:no_load_nif) do
    :io_lib.format(~c"nifs defined, but no call to erlang:load_nif/2", [])
  end

  def format_error({:invalid_deprecated, d}) do
    :io_lib.format(~c"badly formed deprecated attribute ~tw", [d])
  end

  def format_error({:bad_deprecated, {f, a}}) do
    :io_lib.format(~c"deprecated function ~tw/~w undefined or not exported", [f, a])
  end

  def format_error({:invalid_removed, d}) do
    :io_lib.format(~c"badly formed removed attribute ~tw", [d])
  end

  def format_error({:bad_removed, {f, a}})
      when f === :_ or
             a === :_ do
    :io_lib.format(~c"at least one function matching ~tw/~w is still exported", [f, a])
  end

  def format_error({:bad_removed, {f, a}}) do
    :io_lib.format(~c"removed function ~tw/~w is still exported", [f, a])
  end

  def format_error({:bad_nowarn_unused_function, {f, a}}) do
    :io_lib.format(~c"function ~tw/~w undefined", [f, a])
  end

  def format_error({:bad_nowarn_bif_clash, {f, a}}) do
    :io_lib.format(~c"function ~tw/~w undefined", [f, a])
  end

  def format_error(:disallowed_nowarn_bif_clash) do
    :io_lib.format(
      ~c"compile directive nowarn_bif_clash is no longer allowed,~n - use explicit module names or -compile({no_auto_import, [F/A]})",
      []
    )
  end

  def format_error({:bad_on_load, term}) do
    :io_lib.format(~c"badly formed on_load attribute: ~tw", [term])
  end

  def format_error(:multiple_on_loads) do
    ~c"more than one on_load attribute"
  end

  def format_error({:bad_on_load_arity, {f, a}}) do
    :io_lib.format(~c"function ~tw/~w has wrong arity (must be 0)", [f, a])
  end

  def format_error({:undefined_on_load, {f, a}}) do
    :io_lib.format(~c"function ~tw/~w undefined", [f, a])
  end

  def format_error(:nif_inline) do
    ~c"inlining is enabled - local calls to NIFs may call their Erlang implementation instead"
  end

  def format_error(:export_all) do
    ~c"export_all flag enabled - all functions will be exported"
  end

  def format_error({:duplicated_export, {f, a}}) do
    :io_lib.format(~c"function ~tw/~w already exported", [f, a])
  end

  def format_error({:unused_import, {{f, a}, m}}) do
    :io_lib.format(~c"import ~w:~tw/~w is unused", [m, f, a])
  end

  def format_error({:undefined_function, {f, a}}) do
    :io_lib.format(~c"function ~tw/~w undefined", [f, a])
  end

  def format_error({:redefine_function, {f, a}}) do
    :io_lib.format(~c"function ~tw/~w already defined", [f, a])
  end

  def format_error({:define_import, {f, a}}) do
    :io_lib.format(~c"defining imported function ~tw/~w", [f, a])
  end

  def format_error({:unused_function, {f, a}}) do
    :io_lib.format(~c"function ~tw/~w is unused", [f, a])
  end

  def format_error({:call_to_redefined_bif, {f, a}}) do
    :io_lib.format(
      ~c"ambiguous call of overridden auto-imported BIF ~w/~w~n - use erlang:~w/~w or \"-compile({no_auto_import,[~w/~w]}).\" to resolve name clash",
      [f, a, f, a, f, a]
    )
  end

  def format_error({:call_to_redefined_old_bif, {f, a}}) do
    :io_lib.format(
      ~c"ambiguous call of overridden pre R14 auto-imported BIF ~w/~w~n - use erlang:~w/~w or \"-compile({no_auto_import,[~w/~w]}).\" to resolve name clash",
      [f, a, f, a, f, a]
    )
  end

  def format_error({:redefine_old_bif_import, {f, a}}) do
    :io_lib.format(
      ~c"import directive overrides pre R14 auto-imported BIF ~w/~w~n - use \"-compile({no_auto_import,[~w/~w]}).\" to resolve name clash",
      [f, a, f, a]
    )
  end

  def format_error({:redefine_bif_import, {f, a}}) do
    :io_lib.format(
      ~c"import directive overrides auto-imported BIF ~w/~w~n - use \"-compile({no_auto_import,[~w/~w]}).\" to resolve name clash",
      [f, a, f, a]
    )
  end

  def format_error({:deprecated, mFA, string, rel}) do
    :io_lib.format(~c"~s is deprecated and will be removed in ~s; ~s", [
      format_mfa(mFA),
      rel,
      string
    ])
  end

  def format_error({:deprecated, mFA, string})
      when is_list(string) do
    :io_lib.format(~c"~s is deprecated; ~s", [format_mfa(mFA), string])
  end

  def format_error({:deprecated_type, {m1, f1, a1}, string, rel}) do
    :io_lib.format(
      ~c"the type ~p:~p~s is deprecated and will be removed in ~s; ~s",
      [m1, f1, gen_type_paren(a1), rel, string]
    )
  end

  def format_error({:deprecated_type, {m1, f1, a1}, string})
      when is_list(string) do
    :io_lib.format(~c"the type ~p:~p~s is deprecated; ~s", [m1, f1, gen_type_paren(a1), string])
  end

  def format_error({:removed, mFA, replacementMFA, rel}) do
    :io_lib.format(
      ~c"call to ~s will fail, since it was removed in ~s; use ~s",
      [format_mfa(mFA), rel, format_mfa(replacementMFA)]
    )
  end

  def format_error({:removed, mFA, string}) when is_list(string) do
    :io_lib.format(~c"~s is removed; ~s", [format_mfa(mFA), string])
  end

  def format_error({:removed_type, mNA, string}) do
    :io_lib.format(~c"the type ~s is removed; ~s", [format_mna(mNA), string])
  end

  def format_error({:obsolete_guard, {f, a}}) do
    :io_lib.format(~c"~p/~p obsolete (use is_~p/~p)", [f, a, f, a])
  end

  def format_error({:obsolete_guard_overridden, test}) do
    :io_lib.format(
      ~c"obsolete ~s/1 (meaning is_~s/1) is illegal when there is a local/imported function named is_~p/1 ",
      [test, test, test]
    )
  end

  def format_error({:too_many_arguments, arity}) do
    :io_lib.format(~c"too many arguments (~w) - maximum allowed is ~w", [arity, 255])
  end

  def format_error(:illegal_pattern) do
    ~c"illegal pattern"
  end

  def format_error(:illegal_map_key) do
    ~c"illegal map key in pattern"
  end

  def format_error(:illegal_expr) do
    ~c"illegal expression"
  end

  def format_error({:illegal_guard_local_call, {f, a}}) do
    :io_lib.format(~c"call to local/imported function ~tw/~w is illegal in guard", [f, a])
  end

  def format_error(:illegal_guard_expr) do
    ~c"illegal guard expression"
  end

  def format_error(:match_float_zero) do
    ~c"matching on the float 0.0 will no longer also match -0.0 in OTP 27. If you specifically intend to match 0.0 alone, write +0.0 instead."
  end

  def format_error(:illegal_map_construction) do
    ~c"only association operators '=>' are allowed in map construction"
  end

  def format_error({:undefined_record, t}) do
    :io_lib.format(~c"record ~tw undefined", [t])
  end

  def format_error({:redefine_record, t}) do
    :io_lib.format(~c"record ~tw already defined", [t])
  end

  def format_error({:redefine_field, t, f}) do
    :io_lib.format(~c"field ~tw already defined in record ~tw", [f, t])
  end

  def format_error(:bad_multi_field_init) do
    :io_lib.format(~c"'_' initializes no omitted fields", [])
  end

  def format_error({:undefined_field, t, f}) do
    :io_lib.format(~c"field ~tw undefined in record ~tw", [f, t])
  end

  def format_error(:illegal_record_info) do
    ~c"illegal record info"
  end

  def format_error({:field_name_is_variable, t, f}) do
    :io_lib.format(~c"field ~tw is not an atom or _ in record ~tw", [f, t])
  end

  def format_error({:wildcard_in_update, t}) do
    :io_lib.format(~c"meaningless use of _ in update of record ~tw", [t])
  end

  def format_error({:unused_record, t}) do
    :io_lib.format(~c"record ~tw is unused", [t])
  end

  def format_error({:untyped_record, t}) do
    :io_lib.format(~c"record ~tw has field(s) without type information", [t])
  end

  def format_error({:unbound_var, v}) do
    :io_lib.format(~c"variable ~w is unbound", [v])
  end

  def format_error({:unsafe_var, v, {what, where}}) do
    :io_lib.format(~c"variable ~w unsafe in ~w ~s", [v, what, format_where(where)])
  end

  def format_error({:exported_var, v, {what, where}}) do
    :io_lib.format(~c"variable ~w exported from ~w ~s", [v, what, format_where(where)])
  end

  def format_error({:match_underscore_var, v}) do
    :io_lib.format(
      ~c"variable ~w is already bound. If you mean to ignore this value, use '_' or a different underscore-prefixed name",
      [v]
    )
  end

  def format_error({:match_underscore_var_pat, v}) do
    :io_lib.format(
      ~c"variable ~w is bound multiple times in this pattern. If you mean to ignore this value, use '_' or a different underscore-prefixed name",
      [v]
    )
  end

  def format_error({:shadowed_var, v, in__}) do
    :io_lib.format(~c"variable ~w shadowed in ~w", [v, in__])
  end

  def format_error({:unused_var, v}) do
    :io_lib.format(~c"variable ~w is unused", [v])
  end

  def format_error({:variable_in_record_def, v}) do
    :io_lib.format(~c"variable ~w in record definition", [v])
  end

  def format_error({:stacktrace_guard, v}) do
    :io_lib.format(~c"stacktrace variable ~w must not be used in a guard", [v])
  end

  def format_error({:stacktrace_bound, v}) do
    :io_lib.format(~c"stacktrace variable ~w must not be previously bound", [v])
  end

  def format_error({:undefined_bittype, type}) do
    :io_lib.format(~c"bit type ~tw undefined", [type])
  end

  def format_error({:bittype_mismatch, val1, val2, what}) do
    :io_lib.format(~c"conflict in ~s specification for bit field: '~p' and '~p'", [
      what,
      val1,
      val2
    ])
  end

  def format_error(:bittype_unit) do
    ~c"a bit unit size must not be specified unless a size is specified too"
  end

  def format_error(:illegal_bitsize) do
    ~c"illegal bit size"
  end

  def format_error({:illegal_bitsize_local_call, {f, a}}) do
    :io_lib.format(
      ~c"call to local/imported function ~tw/~w is illegal in a size expression for a binary segment",
      [f, a]
    )
  end

  def format_error(:non_integer_bitsize) do
    ~c"a size expression in a pattern evaluates to a non-integer value; this pattern cannot possibly match"
  end

  def format_error(:unsized_binary_not_at_end) do
    ~c"a binary field without size is only allowed at the end of a binary pattern"
  end

  def format_error(:typed_literal_string) do
    ~c"a literal string in a binary pattern must not have a type or a size"
  end

  def format_error(:utf_bittype_size_or_unit) do
    ~c"neither size nor unit must be given for segments of type utf8/utf16/utf32"
  end

  def format_error({:bad_bitsize, type}) do
    :io_lib.format(~c"bad ~s bit size", [type])
  end

  def format_error(:unsized_binary_in_bin_gen_pattern) do
    ~c"binary fields without size are not allowed in patterns of bit string generators"
  end

  def format_error({:conflicting_behaviours, {name, arity}, b, firstL, firstB}) do
    :io_lib.format(
      ~c"conflicting behaviours - callback ~tw/~w required by both '~p' and '~p' ~s",
      [name, arity, b, firstB, format_where(firstL)]
    )
  end

  def format_error({:undefined_behaviour_func, {func, arity}, behaviour}) do
    :io_lib.format(~c"undefined callback function ~tw/~w (behaviour '~w')", [
      func,
      arity,
      behaviour
    ])
  end

  def format_error({:undefined_behaviour, behaviour}) do
    :io_lib.format(~c"behaviour ~tw undefined", [behaviour])
  end

  def format_error({:undefined_behaviour_callbacks, behaviour}) do
    :io_lib.format(~c"behaviour ~w callback functions are undefined", [behaviour])
  end

  def format_error({:ill_defined_behaviour_callbacks, behaviour}) do
    :io_lib.format(~c"behaviour ~w callback functions erroneously defined", [behaviour])
  end

  def format_error({:ill_defined_optional_callbacks, behaviour}) do
    :io_lib.format(~c"behaviour ~w optional callback functions erroneously defined", [behaviour])
  end

  def format_error({:behaviour_info, {_M, f, a}}) do
    :io_lib.format(
      ~c"cannot define callback attibute for ~tw/~w when behaviour_info is defined",
      [f, a]
    )
  end

  def format_error({:redefine_optional_callback, {f, a}}) do
    :io_lib.format(~c"optional callback ~tw/~w duplicated", [f, a])
  end

  def format_error({:undefined_callback, {_M, f, a}}) do
    :io_lib.format(~c"callback ~tw/~w is undefined", [f, a])
  end

  def format_error({:singleton_typevar, name}) do
    :io_lib.format(~c"type variable ~w is only used once (is unbound)", [name])
  end

  def format_error({:bad_export_type, _ETs}) do
    :io_lib.format(~c"bad export_type declaration", [])
  end

  def format_error({:duplicated_export_type, {t, a}}) do
    :io_lib.format(~c"type ~tw/~w already exported", [t, a])
  end

  def format_error({:undefined_type, {typeName, arity}}) do
    :io_lib.format(~c"type ~tw~s undefined", [typeName, gen_type_paren(arity)])
  end

  def format_error({:unused_type, {typeName, arity}}) do
    :io_lib.format(~c"type ~tw~s is unused", [typeName, gen_type_paren(arity)])
  end

  def format_error({:redefine_builtin_type, {typeName, arity}}) do
    :io_lib.format(~c"local redefinition of built-in type: ~w~s", [
      typeName,
      gen_type_paren(arity)
    ])
  end

  def format_error({:renamed_type, oldName, newName}) do
    :io_lib.format(~c"type ~w() is now called ~w(); please use the new name instead", [
      oldName,
      newName
    ])
  end

  def format_error({:redefine_type, {typeName, arity}}) do
    :io_lib.format(~c"type ~tw~s already defined", [typeName, gen_type_paren(arity)])
  end

  def format_error({:type_syntax, constr}) do
    :io_lib.format(~c"bad ~tw type", [constr])
  end

  def format_error(:old_abstract_code) do
    :io_lib.format(
      ~c"abstract code generated before Erlang/OTP 19.0 and having typed record fields cannot be compiled",
      []
    )
  end

  def format_error({:redefine_spec, {m, f, a}}) do
    :io_lib.format(~c"spec for ~tw:~tw/~w already defined", [m, f, a])
  end

  def format_error({:redefine_spec, {f, a}}) do
    :io_lib.format(~c"spec for ~tw/~w already defined", [f, a])
  end

  def format_error({:redefine_callback, {f, a}}) do
    :io_lib.format(~c"callback ~tw/~w already defined", [f, a])
  end

  def format_error({:bad_callback, {m, f, a}}) do
    :io_lib.format(~c"explicit module not allowed for callback ~tw:~tw/~w", [m, f, a])
  end

  def format_error({:bad_module, {m, f, a}}) do
    :io_lib.format(~c"spec for function ~w:~tw/~w from other module", [m, f, a])
  end

  def format_error({:spec_fun_undefined, {f, a}}) do
    :io_lib.format(~c"spec for undefined function ~tw/~w", [f, a])
  end

  def format_error({:missing_spec, {f, a}}) do
    :io_lib.format(~c"missing specification for function ~tw/~w", [f, a])
  end

  def format_error(:spec_wrong_arity) do
    ~c"spec has wrong arity"
  end

  def format_error(:callback_wrong_arity) do
    ~c"callback has wrong arity"
  end

  def format_error({:deprecated_builtin_type, {name, arity}, replacement, rel}) do
    useS =
      case replacement do
        {mod, newName} ->
          :io_lib.format(~c"use ~w:~w/~w", [mod, newName, arity])

        {mod, newName, newArity} ->
          :io_lib.format(
            ~c"use ~w:~w/~w or preferably ~w:~w/~w",
            [mod, newName, arity, mod, newName, newArity]
          )
      end

    :io_lib.format(~c"type ~w/~w is deprecated and will be removed in ~s; use ~s", [
      name,
      arity,
      rel,
      useS
    ])
  end

  def format_error({:not_exported_opaque, {typeName, arity}}) do
    :io_lib.format(~c"opaque type ~tw~s is not exported", [typeName, gen_type_paren(arity)])
  end

  def format_error({:bad_dialyzer_attribute, term}) do
    :io_lib.format(~c"badly formed dialyzer attribute: ~tw", [term])
  end

  def format_error({:bad_dialyzer_option, term}) do
    :io_lib.format(~c"unknown dialyzer warning option: ~tw", [term])
  end

  def format_error({:format_error, {fmt, args}}) do
    :io_lib.format(fmt, args)
  end

  defp gen_type_paren(arity)
       when is_integer(arity) and
              arity >= 0 do
    gen_type_paren_1(arity, ~c")")
  end

  defp gen_type_paren_1(0, acc) do
    ~c"(" ++ acc
  end

  defp gen_type_paren_1(1, acc) do
    ~c"(_" ++ acc
  end

  defp gen_type_paren_1(n, acc) do
    gen_type_paren_1(n - 1, ~c",_" ++ acc)
  end

  defp format_mfa({m, f, [_ | _] = as}) do
    ~c"," ++ arityString =
      :lists.append(
        for a <- as do
          [?, | :erlang.integer_to_list(a)]
        end
      )

    format_mf(m, f, arityString)
  end

  defp format_mfa({m, f, a}) when is_integer(a) do
    format_mf(m, f, :erlang.integer_to_list(a))
  end

  defp format_mf(m, f, arityString)
       when is_atom(m) and
              is_atom(f) do
    :erlang.atom_to_list(m) ++ ~c":" ++ :erlang.atom_to_list(f) ++ ~c"/" ++ arityString
  end

  defp format_mna({m, n, a}) when is_integer(a) do
    :erlang.atom_to_list(m) ++ ~c":" ++ :erlang.atom_to_list(n) ++ gen_type_paren(a)
  end

  defp format_where(l) when is_integer(l) do
    :io_lib.format(~c"(line ~p)", [l])
  end

  defp format_where({l, c})
       when is_integer(l) and
              is_integer(c) do
    :io_lib.format(~c"(line ~p, column ~p)", [l, c])
  end

  defp pseudolocals() do
    [{:module_info, 0}, {:module_info, 1}, {:record_info, 2}]
  end

  def exprs(exprs, bindingsList) do
    exprs_opt(exprs, bindingsList, [])
  end

  def exprs_opt(exprs, bindingsList, opts) do
    {st0, vs} =
      foldl(
        fn
          {{:record, _SequenceNumber, _Name}, attr0}, {st1, vs1} ->
            attr = set_file(attr0, ~c"none")
            {attribute_state(attr, st1), vs1}

          {v, _}, {st1, vs1} ->
            {st1, [{v, {:bound, :unused, []}} | vs1]}
        end,
        {start(~c"nofile", opts), []},
        bindingsList
      )

    vt = :orddict.from_list(vs)
    {_Evt, st} = exprs(set_file(exprs, ~c"nofile"), vt, st0)
    return_status(st)
  end

  def used_vars(exprs, bindingsList) do
    vs =
      foldl(
        fn
          {{:record, _SequenceNumber, _Name}, _Attr}, vs0 ->
            vs0

          {v, _Val}, vs0 ->
            [{v, {:bound, :unused, []}} | vs0]
        end,
        [],
        bindingsList
      )

    vt = :orddict.from_list(vs)
    st0 = r_lint(start(), fun_used_vars: :maps.new())
    {_Evt, st1} = exprs(exprs, vt, st0)
    r_lint(st1, :fun_used_vars)
  end

  def module(forms) do
    opts = compiler_options(forms)
    st = forms(forms, start(~c"nofile", opts))
    return_status(st)
  end

  def module(forms, fileName) do
    opts = compiler_options(forms)
    st = forms(forms, start(fileName, opts))
    return_status(st)
  end

  def module(forms, fileName, opts0) do
    opts = compiler_options(forms) ++ opts0
    st = forms(forms, start(fileName, opts))
    return_status(st)
  end

  defp compiler_options(forms) do
    :lists.flatten(
      for {:attribute, _, :compile, c} <- forms do
        c
      end
    )
  end

  defp start() do
    start(~c"nofile", [])
  end

  defp start(file, opts) do
    enabled0 = [
      {:unused_vars, bool_option(:warn_unused_vars, :nowarn_unused_vars, true, opts)},
      {:underscore_match,
       bool_option(:warn_underscore_match, :nowarn_underscore_match, true, opts)},
      {:export_all, bool_option(:warn_export_all, :nowarn_export_all, true, opts)},
      {:export_vars, bool_option(:warn_export_vars, :nowarn_export_vars, false, opts)},
      {:shadow_vars, bool_option(:warn_shadow_vars, :nowarn_shadow_vars, true, opts)},
      {:unused_import, bool_option(:warn_unused_import, :nowarn_unused_import, false, opts)},
      {:unused_function, bool_option(:warn_unused_function, :nowarn_unused_function, true, opts)},
      {:unused_type, bool_option(:warn_unused_type, :nowarn_unused_type, true, opts)},
      {:bif_clash, bool_option(:warn_bif_clash, :nowarn_bif_clash, true, opts)},
      {:unused_record,
       bool_option(
         :warn_unused_record,
         :nowarn_unused_record,
         true,
         opts
       )},
      {:deprecated_function,
       bool_option(
         :warn_deprecated_function,
         :nowarn_deprecated_function,
         true,
         opts
       )},
      {:deprecated_type,
       bool_option(
         :warn_deprecated_type,
         :nowarn_deprecated_type,
         true,
         opts
       )},
      {:obsolete_guard,
       bool_option(
         :warn_obsolete_guard,
         :nowarn_obsolete_guard,
         true,
         opts
       )},
      {:untyped_record,
       bool_option(
         :warn_untyped_record,
         :nowarn_untyped_record,
         false,
         opts
       )},
      {:missing_spec,
       bool_option(
         :warn_missing_spec,
         :nowarn_missing_spec,
         false,
         opts
       )},
      {:missing_spec_all,
       bool_option(
         :warn_missing_spec_all,
         :nowarn_missing_spec_all,
         false,
         opts
       )},
      {:removed,
       bool_option(
         :warn_removed,
         :nowarn_removed,
         true,
         opts
       )},
      {:nif_inline,
       bool_option(
         :warn_nif_inline,
         :nowarn_nif_inline,
         true,
         opts
       )},
      {:keyword_warning,
       bool_option(
         :warn_keywords,
         :nowarn_keywords,
         false,
         opts
       )},
      {:redefined_builtin_type,
       bool_option(
         :warn_redefined_builtin_type,
         :nowarn_redefined_builtin_type,
         true,
         opts
       )},
      {:singleton_typevar,
       bool_option(
         :warn_singleton_typevar,
         :nowarn_singleton_typevar,
         true,
         opts
       )},
      {:match_float_zero,
       bool_option(
         :warn_match_float_zero,
         :nowarn_match_float_zero,
         true,
         opts
       )}
    ]

    enabled1 =
      for {category, true} <- enabled0 do
        category
      end

    enabled = :ordsets.from_list(enabled1)

    calls =
      case :ordsets.is_element(
             :unused_function,
             enabled
           ) do
        true ->
          %{{:module_info, 1} => pseudolocals()}

        false ->
          :undefined
      end

    r_lint(
      state: :start,
      exports: :gb_sets.from_list([{:module_info, 0}, {:module_info, 1}]),
      compile: opts,
      defined: :gb_sets.from_list(pseudolocals()),
      called:
        for f <- pseudolocals() do
          {f, 0}
        end,
      usage: r_usage(calls: calls),
      warn_format: value_option(:warn_format, 1, :warn_format, 1, :nowarn_format, 0, opts),
      enabled_warnings: enabled,
      nowarn_bif_clash:
        nowarn_function(
          :nowarn_bif_clash,
          opts
        ),
      file: file
    )
  end

  defp is_warn_enabled(type, r_lint(enabled_warnings: enabled)) do
    :ordsets.is_element(type, enabled)
  end

  defp return_status(st) do
    ws = pack_warnings(r_lint(st, :warnings))

    case pack_errors(r_lint(st, :errors)) do
      [] ->
        {:ok, ws}

      es ->
        {:error, es, ws}
    end
  end

  defp pack_errors(es) do
    {es1, _} =
      mapfoldl(
        fn {file, e}, i ->
          {{file, {i, e}}, i - 1}
        end,
        -1,
        es
      )

    map(
      fn {file, eIs} ->
        {file,
         map(
           fn {_I, e} ->
             e
           end,
           eIs
         )}
      end,
      pack_warnings(es1)
    )
  end

  defp pack_warnings(ws) do
    for file <-
          :lists.usort(
            for {f, _} <- ws do
              f
            end
          ) do
      {file,
       :lists.sort(
         for {f, w} <- ws, f === file do
           w
         end
       )}
    end
  end

  defp add_error(e, st) do
    add_lint_error(e, r_lint(st, :file), st)
  end

  defp add_error(anno, e0, r_lint(gexpr_context: context) = st) do
    e =
      case {e0, context} do
        {:illegal_guard_expr, :bin_seg_size} ->
          :illegal_bitsize

        {{:illegal_guard_local_call, fA}, :bin_seg_size} ->
          {:illegal_bitsize_local_call, fA}

        {_, _} ->
          e0
      end

    {file, location} = loc(anno, st)
    add_lint_error({location, :erl_lint, e}, file, st)
  end

  defp add_lint_error(e, file, st) do
    r_lint(st, errors: [{file, e} | r_lint(st, :errors)])
  end

  defp add_warning(w, st) do
    add_lint_warning(w, r_lint(st, :file), st)
  end

  defp add_warning(anno, w, st) do
    {file, location} = loc(anno, st)
    add_lint_warning({location, :erl_lint, w}, file, st)
  end

  defp add_lint_warning(w, file, st) do
    r_lint(st, warnings: [{file, w} | r_lint(st, :warnings)])
  end

  defp loc(anno, st) do
    location = :erl_anno.location(anno)

    case :erl_anno.file(anno) do
      :undefined ->
        {r_lint(st, :file), location}

      file ->
        {file, location}
    end
  end

  defp forms(forms0, st0) do
    forms = eval_file_attribute(forms0, st0)
    locals = local_functions(forms)
    autoImportSuppressed = auto_import_suppressed(r_lint(st0, :compile))
    stDeprecated = disallowed_compile_flags(forms, st0)

    st1 =
      includes_qlc_hrl(
        forms,
        r_lint(stDeprecated,
          locals: locals,
          no_auto: autoImportSuppressed
        )
      )

    st2 = bif_clashes(forms, st1)
    st3 = not_deprecated(forms, st2)
    st4 = not_removed(forms, st3)
    st5 = foldl(&form/2, pre_scan(forms, st4), forms)
    post_traversal_check(forms, st5)
  end

  defp pre_scan([{:attribute, a, :compile, c} | fs], st) do
    case is_warn_enabled(
           :export_all,
           st
         ) and member(:export_all, :lists.flatten([c])) do
      true ->
        pre_scan(fs, add_warning(a, :export_all, st))

      false ->
        pre_scan(fs, st)
    end
  end

  defp pre_scan([_ | fs], st) do
    pre_scan(fs, st)
  end

  defp pre_scan([], st) do
    st
  end

  defp includes_qlc_hrl(forms, st) do
    qH =
      for {:attribute, _, :file, {file, _line}} <- forms,
          :filename.basename(file) === ~c"qlc.hrl" do
        file
      end

    r_lint(st, xqlc: qH !== [])
  end

  defp eval_file_attribute(forms, st) do
    eval_file_attr(forms, r_lint(st, :file))
  end

  defp eval_file_attr(
         [
           {:attribute, _A, :file, {file, _Line}} = form
           | forms
         ],
         _File
       ) do
    [form | eval_file_attr(forms, file)]
  end

  defp eval_file_attr([form0 | forms], file) do
    form = set_form_file(form0, file)
    [form | eval_file_attr(forms, file)]
  end

  defp eval_file_attr([], _File) do
    []
  end

  defp set_form_file({:attribute, a, k, v}, file) do
    {:attribute, :erl_anno.set_file(file, a), k, v}
  end

  defp set_form_file({:function, anno, n, a, c}, file) do
    {:function, :erl_anno.set_file(file, anno), n, a, c}
  end

  defp set_form_file(form, _File) do
    form
  end

  defp set_file(ts, file) when is_list(ts) do
    for t <- ts do
      anno_set_file(t, file)
    end
  end

  defp set_file(t, file) do
    anno_set_file(t, file)
  end

  defp anno_set_file(t, file) do
    f = fn anno ->
      :erl_anno.set_file(file, anno)
    end

    :erl_parse.map_anno(f, t)
  end

  defp form({:error, e}, st) do
    add_error(e, st)
  end

  defp form({:warning, w}, st) do
    add_warning(w, st)
  end

  defp form({:attribute, _A, :file, {file, _Line}}, st) do
    r_lint(st, file: file)
  end

  defp form({:attribute, _A, :compile, _}, st) do
    st
  end

  defp form(form, r_lint(state: state) = st) do
    case state do
      :start ->
        start_state(form, st)

      :attribute ->
        attribute_state(form, st)

      :function ->
        function_state(form, st)
    end
  end

  defp start_state(
         {:attribute, anno, :module, {_, _}} = form,
         st0
       ) do
    st1 = add_error(anno, :pmod_unsupported, st0)
    attribute_state(form, r_lint(st1, state: :attribute))
  end

  defp start_state({:attribute, anno, :module, m}, st0) do
    st1 = r_lint(st0, module: m)
    st2 = r_lint(st1, state: :attribute)
    check_module_name(m, anno, st2)
  end

  defp start_state(form, st) do
    anno =
      case form do
        {:eof, location} ->
          :erl_anno.new(location)

        _ ->
          :erlang.element(2, form)
      end

    st1 = add_error(anno, :undefined_module, st)
    attribute_state(form, r_lint(st1, state: :attribute))
  end

  defp attribute_state(
         {:attribute, _A, :module, _M},
         r_lint(module: :"") = st
       ) do
    st
  end

  defp attribute_state({:attribute, a, :module, _M}, st) do
    add_error(a, :redefine_module, st)
  end

  defp attribute_state({:attribute, a, :export, es}, st) do
    export(a, es, st)
  end

  defp attribute_state({:attribute, a, :export_type, es}, st) do
    export_type(a, es, st)
  end

  defp attribute_state({:attribute, a, :import, is}, st) do
    import(a, is, st)
  end

  defp attribute_state({:attribute, a, :record, {name, fields}}, st) do
    record_def(a, name, fields, st)
  end

  defp attribute_state({:attribute, aa, :behaviour, behaviour}, st) do
    r_lint(st, behaviour: r_lint(st, :behaviour) ++ [{aa, behaviour}])
  end

  defp attribute_state({:attribute, aa, :behavior, behaviour}, st) do
    r_lint(st, behaviour: r_lint(st, :behaviour) ++ [{aa, behaviour}])
  end

  defp attribute_state(
         {:attribute, a, :type, {typeName, typeDef, args}},
         st
       ) do
    type_def(:type, a, typeName, typeDef, args, st)
  end

  defp attribute_state(
         {:attribute, a, :opaque, {typeName, typeDef, args}},
         st
       ) do
    type_def(:opaque, a, typeName, typeDef, args, st)
  end

  defp attribute_state({:attribute, a, :spec, {fun, types}}, st) do
    spec_decl(a, fun, types, st)
  end

  defp attribute_state({:attribute, a, :callback, {fun, types}}, st) do
    callback_decl(a, fun, types, st)
  end

  defp attribute_state({:attribute, a, :optional_callbacks, es}, st) do
    optional_callbacks(a, es, st)
  end

  defp attribute_state({:attribute, a, :on_load, val}, st) do
    on_load(a, val, st)
  end

  defp attribute_state({:attribute, _A, _Other, _Val}, st) do
    st
  end

  defp attribute_state(form, st) do
    function_state(form, r_lint(st, state: :function))
  end

  defp function_state({:attribute, a, :record, {name, fields}}, st) do
    record_def(a, name, fields, st)
  end

  defp function_state(
         {:attribute, a, :type, {typeName, typeDef, args}},
         st
       ) do
    type_def(:type, a, typeName, typeDef, args, st)
  end

  defp function_state(
         {:attribute, a, :opaque, {typeName, typeDef, args}},
         st
       ) do
    type_def(:opaque, a, typeName, typeDef, args, st)
  end

  defp function_state({:attribute, a, :spec, {fun, types}}, st) do
    spec_decl(a, fun, types, st)
  end

  defp function_state({:attribute, _A, :dialyzer, _Val}, st) do
    st
  end

  defp function_state({:attribute, aa, attr, _Val}, st) do
    add_error(aa, {:attribute, attr}, st)
  end

  defp function_state({:function, anno, n, a, cs}, st) do
    function(anno, n, a, cs, st)
  end

  defp function_state({:eof, location}, st) do
    eof(location, st)
  end

  defp eof(_Location, st0) do
    st0
  end

  defp bif_clashes(forms, r_lint(nowarn_bif_clash: nowarn) = st) do
    clashes0 =
      for {:function, _A, name, arity, _Cs} <- forms,
          :erl_internal.bif(name, arity) do
        {name, arity}
      end

    clashes =
      :ordsets.subtract(
        :ordsets.from_list(clashes0),
        nowarn
      )

    r_lint(st, clashes: clashes)
  end

  defp not_deprecated(forms, r_lint(compile: opts) = st0) do
    mFAsAnno =
      for {:attribute, anno, :compile, args} <- forms,
          {:nowarn_deprecated_function, mFAs0} <- :lists.flatten([args]),
          mFA <- :lists.flatten([mFAs0]) do
        {mFA, anno}
      end

    nowarn =
      for {:nowarn_deprecated_function, mFAs0} <- opts,
          mFA <- :lists.flatten([mFAs0]) do
        mFA
      end

    mAnno =
      for {{m, _F, _A}, anno} <- mFAsAnno,
          is_atom(m) do
        {m, anno}
      end

    st1 =
      foldl(
        fn {m, anno}, st2 ->
          check_module_name(m, anno, st2)
        end,
        st0,
        mAnno
      )

    r_lint(st1, not_deprecated: :ordsets.from_list(nowarn))
  end

  defp not_removed(forms, r_lint(compile: opts) = st0) do
    mFAsAnno =
      for {:attribute, anno, :compile, args} <- forms,
          {:nowarn_removed, mFAs0} <- :lists.flatten([args]),
          mFA <- :lists.flatten([mFAs0]) do
        {mFA, anno}
      end

    nowarn =
      for {:nowarn_removed, mFAs0} <- opts,
          mFA <- :lists.flatten([mFAs0]) do
        mFA
      end

    st1 =
      foldl(
        fn
          {{m, _F, _A}, anno}, st2 ->
            check_module_name(m, anno, st2)

          {m, anno}, st2 ->
            check_module_name(m, anno, st2)
        end,
        st0,
        mFAsAnno
      )

    r_lint(st1, not_removed: :gb_sets.from_list(nowarn))
  end

  defp disallowed_compile_flags(forms, st0) do
    errors0 =
      for {:attribute, a, :compile, :nowarn_bif_clash} <- forms,
          {_, l} <- [loc(a, st0)] do
        {r_lint(st0, :file), {l, :erl_lint, :disallowed_nowarn_bif_clash}}
      end

    errors1 =
      for {:attribute, a, :compile, {:nowarn_bif_clash, {_, _}}} <- forms,
          {_, l} <- [loc(a, st0)] do
        {r_lint(st0, :file), {l, :erl_lint, :disallowed_nowarn_bif_clash}}
      end

    disabled = not is_warn_enabled(:bif_clash, st0)

    errors =
      cond do
        disabled and errors0 === [] ->
          [
            {r_lint(st0, :file), {:erl_lint, :disallowed_nowarn_bif_clash}}
            | r_lint(st0, :errors)
          ]

        disabled ->
          errors0 ++ errors1 ++ r_lint(st0, :errors)

        true ->
          errors1 ++ r_lint(st0, :errors)
      end

    r_lint(st0, errors: errors)
  end

  defp post_traversal_check(forms, st0) do
    st1 = check_behaviour(st0)
    st2 = check_deprecated(forms, st1)
    st3 = check_imports(forms, st2)
    st4 = check_inlines(forms, st3)
    st5 = check_undefined_functions(st4)
    st6 = check_unused_functions(forms, st5)
    st7 = check_bif_clashes(forms, st6)
    st8 = check_specs_without_function(st7)
    st9 = check_functions_without_spec(forms, st8)
    stA = check_undefined_types(st9)
    stB = check_unused_types(forms, stA)
    stC = check_untyped_records(forms, stB)
    stD = check_on_load(stC)
    stE = check_unused_records(forms, stD)
    stF = check_local_opaque_types(stE)
    stG = check_dialyzer_attribute(forms, stF)
    stH = check_callback_information(stG)
    stI = check_nifs(forms, stH)
    check_removed(forms, stI)
  end

  defp check_behaviour(st0) do
    behaviour_check(r_lint(st0, :behaviour), st0)
  end

  defp behaviour_check(bs, st0) do
    {allBfs0, st1} = all_behaviour_callbacks(bs, [], st0)
    st = behaviour_missing_callbacks(allBfs0, st1)
    exports = exports(st0)

    f = fn bfs, oBfs ->
      for b <- bfs,
          not :lists.member(b, oBfs) or
            :gb_sets.is_member(
              b,
              exports
            ) do
        b
      end
    end

    allBfs =
      for {item, bfs0, oBfs0} <- allBfs0 do
        {item, f.(bfs0, oBfs0)}
      end

    behaviour_conflicting(allBfs, st)
  end

  defp all_behaviour_callbacks([{anno, b} | bs], acc, st0) do
    {bfs0, oBfs0, st} = behaviour_callbacks(anno, b, st0)
    all_behaviour_callbacks(bs, [{{anno, b}, bfs0, oBfs0} | acc], st)
  end

  defp all_behaviour_callbacks([], acc, st) do
    {reverse(acc), st}
  end

  defp behaviour_callbacks(anno, b, st0) do
    try do
      b.behaviour_info(:callbacks)
    catch
      _, _ ->
        st1 = add_warning(anno, {:undefined_behaviour, b}, st0)
        st2 = check_module_name(b, anno, st1)
        {[], [], st2}
    else
      :undefined ->
        st1 = add_warning(anno, {:undefined_behaviour_callbacks, b}, st0)
        {[], [], st1}

      funcs ->
        case is_fa_list(funcs) do
          true ->
            try do
              b.behaviour_info(:optional_callbacks)
            catch
              _, _ ->
                {funcs, [], st0}
            else
              :undefined ->
                {funcs, [], st0}

              optFuncs ->
                case is_fa_list(optFuncs) do
                  true ->
                    {funcs, optFuncs, st0}

                  false ->
                    w = {:ill_defined_optional_callbacks, b}
                    st1 = add_warning(anno, w, st0)
                    {funcs, [], st1}
                end
            end

          false ->
            st1 = add_warning(anno, {:ill_defined_behaviour_callbacks, b}, st0)
            {[], [], st1}
        end
    end
  end

  defp behaviour_missing_callbacks([{{anno, b}, bfs0, oBfs} | t], st0) do
    bfs =
      :ordsets.subtract(
        :ordsets.from_list(bfs0),
        :ordsets.from_list(oBfs)
      )

    exports = :gb_sets.to_list(exports(st0))
    missing = :ordsets.subtract(bfs, exports)

    st =
      foldl(
        fn f, s0 ->
          case is_fa(f) do
            true ->
              m = {:undefined_behaviour_func, f, b}
              add_warning(anno, m, s0)

            false ->
              s0
          end
        end,
        st0,
        missing
      )

    behaviour_missing_callbacks(t, st)
  end

  defp behaviour_missing_callbacks([], st) do
    st
  end

  defp behaviour_conflicting(allBfs, st) do
    r0 = :sofs.relation(allBfs, [{:item, [:callback]}])
    r1 = :sofs.family_to_relation(r0)
    r2 = :sofs.converse(r1)
    r3 = :sofs.relation_to_family(r2)

    r4 =
      :sofs.family_specification(
        fn s ->
          :sofs.no_elements(s) > 1
        end,
        r3
      )

    r = :sofs.to_external(r4)
    behaviour_add_conflicts(r, st)
  end

  defp behaviour_add_conflicts([{cb, [{firstAnno, firstB} | cs]} | t], st0) do
    firstL = :erlang.element(2, loc(firstAnno, st0))
    st = behaviour_add_conflict(cs, cb, firstL, firstB, st0)
    behaviour_add_conflicts(t, st)
  end

  defp behaviour_add_conflicts([], st) do
    st
  end

  defp behaviour_add_conflict([{anno, b} | cs], cb, firstL, firstB, st0) do
    st = add_warning(anno, {:conflicting_behaviours, cb, b, firstL, firstB}, st0)
    behaviour_add_conflict(cs, cb, firstL, firstB, st)
  end

  defp behaviour_add_conflict([], _, _, _, st) do
    st
  end

  defp check_deprecated(forms, st0) do
    exports = exports(st0)
    x = ignore_predefined_funcs(:gb_sets.to_list(exports))
    r_lint(module: mod) = st0

    bad =
      for {:attribute, anno, :deprecated, depr} <- forms,
          d <- :lists.flatten([depr]),
          e <- depr_cat(d, x, mod) do
        {e, anno}
      end

    foldl(
      fn {e, anno}, st1 ->
        add_error(anno, e, st1)
      end,
      st0,
      bad
    )
  end

  defp depr_cat({f, a, flg} = d, x, mod) do
    case deprecated_flag(flg) do
      false ->
        [{:invalid_deprecated, d}]

      true ->
        depr_fa(f, a, x, mod)
    end
  end

  defp depr_cat({f, a}, x, mod) do
    depr_fa(f, a, x, mod)
  end

  defp depr_cat(:module, _X, _Mod) do
    []
  end

  defp depr_cat(d, _X, _Mod) do
    [{:invalid_deprecated, d}]
  end

  defp depr_fa(:_, :_, _X, _Mod) do
    []
  end

  defp depr_fa(f, :_, x, _Mod) when is_atom(f) do
    case :lists.filter(
           fn {f1, _} ->
             f1 === f
           end,
           x
         ) do
      [] ->
        [{:bad_deprecated, {f, :_}}]

      _ ->
        []
    end
  end

  defp depr_fa(f, a, x, mod)
       when is_atom(f) and
              is_integer(a) and a >= 0 do
    case :lists.member({f, a}, x) do
      true ->
        []

      false ->
        case :erlang.is_builtin(mod, f, a) do
          true ->
            []

          false ->
            [{:bad_deprecated, {f, a}}]
        end
    end
  end

  defp depr_fa(f, a, _X, _Mod) do
    [{:invalid_deprecated, {f, a}}]
  end

  defp deprecated_flag(:next_version) do
    true
  end

  defp deprecated_flag(:next_major_release) do
    true
  end

  defp deprecated_flag(:eventually) do
    true
  end

  defp deprecated_flag(string) do
    deprecated_desc(string)
  end

  defp deprecated_desc([char | str]) when is_integer(char) do
    deprecated_desc(str)
  end

  defp deprecated_desc([]) do
    true
  end

  defp deprecated_desc(_) do
    false
  end

  defp check_removed(forms, st0) do
    exports = exports(st0)
    x = ignore_predefined_funcs(:gb_sets.to_list(exports))
    r_lint(module: mod) = st0

    bad =
      for {:attribute, anno, :removed, removed} <- forms,
          r <- :lists.flatten([removed]),
          e <- removed_cat(r, x, mod) do
        {e, anno}
      end

    foldl(
      fn {e, anno}, st1 ->
        add_error(anno, e, st1)
      end,
      st0,
      bad
    )
  end

  defp removed_cat({f, a, desc} = r, x, mod) do
    case removed_desc(desc) do
      false ->
        [{:invalid_removed, r}]

      true ->
        removed_fa(f, a, x, mod)
    end
  end

  defp removed_cat({f, a}, x, mod) do
    removed_fa(f, a, x, mod)
  end

  defp removed_cat(:module, x, mod) do
    removed_fa(:_, :_, x, mod)
  end

  defp removed_cat(r, _X, _Mod) do
    [{:invalid_removed, r}]
  end

  defp removed_fa(:_, :_, x, _Mod) do
    case x do
      [_ | _] ->
        [{:bad_removed, {:_, :_}}]

      [] ->
        []
    end
  end

  defp removed_fa(f, :_, x, _Mod) when is_atom(f) do
    case :lists.filter(
           fn {f1, _} ->
             f1 === f
           end,
           x
         ) do
      [_ | _] ->
        [{:bad_removed, {f, :_}}]

      _ ->
        []
    end
  end

  defp removed_fa(f, a, x, mod)
       when is_atom(f) and
              is_integer(a) and a >= 0 do
    case :lists.member({f, a}, x) do
      true ->
        [{:bad_removed, {f, a}}]

      false ->
        case :erlang.is_builtin(mod, f, a) do
          true ->
            [{:bad_removed, {f, a}}]

          false ->
            []
        end
    end
  end

  defp removed_fa(f, a, _X, _Mod) do
    [{:invalid_removed, {f, a}}]
  end

  defp removed_desc([char | str]) when is_integer(char) do
    removed_desc(str)
  end

  defp removed_desc([]) do
    true
  end

  defp removed_desc(_) do
    false
  end

  defp ignore_predefined_funcs([{:behaviour_info, 1} | fs]) do
    ignore_predefined_funcs(fs)
  end

  defp ignore_predefined_funcs([{:module_info, 0} | fs]) do
    ignore_predefined_funcs(fs)
  end

  defp ignore_predefined_funcs([{:module_info, 1} | fs]) do
    ignore_predefined_funcs(fs)
  end

  defp ignore_predefined_funcs([other | fs]) do
    [other | ignore_predefined_funcs(fs)]
  end

  defp ignore_predefined_funcs([]) do
    []
  end

  defp check_imports(forms, st0) do
    case is_warn_enabled(:unused_import, st0) do
      false ->
        st0

      true ->
        usage = r_lint(st0, :usage)

        unused =
          :ordsets.subtract(
            r_lint(st0, :imports),
            r_usage(usage, :imported)
          )

        imports =
          for {:attribute, anno, :import, {mod, fs}} <- forms,
              fA <- :lists.usort(fs) do
            {{fA, mod}, anno}
          end

        bad =
          for fM <- unused, {fM2, anno} <- imports, fM === fM2 do
            {fM, anno}
          end

        func_location_warning(:unused_import, bad, st0)
    end
  end

  defp check_inlines(forms, st0) do
    check_option_functions(forms, :inline, :bad_inline, st0)
  end

  defp check_unused_functions(forms, st0) do
    st1 = check_option_functions(forms, :nowarn_unused_function, :bad_nowarn_unused_function, st0)
    opts = r_lint(st1, :compile)

    case member(:export_all, opts) or
           not is_warn_enabled(
             :unused_function,
             st1
           ) do
      true ->
        st1

      false ->
        nowarn = nowarn_function(:nowarn_unused_function, opts)
        usage = r_lint(st1, :usage)

        used =
          reached_functions(
            initially_reached(st1),
            r_usage(usage, :calls)
          )

        usedOrNowarn = :ordsets.union(used, nowarn)

        unused =
          :ordsets.subtract(
            :gb_sets.to_list(r_lint(st1, :defined)),
            usedOrNowarn
          )

        functions =
          for {:function, anno, n, a, _} <- forms do
            {{n, a}, anno}
          end

        bad =
          for fA <- unused, {fA2, anno} <- functions, fA === fA2 do
            {fA, anno}
          end

        func_location_warning(:unused_function, bad, st1)
    end
  end

  defp initially_reached(r_lint(exports: exp, on_load: onLoad)) do
    onLoad ++ :gb_sets.to_list(exp)
  end

  defp reached_functions(root, ref) do
    reached_functions(root, [], ref, :gb_sets.empty())
  end

  defp reached_functions([r | rs], more0, ref, reached0) do
    case :gb_sets.is_element(r, reached0) do
      true ->
        reached_functions(rs, more0, ref, reached0)

      false ->
        reached = :gb_sets.add_element(r, reached0)

        case :maps.find(r, ref) do
          {:ok, more} ->
            reached_functions(rs, [more | more0], ref, reached)

          :error ->
            reached_functions(rs, more0, ref, reached)
        end
    end
  end

  defp reached_functions([], [_ | _] = more, ref, reached) do
    reached_functions(:lists.append(more), [], ref, reached)
  end

  defp reached_functions([], [], _Ref, reached) do
    :gb_sets.to_list(reached)
  end

  defp check_undefined_functions(r_lint(called: called0, defined: def0) = st0) do
    called = :sofs.relation(called0, [{:func, :location}])

    def__ =
      :sofs.from_external(
        :gb_sets.to_list(def0),
        [:func]
      )

    undef =
      :sofs.to_external(
        :sofs.drestriction(
          called,
          def__
        )
      )

    foldl(
      fn {nA, anno}, st ->
        add_error(anno, {:undefined_function, nA}, st)
      end,
      st0,
      undef
    )
  end

  defp check_undefined_types(r_lint(usage: usage, types: def__) = st0) do
    used = r_usage(usage, :used_types)
    uTAs = :maps.keys(used)

    undef =
      for tA <- uTAs,
          not :erlang.is_map_key(tA, def__),
          not is_default_type(tA) do
        {tA, :erlang.map_get(tA, used)}
      end

    foldl(
      fn {tA, usedTypeList}, st ->
        foldl(
          fn r_used_type(anno: anno), st1 ->
            add_error(anno, {:undefined_type, tA}, st1)
          end,
          st,
          usedTypeList
        )
      end,
      st0,
      undef
    )
  end

  defp check_bif_clashes(forms, st0) do
    check_option_functions(forms, :nowarn_bif_clash, :bad_nowarn_bif_clash, st0)
  end

  defp check_option_functions(forms, tag0, type, st0) do
    fAsAnno =
      for {:attribute, anno, :compile, args} <- forms,
          {tag, fAs0} <- :lists.flatten([args]),
          tag0 === tag,
          fA <- :lists.flatten([fAs0]) do
        {fA, anno}
      end

    defFunctions =
      (:gb_sets.to_list(r_lint(st0, :defined)) -- pseudolocals()) ++
        for {{f, a}, _} <- :orddict.to_list(r_lint(st0, :imports)) do
          {f, a}
        end

    bad =
      for {fA, anno} <- fAsAnno,
          not member(fA, defFunctions) do
        {fA, anno}
      end

    func_location_error(type, bad, st0)
  end

  defp check_nifs(forms, st0) do
    fAsAnno =
      for {:attribute, anno, :nifs, args} <- forms,
          fA <- args do
        {fA, anno}
      end

    st1 =
      case {fAsAnno, r_lint(st0, :load_nif)} do
        {[{_, anno1} | _], false} ->
          add_warning(anno1, :no_load_nif, st0)

        _ ->
          st0
      end

    defFunctions =
      :gb_sets.subtract(
        r_lint(st1, :defined),
        :gb_sets.from_list(pseudolocals())
      )

    bad =
      for {fA, anno} <- fAsAnno,
          not :gb_sets.is_element(fA, defFunctions) do
        {fA, anno}
      end

    func_location_error(:undefined_nif, bad, st1)
  end

  defp nowarn_function(tag, opts) do
    :ordsets.from_list(
      for {tag1, fAs} <- opts, tag1 === tag, fA <- :lists.flatten([fAs]) do
        fA
      end
    )
  end

  defp func_location_warning(type, fs, st) do
    foldl(
      fn {f, anno}, st0 ->
        add_warning(anno, {type, f}, st0)
      end,
      st,
      fs
    )
  end

  defp func_location_error(type, fs, st) do
    foldl(
      fn {f, anno}, st0 ->
        add_error(anno, {type, f}, st0)
      end,
      st,
      fs
    )
  end

  defp check_untyped_records(forms, st0) do
    case is_warn_enabled(:untyped_record, st0) do
      true ->
        recNames = :maps.keys(r_lint(st0, :records))

        tRecNames =
          for {:attribute, _, :record, {name, fields}} <- forms,
              :lists.all(
                fn
                  {:typed_record_field, _, _} ->
                    true

                  _ ->
                    false
                end,
                fields
              ) do
            name
          end

        foldl(
          fn n, st ->
            {anno, fields} = :erlang.map_get(n, r_lint(st0, :records))

            case fields do
              [] ->
                st

              [_ | _] ->
                add_warning(anno, {:untyped_record, n}, st)
            end
          end,
          st0,
          :ordsets.subtract(
            :ordsets.from_list(recNames),
            :ordsets.from_list(tRecNames)
          )
        )

      false ->
        st0
    end
  end

  defp check_callback_information(
         r_lint(
           callbacks: callbacks,
           optional_callbacks: optionalCbs,
           defined: defined
         ) = st0
       ) do
    optFun = fn mFA, anno, st ->
      case :erlang.is_map_key(mFA, callbacks) do
        true ->
          st

        false ->
          add_error(anno, {:undefined_callback, mFA}, st)
      end
    end

    st1 = :maps.fold(optFun, st0, optionalCbs)

    case :gb_sets.is_member(
           {:behaviour_info, 1},
           defined
         ) do
      false ->
        st1

      true ->
        case map_size(callbacks) do
          0 ->
            st1

          _ ->
            foldFun = fn fa, anno, st ->
              add_error(anno, {:behaviour_info, fa}, st)
            end

            :maps.fold(foldFun, st1, callbacks)
        end
    end
  end

  defp export(anno, es, r_lint(exports: es0, called: called) = st0) do
    {es1, c1, st1} =
      foldl(
        fn nA, {e, c, st2} ->
          st =
            case :gb_sets.is_element(nA, e) do
              true ->
                warn = {:duplicated_export, nA}
                add_warning(anno, warn, st2)

              false ->
                st2
            end

          {:gb_sets.add_element(nA, e), [{nA, anno} | c], st}
        end,
        {es0, called, st0},
        es
      )

    r_lint(st1, exports: es1, called: c1)
  end

  defp export_type(anno, eTs, r_lint(exp_types: eTs0) = st0) do
    try do
      foldl(
        fn {t, a} = tA, {e, st2}
           when is_atom(t) and
                  is_integer(a) ->
          st =
            case :gb_sets.is_element(tA, e) do
              true ->
                warn = {:duplicated_export_type, tA}
                add_warning(anno, warn, st2)

              false ->
                st3 = r_lint(st2, type_id: {:export, []})
                used_type(tA, anno, st3)
            end

          {:gb_sets.add_element(tA, e), st}
        end,
        {eTs0, st0},
        eTs
      )
    catch
      :error, _ ->
        add_error(anno, {:bad_export_type, eTs}, st0)
    else
      {eTs1, st1} ->
        r_lint(st1, exp_types: eTs1)
    end
  end

  defp exports(r_lint(compile: opts, defined: defs, exports: es)) do
    case :lists.member(:export_all, opts) do
      true ->
        defs

      false ->
        es
    end
  end

  defp import(anno, {mod, fs}, st00) do
    st = check_module_name(mod, anno, st00)
    mfs = :ordsets.from_list(fs)

    case check_imports(anno, mfs, r_lint(st, :imports)) do
      [] ->
        r_lint(st, imports: add_imports(mod, mfs, r_lint(st, :imports)))

      efs ->
        {err, st1} =
          foldl(
            fn
              {:bif, {f, a}, _}, {err, st0} ->
                warn =
                  is_warn_enabled(:bif_clash, st0) and
                    not bif_clash_specifically_disabled(
                      st0,
                      {f, a}
                    )

                autoImpSup =
                  is_autoimport_suppressed(
                    r_lint(st0, :no_auto),
                    {f, a}
                  )

                oldBif = :erl_internal.old_bif(f, a)

                {err,
                 cond do
                   warn and not autoImpSup and oldBif ->
                     add_error(
                       anno,
                       {:redefine_old_bif_import, {f, a}},
                       st0
                     )

                   warn and not autoImpSup ->
                     add_warning(
                       anno,
                       {:redefine_bif_import, {f, a}},
                       st0
                     )

                   true ->
                     st0
                 end}

              ef, {_Err, st0} ->
                {true, add_error(anno, {:redefine_import, ef}, st0)}
            end,
            {false, st},
            efs
          )

        cond do
          not err ->
            r_lint(st1, imports: add_imports(mod, mfs, r_lint(st, :imports)))

          true ->
            st1
        end
    end
  end

  defp check_imports(_Anno, fs, is) do
    foldl(
      fn f, efs ->
        case :orddict.find(f, is) do
          {:ok, mod} ->
            [{f, mod} | efs]

          :error ->
            {n, a} = f

            case :erl_internal.bif(n, a) do
              true ->
                [{:bif, f, :erlang} | efs]

              false ->
                efs
            end
        end
      end,
      [],
      fs
    )
  end

  defp add_imports(mod, fs, is) do
    foldl(
      fn f, is0 ->
        :orddict.store(f, mod, is0)
      end,
      is,
      fs
    )
  end

  defp imported(f, a, st) do
    case :orddict.find({f, a}, r_lint(st, :imports)) do
      {:ok, mod} ->
        {:yes, mod}

      :error ->
        :no
    end
  end

  defp on_load(anno, {name, arity} = fa, r_lint(on_load: onLoad0) = st0)
       when is_atom(name) and is_integer(arity) do
    st =
      r_lint(st0,
        on_load: [fa | onLoad0],
        on_load_anno: anno
      )

    case st do
      r_lint(on_load: [{_, 0}]) ->
        st

      r_lint(on_load: [{_, _}]) ->
        add_error(anno, {:bad_on_load_arity, fa}, st)

      r_lint(on_load: [_, _ | _]) ->
        add_error(anno, :multiple_on_loads, st)
    end
  end

  defp on_load(anno, val, st) do
    add_error(anno, {:bad_on_load, val}, st)
  end

  defp check_on_load(r_lint(defined: defined, on_load: [{_, 0} = fa], on_load_anno: anno) = st) do
    case :gb_sets.is_member(fa, defined) do
      true ->
        st

      false ->
        add_error(anno, {:undefined_on_load, fa}, st)
    end
  end

  defp check_on_load(st) do
    st
  end

  defp call_function(anno0, f, a, r_lint(usage: usage0, called: cd, func: func, file: file) = st) do
    r_usage(calls: cs) = usage0
    nA = {f, a}

    usage =
      case cs do
        :undefined ->
          usage0

        _ ->
          r_usage(usage0, calls: maps_prepend(func, nA, cs))
      end

    anno = :erl_anno.set_file(file, anno0)
    r_lint(st, called: [{nA, anno} | cd], usage: usage)
  end

  defp function(anno, name, arity, cs, st0) do
    st1 = r_lint(st0, func: {name, arity})
    st2 = define_function(anno, name, arity, st1)
    clauses(cs, st2)
  end

  defp define_function(anno, name, arity, st0) do
    st1 = keyword_warning(anno, name, st0)
    nA = {name, arity}

    case :gb_sets.is_member(nA, r_lint(st1, :defined)) do
      true ->
        add_error(anno, {:redefine_function, nA}, st1)

      false ->
        st2 = function_check_max_args(anno, arity, st1)

        st3 =
          r_lint(st2,
            defined:
              :gb_sets.add_element(
                nA,
                r_lint(st2, :defined)
              )
          )

        case imported(name, arity, st3) do
          {:yes, _M} ->
            add_error(anno, {:define_import, nA}, st3)

          :no ->
            st3
        end
    end
  end

  defp function_check_max_args(anno, arity, st) when arity > 255 do
    add_error(anno, {:too_many_arguments, arity}, st)
  end

  defp function_check_max_args(_, _, st) do
    st
  end

  defp clauses(cs, st) do
    foldl(
      fn c, st0 ->
        {_, st1} = clause(c, st0)
        st1
      end,
      st,
      cs
    )
  end

  defp clause({:clause, _Anno, h, g, b}, st0) do
    vt0 = []
    {hvt, hnew, st1} = head(h, vt0, st0)
    vt1 = vtupdate(hvt, vtupdate(hnew, vt0))
    {gvt, st2} = guard(g, vt1, st1)
    vt2 = vtupdate(gvt, vt1)
    {bvt, st3} = exprs(b, vt2, st2)
    upd = vtupdate(bvt, vt2)
    check_unused_vars(upd, vt0, st3)
  end

  defp head(ps, vt, st0) do
    head(ps, vt, vt, st0)
  end

  defp head([p | ps], vt0, old, st0) do
    {pvt, pnew, st1} = pattern(p, vt0, old, st0)
    {psvt, psnew, st2} = head(ps, vt0, old, st1)
    {vt, st3} = vtmerge_pat(pvt, psvt, st2)
    {new, st4} = vtmerge_pat(pnew, psnew, st3)
    {vt, new, st4}
  end

  defp head([], _Vt, _Env, st) do
    {[], [], st}
  end

  defp pattern(p, vt, st) do
    pattern(p, vt, vt, st)
  end

  defp pattern({:var, _Anno, :_}, _Vt, _Old, st) do
    {[], [], st}
  end

  defp pattern({:var, anno, v}, _Vt, old, st) do
    pat_var(v, anno, old, [], st)
  end

  defp pattern({:char, _Anno, _C}, _Vt, _Old, st) do
    {[], [], st}
  end

  defp pattern({:integer, _Anno, _I}, _Vt, _Old, st) do
    {[], [], st}
  end

  defp pattern({:float, anno, f}, _Vt, _Old, st0) do
    st =
      case f == 0 and
             is_warn_enabled(
               :match_float_zero,
               st0
             ) do
        true ->
          add_warning(anno, :match_float_zero, st0)

        false ->
          st0
      end

    {[], [], st}
  end

  defp pattern({:atom, anno, a}, _Vt, _Old, st) do
    {[], [], keyword_warning(anno, a, st)}
  end

  defp pattern({:string, _Anno, _S}, _Vt, _Old, st) do
    {[], [], st}
  end

  defp pattern({nil, _Anno}, _Vt, _Old, st) do
    {[], [], st}
  end

  defp pattern({:cons, _Anno, h, t}, vt0, old, st0) do
    {hvt, hnew, st1} = pattern(h, vt0, old, st0)
    {tvt, tnew, st2} = pattern(t, vt0, old, st1)
    {vt1, st3} = vtmerge_pat(hvt, tvt, st2)
    {new, st4} = vtmerge_pat(hnew, tnew, st3)
    {vt1, new, st4}
  end

  defp pattern({:tuple, _Anno, ps}, vt, old, st) do
    pattern_list(ps, vt, old, st)
  end

  defp pattern({:map, _Anno, ps}, vt, old, st) do
    pattern_map(ps, vt, old, st)
  end

  defp pattern({:record_index, anno, name, field}, _Vt, _Old, st) do
    {vt1, st1} =
      check_record(anno, name, st, fn dfs, st1 ->
        pattern_field(field, name, dfs, st1)
      end)

    {vt1, [], st1}
  end

  defp pattern({:record, anno, name, pfs}, vt, old, st) do
    case :maps.find(name, r_lint(st, :records)) do
      {:ok, {_Anno, fields}} ->
        st1 = used_record(name, st)
        st2 = check_multi_field_init(pfs, anno, fields, st1)
        pattern_fields(pfs, name, fields, vt, old, st2)

      :error ->
        {[], [], add_error(anno, {:undefined_record, name}, st)}
    end
  end

  defp pattern({:bin, _, fs}, vt, old, st) do
    pattern_bin(fs, vt, old, st)
  end

  defp pattern({:op, _Anno, :++, {nil, _}, r}, vt, old, st) do
    pattern(r, vt, old, st)
  end

  defp pattern({:op, _Anno, :++, {:cons, ai, {:char, _A2, _C}, t}, r}, vt, old, st) do
    pattern({:op, ai, :++, t, r}, vt, old, st)
  end

  defp pattern({:op, _Anno, :++, {:cons, ai, {:integer, _A2, _I}, t}, r}, vt, old, st) do
    pattern({:op, ai, :++, t, r}, vt, old, st)
  end

  defp pattern({:op, _Anno, :++, {:string, _Ai, _S}, r}, vt, old, st) do
    pattern(r, vt, old, st)
  end

  defp pattern({:match, _Anno, pat1, pat2}, vt0, old, st0) do
    {lvt, lnew, st1} = pattern(pat1, vt0, old, st0)
    {rvt, rnew, st2} = pattern(pat2, vt0, old, st1)
    {vt1, st3} = vtmerge_pat(lvt, rvt, st2)
    {new, st4} = vtmerge_pat(lnew, rnew, st3)
    {vt1, new, st4}
  end

  defp pattern(pat, _Vt, _Old, st) do
    case is_pattern_expr(pat) do
      true ->
        {[], [], st}

      false ->
        {[], [], add_error(:erlang.element(2, pat), :illegal_pattern, st)}
    end
  end

  defp pattern_list(ps, vt0, old, st) do
    foldl(
      fn p, {psvt, psnew, st0} ->
        {pvt, pnew, st1} = pattern(p, vt0, old, st0)
        {vt1, st2} = vtmerge_pat(pvt, psvt, st1)
        {new, st3} = vtmerge_pat(psnew, pnew, st2)
        {vt1, new, st3}
      end,
      {[], [], st},
      ps
    )
  end

  defp check_multi_field_init(fs, anno, fields, st) do
    case init_fields(fs, anno, fields) === [] do
      true ->
        case has_wildcard_field(fs) do
          :no ->
            st

          wildAnno ->
            add_error(wildAnno, :bad_multi_field_init, st)
        end

      false ->
        st
    end
  end

  def is_pattern_expr(expr) do
    case is_pattern_expr_1(expr) do
      false ->
        false

      true ->
        case :erl_eval.partial_eval(expr) do
          {:integer, _, _} ->
            true

          {:char, _, _} ->
            true

          {:float, _, _} ->
            true

          {:atom, _, _} ->
            true

          _ ->
            false
        end
    end
  end

  defp is_pattern_expr_1({:char, _Anno, _C}) do
    true
  end

  defp is_pattern_expr_1({:integer, _Anno, _I}) do
    true
  end

  defp is_pattern_expr_1({:float, _Anno, _F}) do
    true
  end

  defp is_pattern_expr_1({:atom, _Anno, _A}) do
    true
  end

  defp is_pattern_expr_1({:tuple, _Anno, es}) do
    all(&is_pattern_expr_1/1, es)
  end

  defp is_pattern_expr_1({nil, _Anno}) do
    true
  end

  defp is_pattern_expr_1({:cons, _Anno, h, t}) do
    is_pattern_expr_1(h) and is_pattern_expr_1(t)
  end

  defp is_pattern_expr_1({:op, _Anno, op, a}) do
    :erl_internal.arith_op(op, 1) and is_pattern_expr_1(a)
  end

  defp is_pattern_expr_1({:op, _Anno, op, a1, a2}) do
    :erl_internal.arith_op(
      op,
      2
    ) and all(&is_pattern_expr_1/1, [a1, a2])
  end

  defp is_pattern_expr_1(_Other) do
    false
  end

  defp pattern_map(ps, vt0, old, st0) do
    foldl(
      fn
        {:map_field_assoc, a, _, _}, {psvt, psnew, st1} ->
          {psvt, psnew, add_error(a, :illegal_pattern, st1)}

        {:map_field_exact, _A, k, v}, {psvt, psnew, st1} ->
          st2 = r_lint(st1, gexpr_context: :map_key)
          {kvt, st3} = gexpr(k, vt0, st2)
          {vvt, vnew, st4} = pattern(v, vt0, old, st3)
          {vt1, st5} = vtmerge_pat(kvt, vvt, st4)
          {vt2, st6} = vtmerge_pat(vt1, psvt, st5)
          {new, st7} = vtmerge_pat(psnew, vnew, st6)
          {vt2, new, st7}
      end,
      {[], [], st0},
      ps
    )
  end

  defp pattern_bin(es, vt, old, st0) do
    {_, esvt, esnew, st1} =
      foldl(
        fn e, acc ->
          pattern_element(e, vt, old, acc)
        end,
        {{0, 0}, [], [], st0},
        es
      )

    {esvt, esnew, st1}
  end

  defp pattern_element(
         {:bin_element, anno, {:string, _, _}, size, ts} = be,
         vt,
         old,
         {sz, esvt, esnew, st0} = acc
       ) do
    case good_string_size_type(size, ts) do
      true ->
        pattern_element_1(be, vt, old, acc)

      false ->
        st = add_error(anno, :typed_literal_string, st0)
        {sz, esvt, esnew, st}
    end
  end

  defp pattern_element(be, vt, old, acc) do
    pattern_element_1(be, vt, old, acc)
  end

  defp pattern_element_1(
         {:bin_element, anno, e, sz0, ts},
         vt,
         old,
         {{prevSize, prevAnno}, esvt, esnew, st0}
       ) do
    {pevt, penew, st1} = pat_bit_expr(e, old, esnew, st0)
    {sz1, szvt, sznew, st2} = pat_bit_size(sz0, vt, esnew, st1)
    {sz2, bt, st3} = bit_type(anno, sz1, ts, st2)
    {sz3, st4} = bit_size_check(anno, sz2, bt, st3)

    sz4 =
      case {e, sz3} do
        {{:string, _, s}, :all} ->
          8 * length(s)

        {_, _} ->
          sz3
      end

    st5 =
      case prevSize do
        :all ->
          add_error(prevAnno, :unsized_binary_not_at_end, st4)

        _ ->
          st4
      end

    {{sz4, anno}, vtmerge(szvt, vtmerge(pevt, esvt)), vtmerge(sznew, vtmerge(esnew, penew)), st5}
  end

  defp good_string_size_type(:default, :default) do
    true
  end

  defp good_string_size_type(:default, ts) do
    :lists.any(
      fn
        :utf8 ->
          true

        :utf16 ->
          true

        :utf32 ->
          true

        _ ->
          false
      end,
      ts
    )
  end

  defp good_string_size_type(_, _) do
    false
  end

  defp pat_bit_expr({:var, _, :_}, _Old, _New, st) do
    {[], [], st}
  end

  defp pat_bit_expr({:var, anno, v}, old, new, st) do
    pat_var(v, anno, old, new, st)
  end

  defp pat_bit_expr({:string, _, _}, _Old, _new, st) do
    {[], [], st}
  end

  defp pat_bit_expr({:bin, a, _}, _Old, _New, st) do
    {[], [], add_error(a, :illegal_pattern, st)}
  end

  defp pat_bit_expr(p, _Old, _New, st) do
    case is_pattern_expr(p) do
      true ->
        {[], [], st}

      false ->
        {[], [], add_error(:erlang.element(2, p), :illegal_pattern, st)}
    end
  end

  defp pat_bit_size(:default, _Vt, _New, st) do
    {:default, [], [], st}
  end

  defp pat_bit_size({:var, anno, v}, vt0, new0, st0) do
    {vt, new, st1} = pat_binsize_var(v, anno, vt0, new0, st0)
    {:unknown, vt, new, st1}
  end

  defp pat_bit_size(size, vt0, new0, st0) do
    anno = :erlang.element(2, size)

    case :erl_eval.partial_eval(size) do
      {:integer, ^anno, i} ->
        {i, [], [], st0}

      expr ->
        st1 = r_lint(st0, bvt: new0, gexpr_context: :bin_seg_size)
        {vt, r_lint(bvt: new) = st2} = gexpr(size, vt0, st1)

        st3 =
          r_lint(st2,
            bvt: :none,
            gexpr_context: r_lint(st0, :gexpr_context)
          )

        st =
          case is_bit_size_illegal(expr) do
            true ->
              add_warning(anno, :non_integer_bitsize, st3)

            false ->
              st3
          end

        {:unknown, vt, new, st}
    end
  end

  defp is_bit_size_illegal({:atom, _, _}) do
    true
  end

  defp is_bit_size_illegal({:bin, _, _}) do
    true
  end

  defp is_bit_size_illegal({:cons, _, _, _}) do
    true
  end

  defp is_bit_size_illegal({:float, _, _}) do
    true
  end

  defp is_bit_size_illegal({:map, _, _}) do
    true
  end

  defp is_bit_size_illegal({nil, _}) do
    true
  end

  defp is_bit_size_illegal({:tuple, _, _}) do
    true
  end

  defp is_bit_size_illegal(_) do
    false
  end

  defp expr_bin(es, vt, st0, check) do
    {esvt, st1} =
      foldl(
        fn e, acc ->
          bin_element(e, vt, acc, check)
        end,
        {[], st0},
        es
      )

    {esvt, st1}
  end

  defp bin_element({:bin_element, anno, e, sz0, ts}, vt, {esvt, st0}, check) do
    {vt1, st1} = check.(e, vt, st0)
    {sz1, vt2, st2} = bit_size(sz0, vt, st1, check)
    {sz2, bt, st3} = bit_type(anno, sz1, ts, st2)
    {_Sz3, st4} = bit_size_check(anno, sz2, bt, st3)
    {vtmerge([vt2, vt1, esvt]), st4}
  end

  defp bit_size(:default, _Vt, st, _Check) do
    {:default, [], st}
  end

  defp bit_size({:atom, _Anno, :all}, _Vt, st, _Check) do
    {:all, [], st}
  end

  defp bit_size(size, vt, st, check) do
    info = is_guard_test2_info(st)

    case is_gexpr(size, info) do
      true ->
        case :erl_eval.partial_eval(size) do
          {:integer, _ILn, i} ->
            {i, [], st}

          _Other ->
            {evt, st1} = check.(size, vt, st)
            {:unknown, evt, st1}
        end

      false ->
        {evt, st1} = check.(size, vt, st)
        {:unknown, evt, st1}
    end
  end

  defp bit_type(anno, size0, type, st) do
    case :erl_bits.set_bit_type(size0, type) do
      {:ok, size1, bt} ->
        {size1, bt, st}

      {:error, what} ->
        {:ok, size1, bt} = :erl_bits.set_bit_type(:default, [])
        {size1, bt, add_error(anno, what, st)}
    end
  end

  defp bit_size_check(_Anno, :unknown, _, st) do
    {:unknown, st}
  end

  defp bit_size_check(_Anno, :undefined, r_bittype(type: type), st) do
    true =
      :erlang.or(
        :erlang.or(
          type === :utf8,
          type === :utf16
        ),
        type === :utf32
      )

    {:undefined, st}
  end

  defp bit_size_check(anno, :all, r_bittype(type: type), st) do
    case type do
      :binary ->
        {:all, st}

      _ ->
        {:unknown, add_error(anno, :illegal_bitsize, st)}
    end
  end

  defp bit_size_check(anno, size, r_bittype(type: type, unit: unit), st)
       when is_integer(size) and is_integer(unit) do
    sz = unit * size
    st2 = elemtype_check(anno, type, sz, st)
    {sz, st2}
  end

  defp elemtype_check(_Anno, :float, 16, st) do
    st
  end

  defp elemtype_check(_Anno, :float, 32, st) do
    st
  end

  defp elemtype_check(_Anno, :float, 64, st) do
    st
  end

  defp elemtype_check(anno, :float, _Size, st) do
    add_warning(anno, {:bad_bitsize, ~c"float"}, st)
  end

  defp elemtype_check(_Anno, _Type, _Size, st) do
    st
  end

  defp guard([l | r], vt, st0) when is_list(l) do
    {gvt, st1} = guard_tests(l, vt, st0)
    {gsvt, st2} = guard(r, vtupdate(gvt, vt), st1)
    {vtupdate(gvt, gsvt), st2}
  end

  defp guard(l, vt, st0) do
    guard_tests(l, vt, st0)
  end

  defp guard_tests([g | gs], vt, st0) do
    {gvt, st1} = guard_test(g, vt, st0)
    {gsvt, st2} = guard_tests(gs, vtupdate(gvt, vt), st1)
    {vtupdate(gvt, gsvt), st2}
  end

  defp guard_tests([], _Vt, st) do
    {[], st}
  end

  defp guard_test(g, vt, st0) do
    st1 = obsolete_guard(g, st0)
    guard_test2(g, vt, st1)
  end

  defp guard_test2({:call, anno, {:atom, ar, :record}, [e, a]}, vt, st0) do
    gexpr({:call, anno, {:atom, ar, :is_record}, [e, a]}, vt, st0)
  end

  defp guard_test2({:call, anno, {:atom, _Aa, f}, as} = g, vt, st0) do
    {asvt, st1} = gexpr_list(as, vt, st0)
    a = length(as)

    case :erl_internal.type_test(f, a) do
      true when f !== :is_record and a !== 2 ->
        case no_guard_bif_clash(st1, {f, a}) do
          false ->
            {asvt, add_error(anno, {:illegal_guard_local_call, {f, a}}, st1)}

          true ->
            {asvt, st1}
        end

      _ ->
        gexpr(g, vt, st0)
    end
  end

  defp guard_test2(g, vt, st) do
    gexpr(g, vt, st)
  end

  defp gexpr({:var, anno, v}, vt, st) do
    expr_var(v, anno, vt, st)
  end

  defp gexpr({:char, _Anno, _C}, _Vt, st) do
    {[], st}
  end

  defp gexpr({:integer, _Anno, _I}, _Vt, st) do
    {[], st}
  end

  defp gexpr({:float, _Anno, _F}, _Vt, st) do
    {[], st}
  end

  defp gexpr({:atom, anno, a}, _Vt, st) do
    {[], keyword_warning(anno, a, st)}
  end

  defp gexpr({:string, _Anno, _S}, _Vt, st) do
    {[], st}
  end

  defp gexpr({nil, _Anno}, _Vt, st) do
    {[], st}
  end

  defp gexpr({:cons, _Anno, h, t}, vt, st) do
    gexpr_list([h, t], vt, st)
  end

  defp gexpr({:tuple, _Anno, es}, vt, st) do
    gexpr_list(es, vt, st)
  end

  defp gexpr({:map, _Anno, es}, vt, st) do
    map_fields(es, vt, check_assoc_fields(es, st), &gexpr_list/3)
  end

  defp gexpr({:map, _Anno, src, es}, vt, st) do
    {svt, st1} = gexpr(src, vt, st)
    {fvt, st2} = map_fields(es, vt, st1, &gexpr_list/3)
    {vtmerge(svt, fvt), st2}
  end

  defp gexpr({:record_index, anno, name, field}, _Vt, st) do
    check_record(anno, name, st, fn dfs, st1 ->
      record_field(field, name, dfs, st1)
    end)
  end

  defp gexpr({:record_field, anno, rec, name, field}, vt, st0) do
    {rvt, st1} = gexpr(rec, vt, st0)

    {fvt, st2} =
      check_record(anno, name, st1, fn dfs, st ->
        record_field(field, name, dfs, st)
      end)

    {vtmerge(rvt, fvt), st2}
  end

  defp gexpr({:record, anno, name, inits}, vt, st) do
    check_record(anno, name, st, fn dfs, st1 ->
      ginit_fields(inits, anno, name, dfs, vt, st1)
    end)
  end

  defp gexpr({:bin, _Anno, fs}, vt, st) do
    expr_bin(fs, vt, st, &gexpr/3)
  end

  defp gexpr({:call, _Anno, {:atom, _Ar, :is_record}, [e, {:atom, an, name}]}, vt, st0) do
    {rvt, st1} = gexpr(e, vt, st0)
    {rvt, exist_record(an, name, st1)}
  end

  defp gexpr({:call, anno, {:atom, _Ar, :is_record}, [e, r]}, vt, st0) do
    {asvt, st1} = gexpr_list([e, r], vt, st0)
    {asvt, add_error(anno, :illegal_guard_expr, st1)}
  end

  defp gexpr(
         {:call, anno, {:remote, _Ar, {:atom, _Am, :erlang}, {:atom, af, :is_record}}, [e, a]},
         vt,
         st0
       ) do
    gexpr({:call, anno, {:atom, af, :is_record}, [e, a]}, vt, st0)
  end

  defp gexpr(
         {:call, anno, {:atom, _Ar, :is_record}, [e0, {:atom, _, _Name}, {:integer, _, _}]},
         vt,
         st0
       ) do
    {e, st1} = gexpr(e0, vt, st0)

    case no_guard_bif_clash(st0, {:is_record, 3}) do
      true ->
        {e, st1}

      false ->
        {e, add_error(anno, {:illegal_guard_local_call, {:is_record, 3}}, st1)}
    end
  end

  defp gexpr({:call, anno, {:atom, _Ar, :is_record}, [_, _, _] = asvt0}, vt, st0) do
    {asvt, st1} = gexpr_list(asvt0, vt, st0)
    {asvt, add_error(anno, :illegal_guard_expr, st1)}
  end

  defp gexpr(
         {:call, anno, {:remote, _, {:atom, _, :erlang}, {:atom, _, :is_record} = isr},
          [_, _, _] = args},
         vt,
         st0
       ) do
    gexpr({:call, anno, isr, args}, vt, st0)
  end

  defp gexpr({:call, anno, {:atom, _Aa, f}, as}, vt, st0) do
    {asvt, st1} = gexpr_list(as, vt, st0)
    a = length(as)

    case :erl_internal.guard_bif(
           f,
           a
         ) and no_guard_bif_clash(st1, {f, a}) do
      true ->
        true = :erl_internal.bif(f, a)
        {asvt, st1}

      false ->
        case is_local_function(
               r_lint(st1, :locals),
               {f, a}
             ) or
               is_imported_function(
                 r_lint(st1, :imports),
                 {f, a}
               ) do
          true ->
            {asvt, add_error(anno, {:illegal_guard_local_call, {f, a}}, st1)}

          _ ->
            {asvt, add_error(anno, :illegal_guard_expr, st1)}
        end
    end
  end

  defp gexpr({:call, anno, {:remote, _Ar, {:atom, _Am, :erlang}, {:atom, _Af, f}}, as}, vt, st0) do
    {asvt, st1} = gexpr_list(as, vt, st0)
    a = length(as)

    case :erl_internal.guard_bif(f, a) or
           is_gexpr_op(
             f,
             a
           ) do
      true ->
        {asvt, st1}

      false ->
        {asvt, add_error(anno, :illegal_guard_expr, st1)}
    end
  end

  defp gexpr({:op, anno, op, a}, vt, st0) do
    {avt, st1} = gexpr(a, vt, st0)

    case is_gexpr_op(op, 1) do
      true ->
        {avt, st1}

      false ->
        {avt, add_error(anno, :illegal_guard_expr, st1)}
    end
  end

  defp gexpr({:op, _, :andalso, l, r}, vt, st) do
    gexpr_list([l, r], vt, st)
  end

  defp gexpr({:op, _, :orelse, l, r}, vt, st) do
    gexpr_list([l, r], vt, st)
  end

  defp gexpr({:op, _Anno, eqOp, l, r}, vt, st0)
       when eqOp === :"=:=" or eqOp === :"=/=" do
    st1 =
      expr_check_match_zero(
        r,
        expr_check_match_zero(l, st0)
      )

    gexpr_list([l, r], vt, st1)
  end

  defp gexpr({:op, anno, op, l, r}, vt, st0) do
    {avt, st1} = gexpr_list([l, r], vt, st0)

    case is_gexpr_op(op, 2) do
      true ->
        {avt, st1}

      false ->
        {avt, add_error(anno, :illegal_guard_expr, st1)}
    end
  end

  defp gexpr(e, _Vt, st) do
    {[], add_error(:erlang.element(2, e), :illegal_guard_expr, st)}
  end

  defp gexpr_list(es, vt, st) do
    foldl(
      fn e, {esvt, st0} ->
        {evt, st1} = gexpr(e, vt, st0)
        {vtmerge(evt, esvt), st1}
      end,
      {[], st},
      es
    )
  end

  def is_guard_test(e) do
    is_guard_test2(
      e,
      {:maps.new(),
       fn _ ->
         false
       end}
    )
  end

  def is_guard_test(expression, forms) do
    is_guard_test(expression, forms, fn _ ->
      false
    end)
  end

  def is_guard_test(expression, forms, isOverridden) do
    noFileExpression = set_file(expression, ~c"nofile")

    f = fn ->
      st =
        foldl(
          fn
            {:attribute, _, :record, _} = attr0, st0 ->
              attr = set_file(attr0, ~c"none")
              attribute_state(attr, st0)

            _, st0 ->
              st0
          end,
          start(),
          forms
        )

      r_lint(st, :records)
    end

    is_guard_test2(noFileExpression, {f, isOverridden})
  end

  defp is_guard_test2(
         {:call, anno, {:atom, ar, :record}, [e, a]},
         info
       ) do
    is_gexpr(
      {:call, anno, {:atom, ar, :is_record}, [e, a]},
      info
    )
  end

  defp is_guard_test2(
         {:call, _Anno, {:atom, _Aa, test}, as} = call,
         {_, isOverridden} = info
       ) do
    a = length(as)

    not isOverridden.({test, a}) and
      case :erl_internal.type_test(test, a) do
        true ->
          is_gexpr_list(as, info)

        false ->
          is_gexpr(call, info)
      end
  end

  defp is_guard_test2(g, info) do
    is_gexpr(g, info)
  end

  def is_guard_expr(e) do
    is_gexpr(
      e,
      {[],
       fn {_, _} ->
         false
       end}
    )
  end

  defp is_gexpr({:var, _A, _V}, _Info) do
    true
  end

  defp is_gexpr({:char, _A, _C}, _Info) do
    true
  end

  defp is_gexpr({:integer, _A, _I}, _Info) do
    true
  end

  defp is_gexpr({:float, _A, _F}, _Info) do
    true
  end

  defp is_gexpr({:atom, _A, _Atom}, _Info) do
    true
  end

  defp is_gexpr({:string, _A, _S}, _Info) do
    true
  end

  defp is_gexpr({nil, _A}, _Info) do
    true
  end

  defp is_gexpr({:cons, _A, h, t}, info) do
    is_gexpr_list([h, t], info)
  end

  defp is_gexpr({:tuple, _A, es}, info) do
    is_gexpr_list(es, info)
  end

  defp is_gexpr({:map, _A, es}, info) do
    is_map_fields(es, info)
  end

  defp is_gexpr({:map, _A, src, es}, info) do
    is_gexpr(src, info) and is_map_fields(es, info)
  end

  defp is_gexpr({:record_index, _A, _Name, field}, info) do
    is_gexpr(field, info)
  end

  defp is_gexpr({:record_field, _A, rec, _Name, field}, info) do
    is_gexpr_list([rec, field], info)
  end

  defp is_gexpr({:record, a, name, inits}, info0) do
    info =
      case info0 do
        {%{}, _} ->
          info0

        {f, isOverridden} when is_function(f, 0) ->
          {f.(), isOverridden}
      end

    is_gexpr_fields(inits, a, name, info)
  end

  defp is_gexpr({:bin, _A, fs}, info) do
    all(
      fn {:bin_element, _Anno, e, sz, _Ts} ->
        :erlang.and(
          is_gexpr(e, info),
          sz === :default or is_gexpr(sz, info)
        )
      end,
      fs
    )
  end

  defp is_gexpr(
         {:call, _A, {:atom, _Af, f}, as},
         {_, isOverridden} = info
       ) do
    a = length(as)

    not isOverridden.({f, a}) and
      :erl_internal.guard_bif(
        f,
        a
      ) and
      is_gexpr_list(
        as,
        info
      )
  end

  defp is_gexpr(
         {:call, _A, {:remote, _Ar, {:atom, _Am, :erlang}, {:atom, _Af, f}}, as},
         info
       ) do
    a = length(as)

    (:erl_internal.guard_bif(f, a) or
       is_gexpr_op(
         f,
         a
       )) and
      is_gexpr_list(
        as,
        info
      )
  end

  defp is_gexpr(
         {:call, a, {:tuple, at, [{:atom, am, :erlang}, {:atom, af, f}]}, as},
         info
       ) do
    is_gexpr(
      {:call, a, {:remote, at, {:atom, am, :erlang}, {:atom, af, f}}, as},
      info
    )
  end

  defp is_gexpr({:op, _A, op, a}, info) do
    is_gexpr_op(op, 1) and is_gexpr(a, info)
  end

  defp is_gexpr({:op, _A, :andalso, a1, a2}, info) do
    is_gexpr_list([a1, a2], info)
  end

  defp is_gexpr({:op, _A, :orelse, a1, a2}, info) do
    is_gexpr_list([a1, a2], info)
  end

  defp is_gexpr({:op, _A, op, a1, a2}, info) do
    is_gexpr_op(op, 2) and is_gexpr_list([a1, a2], info)
  end

  defp is_gexpr(_Other, _Info) do
    false
  end

  defp is_gexpr_op(op, a) do
    try do
      :erl_internal.op_type(op, a)
    catch
      _, _ ->
        false
    else
      :arith ->
        true

      :bool ->
        true

      :comp ->
        true

      :list ->
        false

      :send ->
        false
    end
  end

  defp is_gexpr_list(es, info) do
    all(
      fn e ->
        is_gexpr(e, info)
      end,
      es
    )
  end

  defp is_map_fields([{tag, _, k, v} | fs], info)
       when tag === :map_field_assoc or
              tag === :map_field_exact do
    is_gexpr(k, info) and
      is_gexpr(
        v,
        info
      ) and is_map_fields(fs, info)
  end

  defp is_map_fields([], _Info) do
    true
  end

  defp is_map_fields(_T, _Info) do
    false
  end

  defp is_gexpr_fields(fs, a, name, {rDs, _} = info) do
    iFs =
      case :maps.find(name, rDs) do
        {:ok, {_Anno, fields}} ->
          fs ++ init_fields(fs, a, fields)

        :error ->
          fs
      end

    all(
      fn
        {:record_field, _Af, _Name, v} ->
          is_gexpr(v, info)

        _Other ->
          false
      end,
      iFs
    )
  end

  defp exprs([e | es], vt, st0) do
    {evt, st1} = expr(e, vt, st0)
    {esvt, st2} = exprs(es, vtupdate(evt, vt), st1)
    {vtupdate(evt, esvt), st2}
  end

  defp exprs([], _Vt, st) do
    {[], st}
  end

  defp expr({:var, anno, v}, vt, st) do
    expr_var(v, anno, vt, st)
  end

  defp expr({:char, _Anno, _C}, _Vt, st) do
    {[], st}
  end

  defp expr({:integer, _Anno, _I}, _Vt, st) do
    {[], st}
  end

  defp expr({:float, _Anno, _F}, _Vt, st) do
    {[], st}
  end

  defp expr({:atom, anno, a}, _Vt, st) do
    {[], keyword_warning(anno, a, st)}
  end

  defp expr({:string, _Anno, _S}, _Vt, st) do
    {[], st}
  end

  defp expr({nil, _Anno}, _Vt, st) do
    {[], st}
  end

  defp expr({:cons, _Anno, h, t}, vt, st) do
    expr_list([h, t], vt, st)
  end

  defp expr({:lc, _Anno, e, qs}, vt, st) do
    handle_comprehension(e, qs, vt, st)
  end

  defp expr({:bc, _Anno, e, qs}, vt, st) do
    handle_comprehension(e, qs, vt, st)
  end

  defp expr({:mc, _Anno, e, qs}, vt, st) do
    handle_comprehension(e, qs, vt, st)
  end

  defp expr({:tuple, _Anno, es}, vt, st) do
    expr_list(es, vt, st)
  end

  defp expr({:map, _Anno, es}, vt, st) do
    map_fields(es, vt, check_assoc_fields(es, st), &expr_list/3)
  end

  defp expr({:map, _Anno, src, es}, vt, st) do
    {svt, st1} = expr(src, vt, st)
    {fvt, st2} = map_fields(es, vt, st1, &expr_list/3)
    {vtupdate(svt, fvt), st2}
  end

  defp expr({:record_index, anno, name, field}, _Vt, st) do
    check_record(anno, name, st, fn dfs, st1 ->
      record_field(field, name, dfs, st1)
    end)
  end

  defp expr({:record, anno, name, inits}, vt, st) do
    check_record(anno, name, st, fn dfs, st1 ->
      init_fields(inits, anno, name, dfs, vt, st1)
    end)
  end

  defp expr({:record_field, anno, rec, name, field}, vt, st0) do
    {rvt, st1} = record_expr(anno, rec, vt, st0)

    {fvt, st2} =
      check_record(anno, name, st1, fn dfs, st ->
        record_field(field, name, dfs, st)
      end)

    {vtmerge(rvt, fvt), st2}
  end

  defp expr({:record, anno, rec, name, upds}, vt, st0) do
    {rvt, st1} = record_expr(anno, rec, vt, st0)

    {usvt, st2} =
      check_record(anno, name, st1, fn dfs, st ->
        update_fields(upds, name, dfs, vt, st)
      end)

    case has_wildcard_field(upds) do
      :no ->
        {vtmerge(rvt, usvt), st2}

      wildAnno ->
        {[], add_error(wildAnno, {:wildcard_in_update, name}, st2)}
    end
  end

  defp expr({:bin, _Anno, fs}, vt, st) do
    expr_bin(fs, vt, st, &expr/3)
  end

  defp expr({:block, _Anno, es}, vt, st) do
    exprs(es, vt, st)
  end

  defp expr({:if, anno, cs}, vt, st) do
    icrt_clauses(cs, {:if, anno}, vt, st)
  end

  defp expr({:case, anno, e, cs}, vt, st0) do
    {evt, st1} = expr(e, vt, st0)
    {cvt, st2} = icrt_clauses(cs, {:case, anno}, vtupdate(evt, vt), st1)
    {vtmerge(evt, cvt), st2}
  end

  defp expr({:receive, anno, cs}, vt, st) do
    icrt_clauses(cs, {:receive, anno}, vt, st)
  end

  defp expr({:receive, anno, cs, to, toEs}, vt, st0) do
    {tvt, st1} = expr(to, vt, st0)
    {tevt, st2} = exprs(toEs, vt, st1)
    {cvt, st3} = icrt_clauses(cs, vt, st2)
    csvts = [tevt | cvt]
    rvt = icrt_export(csvts, vt, {:receive, anno}, st3)
    {vtmerge([tvt, tevt, rvt]), st3}
  end

  defp expr({:fun, anno, body}, vt, st) do
    case body do
      {:clauses, cs} ->
        fun_clauses(cs, vt, st)

      {:function, :record_info, 2} ->
        {[], add_error(anno, :illegal_record_info, st)}

      {:function, f, a} ->
        case not is_local_function(
               r_lint(st, :locals),
               {f, a}
             ) and :erl_internal.bif(f, a) and
               not is_autoimport_suppressed(
                 r_lint(st, :no_auto),
                 {f, a}
               ) do
          true ->
            {[], st}

          false ->
            {[], call_function(anno, f, a, st)}
        end

      {:function, m, f, a} ->
        expr_list([m, f, a], vt, st)
    end
  end

  defp expr({:named_fun, _, :_, cs}, vt, st) do
    fun_clauses(cs, vt, st)
  end

  defp expr({:named_fun, anno, name, cs}, vt, st0) do
    nvt0 = [{name, {:bound, :unused, [anno]}}]
    st1 = shadow_vars(nvt0, vt, :"named fun", st0)
    nvt1 = vtupdate(vtsubtract(vt, nvt0), nvt0)
    {csvt, st2} = fun_clauses(cs, nvt1, st1)
    {_, st3} = check_unused_vars(vtupdate(csvt, nvt0), [], st2)
    {vtold(csvt, vt), st3}
  end

  defp expr({:call, _Anno, {:atom, _Ar, :is_record}, [e, {:atom, an, name}]}, vt, st0) do
    {rvt, st1} = expr(e, vt, st0)
    {rvt, exist_record(an, name, st1)}
  end

  defp expr(
         {:call, anno, {:remote, _Ar, {:atom, _Am, :erlang}, {:atom, af, :is_record}}, [e, a]},
         vt,
         st0
       ) do
    expr({:call, anno, {:atom, af, :is_record}, [e, a]}, vt, st0)
  end

  defp expr({:call, a, {:tuple, at, [{:atom, am, :erlang}, {:atom, af, :is_record}]}, as}, vt, st) do
    expr({:call, a, {:remote, at, {:atom, am, :erlang}, {:atom, af, :is_record}}, as}, vt, st)
  end

  defp expr({:call, anno, {:remote, _Ar, {:atom, _Am, m}, {:atom, af, f}}, as}, vt, st0) do
    st1 = keyword_warning(af, f, st0)
    st2 = check_remote_function(anno, m, f, as, st1)
    st3 = check_module_name(m, anno, st2)
    expr_list(as, vt, st3)
  end

  defp expr({:call, anno, {:remote, _Ar, m, f}, as}, vt, st0) do
    st1 = keyword_warning(anno, m, st0)
    st2 = keyword_warning(anno, f, st1)

    st3 =
      case m do
        {:atom, am, mod} ->
          check_module_name(mod, am, st2)

        _ ->
          st2
      end

    expr_list([m, f | as], vt, st3)
  end

  defp expr({:call, anno, {:atom, aa, f}, as}, vt, st0) do
    st1 = keyword_warning(aa, f, st0)
    {asvt, st2} = expr_list(as, vt, st1)
    a = length(as)
    isLocal = is_local_function(r_lint(st2, :locals), {f, a})
    isAutoBif = :erl_internal.bif(f, a)

    autoSuppressed =
      is_autoimport_suppressed(
        r_lint(st2, :no_auto),
        {f, a}
      )

    warn =
      :erlang.and(
        is_warn_enabled(:bif_clash, st2),
        not bif_clash_specifically_disabled(st2, {f, a})
      )

    imported = imported(f, a, st2)

    case not isLocal and imported === :no and isAutoBif and not autoSuppressed do
      true ->
        st3 = deprecated_function(anno, :erlang, f, as, st2)
        {asvt, st3}

      false ->
        {asvt,
         case imported do
           {:yes, m} ->
             st3 = check_remote_function(anno, m, f, as, st2)
             u0 = r_lint(st3, :usage)

             imp =
               :ordsets.add_element(
                 {{f, a}, m},
                 r_usage(u0, :imported)
               )

             r_lint(st3, usage: r_usage(u0, imported: imp))

           :no ->
             case {f, a} do
               {:record_info, 2} ->
                 check_record_info_call(anno, aa, as, st2)

               n ->
                 st3 =
                   cond do
                     not autoSuppressed and isAutoBif and warn ->
                       case :erl_internal.old_bif(f, a) do
                         true ->
                           add_error(
                             anno,
                             {:call_to_redefined_old_bif, {f, a}},
                             st2
                           )

                         false ->
                           add_warning(
                             anno,
                             {:call_to_redefined_bif, {f, a}},
                             st2
                           )
                       end

                     true ->
                       st2
                   end

                 cond do
                   n === r_lint(st3, :func) ->
                     st3

                   true ->
                     call_function(anno, f, a, st3)
                 end
             end
         end}
    end
  end

  defp expr({:call, anno, f, as}, vt, st0) do
    st = warn_invalid_call(anno, f, st0)
    expr_list([f | as], vt, st)
  end

  defp expr({:try, anno, es, scs, ccs, as}, vt, st0) do
    {evt0, st1} = exprs(es, vt, st0)
    tryAnno = {:try, anno}
    uvt = vtunsafe(tryAnno, evt0, vt)
    {sccs, st2} = try_clauses(scs, ccs, tryAnno, vtupdate(evt0, vt), uvt, st1)
    evt1 = vtupdate(uvt, evt0)
    rvt0 = sccs
    rvt1 = vtupdate(vtunsafe(tryAnno, rvt0, vt), rvt0)
    evt2 = vtmerge(evt1, rvt1)
    {avt0, st} = exprs(as, vtupdate(evt2, vt), st2)
    avt1 = vtupdate(vtunsafe(tryAnno, avt0, vt), avt0)
    avt = vtmerge(evt2, avt1)
    {avt, st}
  end

  defp expr({:catch, anno, e}, vt, st0) do
    {evt, st} = expr(e, vt, st0)
    {vtupdate(vtunsafe({:catch, anno}, evt, vt), evt), st}
  end

  defp expr({:match, _Anno, p, e}, vt, st0) do
    {evt, st1} = expr(e, vt, st0)
    {pvt, pnew, st} = pattern(p, vtupdate(evt, vt), st1)
    {vtupdate(pnew, vtmerge(evt, pvt)), st}
  end

  defp expr({:maybe_match, anno, p, e}, vt, st0) do
    expr({:match, anno, p, e}, vt, st0)
  end

  defp expr({:maybe, anno, es}, vt, st) do
    {evt0, st1} = exprs(es, vt, st)
    evt1 = vtupdate(vtunsafe({:maybe, anno}, evt0, vt), vt)
    evt2 = vtmerge(evt0, evt1)
    {evt2, st1}
  end

  defp expr({:maybe, maybeAnno, es, {:else, elseAnno, cs}}, vt, st) do
    {evt0, st1} = exprs(es, vt, st)

    evt1 =
      vtupdate(
        vtunsafe({:maybe, maybeAnno}, evt0, vt),
        vt
      )

    {cvt0, st2} = icrt_clauses(cs, {:else, elseAnno}, evt1, st1)

    cvt1 =
      vtupdate(
        vtunsafe({:else, elseAnno}, cvt0, vt),
        vt
      )

    evt2 = vtmerge(evt0, evt1)
    cvt2 = vtmerge(cvt0, cvt1)
    {vtmerge(evt2, cvt2), st2}
  end

  defp expr({:op, _Anno, _Op, a}, vt, st) do
    expr(a, vt, st)
  end

  defp expr({:op, anno, op, l, r}, vt, st0)
       when op === :orelse or op === :andalso do
    {evt1, st1} = expr(l, vt, st0)
    vt1 = vtupdate(evt1, vt)
    {evt2, st2} = expr(r, vt1, st1)
    evt3 = vtupdate(vtunsafe({op, anno}, evt2, vt1), evt2)
    {vtmerge(evt1, evt3), st2}
  end

  defp expr({:op, _Anno, eqOp, l, r}, vt, st0)
       when eqOp === :"=:=" or eqOp === :"=/=" do
    st =
      expr_check_match_zero(
        r,
        expr_check_match_zero(l, st0)
      )

    expr_list([l, r], vt, st)
  end

  defp expr({:op, _Anno, _Op, l, r}, vt, st) do
    expr_list([l, r], vt, st)
  end

  defp expr({:remote, _Anno, m, _F}, _Vt, st) do
    {[], add_error(:erl_parse.first_anno(m), :illegal_expr, st)}
  end

  defp expr({:ssa_check_when, _Anno, _WantedResult, _Args, _Tag, _Exprs}, _Vt, st) do
    {[], st}
  end

  defp expr_check_match_zero({:float, anno, f}, st) do
    case f == 0 and
           is_warn_enabled(
             :match_float_zero,
             st
           ) do
      true ->
        add_warning(anno, :match_float_zero, st)

      false ->
        st
    end
  end

  defp expr_check_match_zero({:cons, _Anno, h, t}, st) do
    expr_check_match_zero(h, expr_check_match_zero(t, st))
  end

  defp expr_check_match_zero({:tuple, _Anno, es}, st) do
    foldl(&expr_check_match_zero/2, st, es)
  end

  defp expr_check_match_zero(_Expr, st) do
    st
  end

  defp expr_list(es, vt, st0) do
    foldl(
      fn e, {esvt, st1} ->
        {evt, st2} = expr(e, vt, st1)
        vtmerge_pat(evt, esvt, st2)
      end,
      {[], st0},
      es
    )
  end

  defp record_expr(anno, rec, vt, st0) do
    st1 = warn_invalid_record(anno, rec, st0)
    expr(rec, vt, st1)
  end

  defp check_assoc_fields([{:map_field_exact, anno, _, _} | fs], st) do
    check_assoc_fields(
      fs,
      add_error(anno, :illegal_map_construction, st)
    )
  end

  defp check_assoc_fields([{:map_field_assoc, _, _, _} | fs], st) do
    check_assoc_fields(fs, st)
  end

  defp check_assoc_fields([], st) do
    st
  end

  defp map_fields([{tag, _, k, v} | fs], vt, st, f)
       when tag === :map_field_assoc or
              tag === :map_field_exact do
    {pvt, st2} = f.([k, v], vt, st)
    {vts, st3} = map_fields(fs, vt, st2, f)
    {vtupdate(pvt, vts), st3}
  end

  defp map_fields([], _, st, _) do
    {[], st}
  end

  defp warn_invalid_record(anno, r, st) do
    case is_valid_record(r) do
      true ->
        st

      false ->
        add_warning(anno, :invalid_record, st)
    end
  end

  defp is_valid_record(rec) do
    case rec do
      {:char, _, _} ->
        false

      {:integer, _, _} ->
        false

      {:float, _, _} ->
        false

      {:atom, _, _} ->
        false

      {:string, _, _} ->
        false

      {:cons, _, _, _} ->
        false

      {nil, _} ->
        false

      {:lc, _, _, _} ->
        false

      {:record_index, _, _, _} ->
        false

      {:fun, _, _} ->
        false

      {:named_fun, _, _, _} ->
        false

      _ ->
        true
    end
  end

  defp warn_invalid_call(anno, f, st) do
    case is_valid_call(f) do
      true ->
        st

      false ->
        add_warning(anno, :invalid_call, st)
    end
  end

  defp is_valid_call(call) do
    case call do
      {:char, _, _} ->
        false

      {:integer, _, _} ->
        false

      {:float, _, _} ->
        false

      {:string, _, _} ->
        false

      {:cons, _, _, _} ->
        false

      {nil, _} ->
        false

      {:lc, _, _, _} ->
        false

      {:record_index, _, _, _} ->
        false

      {:tuple, _, exprs} when length(exprs) !== 2 ->
        false

      _ ->
        true
    end
  end

  defp record_def(anno, name, fs0, st0) do
    case :erlang.is_map_key(name, r_lint(st0, :records)) do
      true ->
        add_error(anno, {:redefine_record, name}, st0)

      false ->
        {fs1, st1} = def_fields(normalise_fields(fs0), name, st0)
        st2 = r_lint(st1, records: :maps.put(name, {anno, fs1}, r_lint(st1, :records)))

        types =
          for {:typed_record_field, _, t} <- fs0 do
            t
          end

        st3 = r_lint(st2, type_id: {:record, name})
        check_type({:type, nowarn(), :product, types}, st3)
    end
  end

  defp def_fields(fs0, name, st0) do
    foldl(
      fn {:record_field, af, {:atom, aa, f}, v}, {fs, st} ->
        case exist_field(f, fs) do
          true ->
            {fs, add_error(af, {:redefine_field, name, f}, st)}

          false ->
            st1 = r_lint(st, recdef_top: true)
            {_, st2} = expr(v, [], st1)

            st3 =
              r_lint(st1,
                warnings: r_lint(st2, :warnings),
                errors: r_lint(st2, :errors),
                called: r_lint(st2, :called),
                recdef_top: false
              )

            nV =
              case r_lint(st2, :errors) === r_lint(st1, :errors) do
                true ->
                  v

                false ->
                  {:atom, aa, :undefined}
              end

            {[{:record_field, af, {:atom, aa, f}, nV} | fs], st3}
        end
      end,
      {[], st0},
      fs0
    )
  end

  defp normalise_fields(fs) do
    map(
      fn
        {:record_field, af, field} ->
          {:record_field, af, field, {:atom, af, :undefined}}

        {:typed_record_field, {:record_field, af, field}, _Type} ->
          {:record_field, af, field, {:atom, af, :undefined}}

        {:typed_record_field, field, _Type} ->
          field

        f ->
          f
      end,
      fs
    )
  end

  defp exist_record(anno, name, st) do
    case :erlang.is_map_key(name, r_lint(st, :records)) do
      true ->
        used_record(name, st)

      false ->
        add_error(anno, {:undefined_record, name}, st)
    end
  end

  defp check_record(anno, name, st, checkFun) do
    case :maps.find(name, r_lint(st, :records)) do
      {:ok, {_Anno, fields}} ->
        checkFun.(fields, used_record(name, st))

      :error ->
        {[], add_error(anno, {:undefined_record, name}, st)}
    end
  end

  defp used_record(name, r_lint(usage: usage) = st) do
    usedRecs =
      :gb_sets.add_element(
        name,
        r_usage(usage, :used_records)
      )

    r_lint(st, usage: r_usage(usage, used_records: usedRecs))
  end

  defp check_fields(fs, name, fields, vt0, st0, checkFun) do
    {_SeenFields, uvt, st1} =
      foldl(
        fn field, {sfsa, vta, sta} ->
          {sfsb, {vtb, stb}} =
            check_field(
              field,
              name,
              fields,
              vt0,
              sta,
              sfsa,
              checkFun
            )

          {vt1, st1} = vtmerge_pat(vta, vtb, stb)
          {sfsb, vt1, st1}
        end,
        {[], [], st0},
        fs
      )

    {uvt, st1}
  end

  defp check_field({:record_field, af, {:atom, aa, f}, val}, name, fields, vt, st, sfs, checkFun) do
    case member(f, sfs) do
      true ->
        {sfs, {[], add_error(af, {:redefine_field, name, f}, st)}}

      false ->
        {[f | sfs],
         case find_field(f, fields) do
           {:ok, _I} ->
             checkFun.(val, vt, st)

           :error ->
             {[], add_error(aa, {:undefined_field, name, f}, st)}
         end}
    end
  end

  defp check_field(
         {:record_field, _Af, {:var, aa, :_ = f}, val},
         _Name,
         _Fields,
         vt,
         st,
         sfs,
         checkFun
       ) do
    case member(f, sfs) do
      true ->
        {sfs, {[], add_error(aa, :bad_multi_field_init, st)}}

      false ->
        {[f | sfs], checkFun.(val, vt, st)}
    end
  end

  defp check_field(
         {:record_field, _Af, {:var, aa, v}, _Val},
         name,
         _Fields,
         vt,
         st,
         sfs,
         _CheckFun
       ) do
    {sfs, {vt, add_error(aa, {:field_name_is_variable, name, v}, st)}}
  end

  defp pattern_field({:atom, aa, f}, name, fields, st) do
    case find_field(f, fields) do
      {:ok, _I} ->
        {[], st}

      :error ->
        {[], add_error(aa, {:undefined_field, name, f}, st)}
    end
  end

  defp pattern_fields(fs, name, fields, vt0, old, st0) do
    checkFun = fn val, vt, st ->
      pattern(val, vt, old, st)
    end

    {_SeenFields, uvt, unew, st1} =
      foldl(
        fn field, {sfsa, vta, newa, sta} ->
          case check_field(field, name, fields, vt0, sta, sfsa, checkFun) do
            {sfsb, {vtb, stb}} ->
              {vt, st1} =
                vtmerge_pat(
                  vta,
                  vtb,
                  stb
                )

              {sfsb, vt, [], st1}

            {sfsb, {vtb, newb, stb}} ->
              {vt, mst0} =
                vtmerge_pat(
                  vta,
                  vtb,
                  stb
                )

              {new, mst} =
                vtmerge_pat(
                  newa,
                  newb,
                  mst0
                )

              {sfsb, vt, new, mst}
          end
        end,
        {[], [], [], st0},
        fs
      )

    {uvt, unew, st1}
  end

  defp record_field({:atom, aa, f}, name, fields, st) do
    case find_field(f, fields) do
      {:ok, _I} ->
        {[], st}

      :error ->
        {[], add_error(aa, {:undefined_field, name, f}, st)}
    end
  end

  defp init_fields(ifs, anno, name, dfs, vt0, st0) do
    {vt1, st1} = check_fields(ifs, name, dfs, vt0, st0, &expr/3)
    defs = init_fields(ifs, anno, dfs)
    {_, st2} = check_fields(defs, name, dfs, vt1, st1, &expr/3)
    {vt1, r_lint(st1, usage: r_lint(st2, :usage))}
  end

  defp ginit_fields(ifs, anno, name, dfs, vt0, st0) do
    {vt1, st1} = check_fields(ifs, name, dfs, vt0, st0, &gexpr/3)
    defs = init_fields(ifs, anno, dfs)
    st2 = r_lint(st1, errors: [])
    {_, st3} = check_fields(defs, name, dfs, vt1, st2, &gexpr/3)
    r_lint(usage: usage, errors: illErrors) = st3

    st4 =
      r_lint(st1,
        usage: usage,
        errors: illErrors ++ r_lint(st1, :errors)
      )

    {vt1, st4}
  end

  defp init_fields(ifs, anno, dfs) do
    for {:record_field, af, {:atom, aa, f}, di} <- dfs,
        not exist_field(f, ifs) do
      {:record_field, af, {:atom, aa, f}, copy_expr(di, anno)}
    end
  end

  defp update_fields(ufs, name, dfs, vt, st) do
    check_fields(ufs, name, dfs, vt, st, &expr/3)
  end

  defp exist_field(
         f,
         [{:record_field, _Af, {:atom, _Aa, f}, _Val} | _Fs]
       ) do
    true
  end

  defp exist_field(f, [_ | fs]) do
    exist_field(f, fs)
  end

  defp exist_field(_F, []) do
    false
  end

  defp find_field(
         f,
         [{:record_field, _Af, {:atom, _Aa, f}, val} | _Fs]
       ) do
    {:ok, val}
  end

  defp find_field(f, [_ | fs]) do
    find_field(f, fs)
  end

  defp find_field(_F, []) do
    :error
  end

  defp type_def(attr, anno, typeName, protoType, args, st0) do
    typeDefs = r_lint(st0, :types)
    arity = length(args)
    typePair = {typeName, arity}
    info = r_typeinfo(attr: attr, anno: anno)

    storeType = fn st ->
      newDefs = :maps.put(typePair, info, typeDefs)
      checkType = {:type, nowarn(), :product, [protoType | args]}
      st1 = r_lint(st, types: newDefs, type_id: {:type, typePair})
      check_type(checkType, st1)
    end

    case is_default_type(typePair) and
           not member(
             :no_auto_import_types,
             r_lint(st0, :compile)
           ) do
      true ->
        case is_obsolete_builtin_type(typePair) do
          true ->
            storeType.(st0)

          false ->
            st1 = storeType.(st0)
            warn_redefined_builtin_type(anno, typePair, st1)
        end

      false ->
        case :erlang.is_map_key(typePair, typeDefs) do
          true ->
            add_error(anno, {:redefine_type, typePair}, st0)

          false ->
            storeType.(st0)
        end
    end
  end

  defp warn_redefined_builtin_type(anno, typePair, r_lint(compile: opts) = st) do
    case is_warn_enabled(:redefined_builtin_type, st) do
      true ->
        noWarn =
          for {:nowarn_redefined_builtin_type, type0} <- opts,
              type <- :lists.flatten([type0]) do
            type
          end

        case :lists.member(typePair, noWarn) do
          true ->
            st

          false ->
            warn = {:redefine_builtin_type, typePair}
            add_warning(anno, warn, st)
        end

      false ->
        st
    end
  end

  defp check_type(types, st) do
    {seenVars, st1} = check_type_1(types, :maps.new(), st)

    :maps.fold(
      fn
        var, {:seen_once, anno}, accSt ->
          case :erlang.atom_to_list(var) do
            ~c"_" ++ _ ->
              accSt

            _ ->
              add_error(anno, {:singleton_typevar, var}, accSt)
          end

        var, {:seen_once_union, anno}, accSt ->
          case is_warn_enabled(:singleton_typevar, accSt) do
            true ->
              case :erlang.atom_to_list(var) do
                ~c"_" ++ _ ->
                  accSt

                _ ->
                  add_warning(anno, {:singleton_typevar, var}, accSt)
              end

            false ->
              accSt
          end

        _Var, :seen_multiple, accSt ->
          accSt
      end,
      st1,
      seenVars
    )
  end

  defp check_type_1({:type, anno, typeName, args} = type, seenVars, r_lint(types: types) = st) do
    typePair =
      {typeName,
       cond do
         is_list(args) ->
           length(args)

         true ->
           0
       end}

    case :erlang.is_map_key(typePair, types) do
      true ->
        check_type_2(type, seenVars, used_type(typePair, anno, st))

      false ->
        check_type_2(type, seenVars, st)
    end
  end

  defp check_type_1(types, seenVars, st) do
    check_type_2(types, seenVars, st)
  end

  defp check_type_2({:ann_type, _A, [_Var, type]}, seenVars, st) do
    check_type_1(type, seenVars, st)
  end

  defp check_type_2({:remote_type, a, [{:atom, _, mod}, {:atom, _, name}, args]}, seenVars, st00) do
    st0 = check_module_name(mod, a, st00)
    st = deprecated_type(a, mod, name, args, st0)
    currentMod = r_lint(st, :module)

    case mod === currentMod do
      true ->
        check_type_2({:user_type, a, name, args}, seenVars, st)

      false ->
        :lists.foldl(
          fn t, {accSeenVars, accSt} ->
            check_type_1(t, accSeenVars, accSt)
          end,
          {seenVars, st},
          args
        )
    end
  end

  defp check_type_2({:integer, _A, _}, seenVars, st) do
    {seenVars, st}
  end

  defp check_type_2({:atom, _A, _}, seenVars, st) do
    {seenVars, st}
  end

  defp check_type_2({:var, _A, :_}, seenVars, st) do
    {seenVars, st}
  end

  defp check_type_2({:var, a, name}, seenVars, st) do
    newSeenVars =
      case :maps.find(name, seenVars) do
        {:ok, {:seen_once, _}} ->
          :maps.put(name, :seen_multiple, seenVars)

        {:ok, {:seen_once_union, _}} ->
          :maps.put(name, :seen_multiple, seenVars)

        {:ok, :seen_multiple} ->
          seenVars

        :error ->
          :maps.put(name, {:seen_once, a}, seenVars)
      end

    {newSeenVars, st}
  end

  defp check_type_2({:type, a, :bool, []}, seenVars, st) do
    {seenVars, add_warning(a, {:renamed_type, :bool, :boolean}, st)}
  end

  defp check_type_2({:type, a, :fun, [dom, range]}, seenVars, st) do
    st1 =
      case dom do
        {:type, _, :product, _} ->
          st

        {:type, _, :any} ->
          st

        _ ->
          add_error(a, {:type_syntax, :fun}, st)
      end

    check_type_2({:type, nowarn(), :product, [dom, range]}, seenVars, st1)
  end

  defp check_type_2({:type, a, :range, [from, to]}, seenVars, st) do
    st1 =
      case {:erl_eval.partial_eval(from), :erl_eval.partial_eval(to)} do
        {{:integer, _, x}, {:integer, _, y}} when x < y ->
          st

        _ ->
          add_error(a, {:type_syntax, :range}, st)
      end

    {seenVars, st1}
  end

  defp check_type_2({:type, _A, :map, :any}, seenVars, st) do
    {seenVars, st}
  end

  defp check_type_2({:type, _A, :map, pairs}, seenVars, st) do
    :lists.foldl(
      fn pair, {accSeenVars, accSt} ->
        check_type_2(pair, accSeenVars, accSt)
      end,
      {seenVars, st},
      pairs
    )
  end

  defp check_type_2({:type, _A, :map_field_assoc, [dom, range]}, seenVars, st) do
    check_type_2({:type, nowarn(), :product, [dom, range]}, seenVars, st)
  end

  defp check_type_2({:type, _A, :tuple, :any}, seenVars, st) do
    {seenVars, st}
  end

  defp check_type_2({:type, _A, :any}, seenVars, st) do
    {seenVars, st}
  end

  defp check_type_2({:type, a, :binary, [base, unit]}, seenVars, st) do
    st1 =
      case {:erl_eval.partial_eval(base), :erl_eval.partial_eval(unit)} do
        {{:integer, _, baseVal}, {:integer, _, unitVal}}
        when baseVal >= 0 and unitVal >= 0 ->
          st

        _ ->
          add_error(a, {:type_syntax, :binary}, st)
      end

    {seenVars, st1}
  end

  defp check_type_2({:type, a, :record, [name | fields]}, seenVars, st) do
    case name do
      {:atom, _, atom} ->
        st1 = used_record(atom, st)
        check_record_types(a, atom, fields, seenVars, st1)

      _ ->
        {seenVars, add_error(a, {:type_syntax, :record}, st)}
    end
  end

  defp check_type_2({:type, _A, tag, args} = _F, seenVars, st)
       when tag === :product or tag === :tuple do
    :lists.foldl(
      fn t, {accSeenVars, accSt} ->
        check_type_1(t, accSeenVars, accSt)
      end,
      {seenVars, st},
      args
    )
  end

  defp check_type_2({:type, _A, :union, args} = _F, seenVars0, st) do
    :lists.foldl(
      fn t, {accSeenVars0, accSt} ->
        {seenVars1, st0} = check_type_1(t, seenVars0, accSt)

        accSeenVars =
          :maps.merge_with(
            fn
              k, {:seen_once, anno}, {:seen_once, _} ->
                case seenVars0 do
                  %{^k => _} ->
                    {:seen_once, anno}

                  %{} ->
                    {:seen_once_union, anno}
                end

              _K, {:seen_once, anno}, {:seen_once_union, _} ->
                {:seen_once_union, anno}

              _K, {:seen_once_union, _} = r, {:seen_once, _} ->
                r

              _K, {:seen_once_union, _} = r, {:seen_once_union, _} ->
                r

              _K, {:seen_once_union, _}, else__ ->
                else__

              _K, {:seen_once, _}, else__ ->
                else__

              _K, else__, {:seen_once_union, _} ->
                else__

              _K, else__, {:seen_once, _} ->
                else__

              _K, else1, _Else2 ->
                else1
            end,
            accSeenVars0,
            seenVars1
          )

        {accSeenVars, st0}
      end,
      {seenVars0, st},
      args
    )
  end

  defp check_type_2({:type, anno, typeName, args}, seenVars, st) do
    r_lint(module: module, types: types) = st
    arity = length(args)
    typePair = {typeName, arity}

    obsolete =
      is_warn_enabled(
        :deprecated_type,
        st
      ) and obsolete_builtin_type(typePair)

    st1 =
      case obsolete do
        {:deprecated, repl, _}
        when :erlang.element(
               1,
               repl
             ) !== module ->
          case :maps.find(typePair, types) do
            {:ok, _} ->
              used_type(typePair, anno, st)

            :error ->
              {:deprecated, replacement, rel} = obsolete
              tag = :deprecated_builtin_type
              w = {tag, typePair, replacement, rel}
              add_warning(anno, w, st)
          end

        _ ->
          case is_default_type(typePair) do
            true ->
              used_type(typePair, anno, st)

            false ->
              st
          end
      end

    check_type_2({:type, nowarn(), :product, args}, seenVars, st1)
  end

  defp check_type_2({:user_type, a, typeName, args}, seenVars, st) do
    arity = length(args)
    typePair = {typeName, arity}
    st1 = used_type(typePair, a, st)

    :lists.foldl(
      fn t, {accSeenVars, accSt} ->
        check_type_1(t, accSeenVars, accSt)
      end,
      {seenVars, st1},
      args
    )
  end

  defp check_type_2([{:typed_record_field, field, _T} | _], seenVars, st) do
    {seenVars, add_error(:erlang.element(2, field), :old_abstract_code, st)}
  end

  defp check_type_2(i, seenVars, st) do
    case :erl_eval.partial_eval(i) do
      {:integer, _A, _Integer} ->
        {seenVars, st}

      _Other ->
        {seenVars, add_error(:erlang.element(2, i), {:type_syntax, :integer}, st)}
    end
  end

  defp check_record_types(anno, name, fields, seenVars, st) do
    case :maps.find(name, r_lint(st, :records)) do
      {:ok, {_A, defFields}} ->
        case :lists.all(
               fn
                 {:type, _, :field_type, _} ->
                   true

                 _ ->
                   false
               end,
               fields
             ) do
          true ->
            check_record_types(fields, name, defFields, seenVars, st, [])

          false ->
            {seenVars, add_error(anno, {:type_syntax, :record}, st)}
        end

      :error ->
        {seenVars, add_error(anno, {:undefined_record, name}, st)}
    end
  end

  defp check_record_types(
         [
           {:type, _, :field_type, [{:atom, anno, fName}, type]}
           | left
         ],
         name,
         defFields,
         seenVars,
         st,
         seenFields
       ) do
    st1 =
      case exist_field(fName, defFields) do
        true ->
          st

        false ->
          add_error(anno, {:undefined_field, name, fName}, st)
      end

    st2 =
      case :ordsets.is_element(fName, seenFields) do
        true ->
          add_error(anno, {:redefine_field, name, fName}, st1)

        false ->
          st1
      end

    {newSeenVars, st3} = check_type_2(type, seenVars, st2)
    newSeenFields = :ordsets.add_element(fName, seenFields)
    check_record_types(left, name, defFields, newSeenVars, st3, newSeenFields)
  end

  defp check_record_types([], _Name, _DefFields, seenVars, st, _SeenFields) do
    {seenVars, st}
  end

  defp used_type(typePair, anno, r_lint(usage: usage, file: file) = st) do
    used = r_usage(usage, :used_types)

    usedType =
      r_used_type(
        anno: :erl_anno.set_file(file, anno),
        at: r_lint(st, :type_id)
      )

    newUsed = maps_prepend(typePair, usedType, used)
    r_lint(st, usage: r_usage(usage, used_types: newUsed))
  end

  defp is_default_type({name, numberOfTypeVariables}) do
    :erl_internal.is_type(name, numberOfTypeVariables)
  end

  defp is_obsolete_builtin_type(typePair) do
    obsolete_builtin_type(typePair) !== :no
  end

  defp obsolete_builtin_type({1, 255}) do
    {:deprecated, {2, 255}, ~c""}
  end

  defp obsolete_builtin_type({name, a})
       when is_atom(name) and
              is_integer(a) do
    :no
  end

  defp spec_decl(anno, mFA0, typeSpecs, r_lint(specs: specs, module: mod) = st0) do
    mFA =
      case mFA0 do
        {f, arity} ->
          {mod, f, arity}

        {_M, _F, arity} ->
          mFA0
      end

    st1 = r_lint(st0, specs: :maps.put(mFA, anno, specs))

    case :erlang.is_map_key(mFA, specs) do
      true ->
        add_error(anno, {:redefine_spec, mFA0}, st1)

      false ->
        st2 =
          case mFA do
            {^mod, _, _} ->
              st1

            _ ->
              st1int =
                case mFA0 do
                  {m, _, _} ->
                    check_module_name(m, anno, st1)

                  _ ->
                    st1
                end

              add_error(anno, {:bad_module, mFA}, st1int)
          end

        st3 = r_lint(st2, type_id: {:spec, mFA})
        check_specs(typeSpecs, :spec_wrong_arity, arity, st3)
    end
  end

  defp callback_decl(anno, mFA0, typeSpecs, st0 = r_lint(callbacks: callbacks, module: mod)) do
    case mFA0 do
      {m, _F, _A} ->
        st1 = check_module_name(m, anno, st0)
        add_error(anno, {:bad_callback, mFA0}, st1)

      {f, arity} ->
        mFA = {mod, f, arity}
        st1 = r_lint(st0, callbacks: :maps.put(mFA, anno, callbacks))

        case :erlang.is_map_key(mFA, callbacks) do
          true ->
            add_error(anno, {:redefine_callback, mFA0}, st1)

          false ->
            st2 = r_lint(st1, type_id: {:spec, mFA})
            check_specs(typeSpecs, :callback_wrong_arity, arity, st2)
        end
    end
  end

  defp optional_callbacks(anno, term, st0) do
    try do
      true = is_fa_list(term)
      term
    catch
      _, _ ->
        st0
    else
      fAs ->
        optional_cbs(anno, fAs, st0)
    end
  end

  defp optional_cbs(_Anno, [], st) do
    st
  end

  defp optional_cbs(anno, [{f, a} | fAs], st0) do
    r_lint(optional_callbacks: optionalCbs, module: mod) = st0
    mFA = {mod, f, a}
    st1 = r_lint(st0, optional_callbacks: :maps.put(mFA, anno, optionalCbs))

    st2 =
      case :erlang.is_map_key(mFA, optionalCbs) do
        true ->
          add_error(anno, {:redefine_optional_callback, {f, a}}, st1)

        false ->
          st1
      end

    optional_cbs(anno, fAs, st2)
  end

  defp is_fa_list([e | l]) do
    is_fa(e) and is_fa_list(l)
  end

  defp is_fa_list([]) do
    true
  end

  defp is_fa_list(_) do
    false
  end

  defp is_fa({funcName, arity})
       when is_atom(funcName) and
              is_integer(arity) and arity >= 0 do
    true
  end

  defp is_fa(_) do
    false
  end

  defp check_module_name(m, anno, st0) do
    allChars = :erlang.atom_to_list(m)
    visibleChars = remove_non_visible(allChars)

    case {allChars, visibleChars} do
      {[], []} ->
        add_error(anno, :empty_module_name, st0)

      {[_ | _], []} ->
        add_error(anno, :blank_module_name, st0)

      {cs, [_ | _]} ->
        st1 =
          case :io_lib.latin1_char_list(cs) do
            true ->
              st0

            false ->
              add_error(anno, :non_latin1_module_unsupported, st0)
          end

        case any_control_characters(cs) do
          true ->
            add_error(anno, :ctrl_chars_in_module_name, st1)

          false ->
            st1
        end
    end
  end

  defp remove_non_visible(cs) do
    sP = ?\s
    nBSP = 160
    sHY = 173

    for c <- cs, c !== sP, c !== nBSP, c !== sHY do
      c
    end
  end

  defp any_control_characters(cs) do
    any(
      fn
        c
        when (is_integer(c) and 0 <= c and c < 32) or
               (is_integer(c) and 127 <= c and c < 160) ->
          true

        _ ->
          false
      end,
      cs
    )
  end

  defp check_specs([funType | left], eTag, arity, st0) do
    {funType1, cTypes} =
      case funType do
        {:type, _, :bounded_fun, [fT = {:type, _, :fun, _}, cs]} ->
          types0 =
            for {:type, _, :constraint, [_, t]} <- cs do
              t
            end

          {fT, :lists.append(types0)}

        {:type, _, :fun, _} = fT ->
          {fT, []}
      end

    {:type, a, :fun, [{:type, _, :product, d}, _]} = funType1
    specArity = length(d)

    st1 =
      case arity === specArity do
        true ->
          st0

        false ->
          add_error(a, eTag, st0)
      end

    st2 =
      check_type(
        {:type, nowarn(), :product, [funType1 | cTypes]},
        st1
      )

    check_specs(left, eTag, arity, st2)
  end

  defp check_specs([], _ETag, _Arity, st) do
    st
  end

  defp nowarn() do
    a0 = :erl_anno.new(0)
    a1 = :erl_anno.set_generated(true, a0)
    :erl_anno.set_file(~c"", a1)
  end

  defp check_specs_without_function(r_lint(module: mod, defined: funcs, specs: specs) = st) do
    fun = fn
      {m, f, a}, anno, accSt when m === mod ->
        fA = {f, a}

        case :gb_sets.is_element(fA, funcs) do
          true ->
            accSt

          false ->
            add_error(anno, {:spec_fun_undefined, fA}, accSt)
        end

      {_M, _F, _A}, _Anno, accSt ->
        accSt
    end

    :maps.fold(fun, st, specs)
  end

  defp check_functions_without_spec(forms, st0) do
    case is_warn_enabled(:missing_spec_all, st0) do
      true ->
        add_missing_spec_warnings(forms, st0, :all)

      false ->
        case is_warn_enabled(:missing_spec, st0) do
          true ->
            add_missing_spec_warnings(forms, st0, :exported)

          false ->
            st0
        end
    end
  end

  defp add_missing_spec_warnings(forms, st0, type) do
    specs =
      for {_M, f, a} <- :maps.keys(r_lint(st0, :specs)) do
        {f, a}
      end

    warns =
      case type do
        :all ->
          for {:function, anno, f, a, _} <- forms,
              not :lists.member(fA = {f, a}, specs) do
            {fA, anno}
          end

        :exported ->
          exps0 = :gb_sets.to_list(exports(st0)) -- pseudolocals()
          exps = exps0 -- specs

          for {:function, anno, f, a, _} <- forms,
              member(fA = {f, a}, exps) do
            {fA, anno}
          end
      end

    foldl(
      fn {fA, anno}, st ->
        add_warning(anno, {:missing_spec, fA}, st)
      end,
      st0,
      warns
    )
  end

  defp check_unused_types(forms, st) do
    case is_warn_enabled(:unused_type, st) do
      true ->
        check_unused_types_1(forms, st)

      false ->
        st
    end
  end

  defp check_unused_types_1(forms, r_lint(types: ts) = st) do
    case (for {:attribute, _A, :file, {file, _Anno}} <- forms do
            file
          end) do
      [firstFile | _] ->
        l = reached_types(st)
        usedTypes = :gb_sets.from_list(l)

        foldFun = fn
          {{:record, _} = _Type, 0}, _, accSt ->
            accSt

          type, r_typeinfo(anno: anno), accSt ->
            case loc(anno, accSt) do
              {^firstFile, _} ->
                case :gb_sets.is_member(type, usedTypes) do
                  true ->
                    accSt

                  false ->
                    warn = {:unused_type, type}
                    add_warning(anno, warn, accSt)
                end

              _ ->
                accSt
            end
        end

        :maps.fold(foldFun, st, ts)

      [] ->
        st
    end
  end

  defp initially_reached_types(es) do
    for {{t, _} = fromTypeId, _} <- es, t !== :type do
      fromTypeId
    end
  end

  defp check_local_opaque_types(st) do
    r_lint(types: ts, exp_types: expTs) = st

    foldFun = fn
      _Type, r_typeinfo(attr: :type), accSt ->
        accSt

      type, r_typeinfo(attr: :opaque, anno: anno), accSt ->
        case :gb_sets.is_element(type, expTs) do
          true ->
            accSt

          false ->
            warn = {:not_exported_opaque, type}
            add_warning(anno, warn, accSt)
        end
    end

    :maps.fold(foldFun, st, ts)
  end

  defp check_dialyzer_attribute(forms, st0) do
    vals =
      for {:attribute, anno, :dialyzer, val} <- forms,
          v0 <- :lists.flatten([val]),
          v <-
            (case v0 do
               {o, f} ->
                 for a <- :lists.flatten([o]),
                     b <- :lists.flatten([f]) do
                   {a, b}
                 end

               t ->
                 [t]
             end) do
        {anno, v}
      end

    {wellformed, bad} =
      :lists.partition(
        fn
          {_, {option, fA}}
          when is_atom(option) ->
            is_fa(fA)

          {_, option} when is_atom(option) ->
            true

          _ ->
            false
        end,
        vals
      )

    st1 =
      foldl(
        fn {anno, term}, st ->
          add_error(anno, {:bad_dialyzer_attribute, term}, st)
        end,
        st0,
        bad
      )

    defFunctions = :gb_sets.to_list(r_lint(st0, :defined)) -- pseudolocals()

    fun = fn
      {anno, {option, fA}}, st ->
        case is_function_dialyzer_option(option) do
          true ->
            case :lists.member(fA, defFunctions) do
              true ->
                st

              false ->
                add_error(anno, {:undefined_function, fA}, st)
            end

          false ->
            add_error(anno, {:bad_dialyzer_option, option}, st)
        end

      {anno, option}, st ->
        case is_module_dialyzer_option(option) do
          true ->
            st

          false ->
            add_error(anno, {:bad_dialyzer_option, option}, st)
        end
    end

    foldl(fun, st1, wellformed)
  end

  defp is_function_dialyzer_option(:nowarn_function) do
    true
  end

  defp is_function_dialyzer_option(option) do
    is_module_dialyzer_option(option)
  end

  defp is_module_dialyzer_option(option) do
    :lists.member(
      option,
      [
        :no_return,
        :no_unused,
        :no_improper_lists,
        :no_fun_app,
        :no_match,
        :no_opaque,
        :no_fail_call,
        :no_contracts,
        :no_unknown,
        :no_behaviours,
        :no_undefined_callbacks,
        :unmatched_returns,
        :error_handling,
        :race_conditions,
        :no_missing_calls,
        :specdiffs,
        :overspecs,
        :underspecs,
        :unknown,
        :no_underspecs,
        :extra_return,
        :no_extra_return,
        :missing_return,
        :no_missing_return,
        :overlapping_contract
      ]
    )
  end

  defp try_clauses(scs, ccs, in__, vt, uvt, st0) do
    {csvt0, st1} = icrt_clauses(scs, vt, st0)
    {csvt1, st2} = catch_clauses(ccs, vtupdate(uvt, vt), st1)
    csvt = csvt0 ++ csvt1
    updVt = icrt_export(csvt, vt, in__, st2)
    {updVt, st2}
  end

  defp icrt_clauses(cs, in__, vt, st0) do
    {csvt, st1} = icrt_clauses(cs, vt, st0)
    updVt = icrt_export(csvt, vt, in__, st1)
    {updVt, st1}
  end

  defp icrt_clauses(cs, vt, st) do
    mapfoldl(
      fn c, st0 ->
        icrt_clause(c, vt, st0)
      end,
      st,
      cs
    )
  end

  defp icrt_clause({:clause, _Anno, h, g, b}, vt0, st0) do
    {hvt, hnew, st1} = head(h, vt0, st0)
    vt1 = vtupdate(hvt, hnew)
    {gvt, st2} = guard(g, vtupdate(vt1, vt0), st1)
    vt2 = vtupdate(gvt, vt1)
    {bvt, st3} = exprs(b, vtupdate(vt2, vt0), st2)
    {vtupdate(bvt, vt2), st3}
  end

  defp catch_clauses(cs, vt, st) do
    mapfoldl(
      fn c, st0 ->
        catch_clause(c, vt, st0)
      end,
      st,
      cs
    )
  end

  defp catch_clause({:clause, _Anno, h, g, b}, vt0, st0) do
    [{:tuple, _, [_, _, stack]}] = h
    {hvt, hnew, st1} = head(h, vt0, st0)
    vt1 = vtupdate(hvt, hnew)
    {guardVt, st2} = taint_stack_var(stack, vtupdate(vt1, vt0), st1)
    {gvt, st3} = guard(g, guardVt, st2)
    vt2 = vtupdate(gvt, vt1)
    {bvt, st4} = exprs(b, vtupdate(vt2, vt0), st3)
    {vtupdate(bvt, vt2), st4}
  end

  defp taint_stack_var({:var, anno, v}, vt, st) when v !== :_ do
    st1 =
      case :orddict.find(v, vt) do
        {:ok, {_, :used, _}} ->
          add_error(anno, {:stacktrace_bound, v}, st)

        _ ->
          st
      end

    {vtupdate([{v, {:stacktrace, :unused, [anno]}}], vt), st1}
  end

  defp taint_stack_var(_, vt, st) do
    {vt, st}
  end

  defp icrt_export(vts, vt, {tag, attrs}, st) do
    {_File, loc} = loc(attrs, st)
    icrt_export(:lists.merge(vts), vt, {tag, loc}, length(vts), [])
  end

  defp icrt_export(
         [{v, {{:export, _}, _, _}} | vs0],
         [{v, {{:export, _} = s0, _, as}} | vt],
         in__,
         i,
         acc
       ) do
    {vVs, vs} =
      :lists.partition(
        fn {k, _} ->
          k === v
        end,
        vs0
      )

    s =
      foldl(
        fn {_, {s1, _, _}}, accS ->
          merge_state(accS, s1)
        end,
        s0,
        vVs
      )

    icrt_export(vs, vt, in__, i, [{v, {s, :used, as}} | acc])
  end

  defp icrt_export([{v, _} | vs0], [{v, {_, _, as}} | vt], in__, i, acc) do
    vs =
      :lists.dropwhile(
        fn {k, _} ->
          k === v
        end,
        vs0
      )

    icrt_export(vs, vt, in__, i, [{v, {:bound, :used, as}} | acc])
  end

  defp icrt_export([{v1, _} | _] = vs, [{v2, _} | vt], in__, i, acc)
       when v1 > v2 do
    icrt_export(vs, vt, in__, i, acc)
  end

  defp icrt_export([{v, _} | _] = vs0, vt, in__, i, acc) do
    {vVs, vs} =
      :lists.partition(
        fn {k, _} ->
          k === v
        end,
        vs0
      )

    f = fn {_, {s, u, as}}, {accI, accS0, accAs0} ->
      accS =
        case {s, accS0} do
          {{:unsafe, _}, {:unsafe, _}} ->
            {:unsafe, in__}

          {{:unsafe, _}, _} ->
            s

          _ ->
            accS0
        end

      accAs =
        case u do
          :used ->
            accAs0

          :unused ->
            merge_annos(accAs0, as)
        end

      {accI + 1, accS, accAs}
    end

    {count, s1, as} = foldl(f, {0, {:export, in__}, []}, vVs)

    s =
      case count do
        ^i ->
          s1

        _ ->
          {:unsafe, in__}
      end

    u =
      case as do
        [] ->
          :used

        _ ->
          :unused
      end

    icrt_export(vs, vt, in__, i, [{v, {s, u, as}} | acc])
  end

  defp icrt_export([], _, _, _, acc) do
    reverse(acc)
  end

  defp handle_comprehension(e, qs, vt0, st0) do
    {vt1, uvt, st1} = lc_quals(qs, vt0, st0)
    {evt, st2} = comprehension_expr(e, vt1, st1)
    vt2 = vtupdate(evt, vt1)
    {_, st3} = check_old_unused_vars(vt2, uvt, st2)
    {_, st4} = check_unused_vars(uvt, vt0, st3)
    {_, st} = check_unused_vars(vt2, vt0, st4)
    vt3 = vtmerge(vtsubtract(vt2, uvt), uvt)
    vt4 = vtold(vt3, vt0)
    vt = vt_no_unsafe(vt_no_unused(vt4))
    {vt, st}
  end

  defp comprehension_expr({:map_field_assoc, _, k, v}, vt0, st0) do
    expr_list([k, v], vt0, st0)
  end

  defp comprehension_expr(e, vt, st) do
    expr(e, vt, st)
  end

  defp lc_quals(qs, vt0, st0) do
    oldRecDef = r_lint(st0, :recdef_top)
    {vt, uvt, st} = lc_quals(qs, vt0, [], r_lint(st0, recdef_top: false))
    {vt, uvt, r_lint(st, recdef_top: oldRecDef)}
  end

  defp lc_quals([{:generate, _Anno, p, e} | qs], vt0, uvt0, st0) do
    {vt, uvt, st} = handle_generator(p, e, vt0, uvt0, st0)
    lc_quals(qs, vt, uvt, st)
  end

  defp lc_quals([{:b_generate, _Anno, p, e} | qs], vt0, uvt0, st0) do
    st1 = handle_bitstring_gen_pat(p, st0)
    {vt, uvt, st} = handle_generator(p, e, vt0, uvt0, st1)
    lc_quals(qs, vt, uvt, st)
  end

  defp lc_quals([{:m_generate, _Anno, p, e} | qs], vt0, uvt0, st0) do
    {vt, uvt, st} = handle_generator(p, e, vt0, uvt0, st0)
    lc_quals(qs, vt, uvt, st)
  end

  defp lc_quals([f | qs], vt, uvt, st0) do
    info = is_guard_test2_info(st0)

    {fvt, st1} =
      case is_guard_test2(f, info) do
        true ->
          guard_test(f, vt, st0)

        false ->
          expr(f, vt, st0)
      end

    lc_quals(qs, vtupdate(fvt, vt), uvt, st1)
  end

  defp lc_quals([], vt, uvt, st) do
    {vt, uvt, st}
  end

  defp is_guard_test2_info(r_lint(records: rDs, locals: locals, imports: imports)) do
    {rDs,
     fn fA ->
       is_local_function(
         locals,
         fA
       ) or is_imported_function(imports, fA)
     end}
  end

  defp handle_generator(p, e, vt, uvt, st0) do
    {evt, st1} = expr(e, vt, st0)
    vt1 = vtupdate(vtold(evt, vt), vt)
    {_, st2} = check_unused_vars(evt, vt, st1)
    {pvt, pnew, st3} = comprehension_pattern(p, vt1, st2)
    vt2 = vtupdate(pvt, vt1)
    st4 = shadow_vars(pnew, vt1, :generate, st3)
    svt = vtold(vt2, pnew)
    {_, st5} = check_old_unused_vars(svt, uvt, st4)
    nUvt = vtupdate(vtnew(svt, uvt), uvt)
    vt3 = vtupdate(vtsubtract(vt2, pnew), pnew)
    {vt3, nUvt, st5}
  end

  defp comprehension_pattern({:map_field_exact, _, k, v}, vt, st) do
    pattern_list([k, v], vt, [], st)
  end

  defp comprehension_pattern(p, vt, st) do
    pattern(p, vt, [], st)
  end

  defp handle_bitstring_gen_pat({:bin, _, segments = [_ | _]}, st) do
    case :lists.last(segments) do
      {:bin_element, anno, _, :default, flags}
      when is_list(flags) ->
        case member(:binary, flags) or
               member(
                 :bytes,
                 flags
               ) or
               member(
                 :bits,
                 flags
               ) or
               member(
                 :bitstring,
                 flags
               ) do
          true ->
            add_error(anno, :unsized_binary_in_bin_gen_pattern, st)

          false ->
            st
        end

      _ ->
        st
    end
  end

  defp handle_bitstring_gen_pat(_, st) do
    st
  end

  defp fun_clauses(cs, vt, r_lint(fun_used_vars: %{} = fUV) = st) do
    {uvt, st0} = fun_clauses1(cs, vt, r_lint(st, fun_used_vars: :maps.new()))
    r_lint(fun_used_vars: innerFUV) = st0

    usedVars =
      for {v, {_, :used, _}} <- uvt do
        v
      end

    outerFUV = :maps.put(cs, {usedVars, innerFUV}, fUV)
    {uvt, r_lint(st0, fun_used_vars: outerFUV)}
  end

  defp fun_clauses(cs, vt, st) do
    fun_clauses1(cs, vt, st)
  end

  defp fun_clauses1(cs, vt, st) do
    oldRecDef = r_lint(st, :recdef_top)

    {bvt, st2} =
      foldl(
        fn c, {bvt0, st0} ->
          {cvt, st1} = fun_clause(c, vt, st0)
          {vtmerge(cvt, bvt0), st1}
        end,
        {[], r_lint(st, recdef_top: false)},
        cs
      )

    uvt = vt_no_unsafe(vt_no_unused(vtold(bvt, vt)))
    {uvt, r_lint(st2, recdef_top: oldRecDef)}
  end

  defp fun_clause({:clause, _Anno, h, g, b}, vt0, st0) do
    {hvt, hnew, st1} = head(h, vt0, [], st0)
    vt1 = vtupdate(hvt, vt0)
    st2 = shadow_vars(hnew, vt0, :fun, st1)
    vt2 = vtupdate(vtsubtract(vt1, hnew), hnew)
    {gvt, st3} = guard(g, vt2, st2)
    vt3 = vtupdate(gvt, vt2)
    {bvt, st4} = exprs(b, vt3, st3)
    cvt = vtupdate(bvt, vt3)
    {_, st5} = check_unused_vars(cvt, vt0, st4)
    svt = vtold(vt1, hnew)
    {_, st6} = check_old_unused_vars(cvt, svt, st5)
    vt4 = vtmerge(svt, vtsubtract(cvt, svt))
    {vtold(vt4, vt0), st6}
  end

  defp pat_var(v, anno, vt, new, st0) do
    case :orddict.find(v, new) do
      {:ok, {:bound, _Usage, as}} ->
        st = warn_underscore_match(v, anno, st0)
        {[], [{v, {:bound, :used, as}}], st}

      :error ->
        case :orddict.find(v, vt) do
          {:ok, {:bound, _Usage, ls}} ->
            st = warn_underscore_match(v, anno, st0)
            {[{v, {:bound, :used, ls}}], [], st}

          {:ok, {{:unsafe, in__}, _Usage, ls}} ->
            {[{v, {:bound, :used, ls}}], [], add_error(anno, {:unsafe_var, v, in__}, st0)}

          {:ok, {{:export, from}, _Usage, ls}} ->
            st = warn_underscore_match(v, anno, st0)
            {[{v, {:bound, :used, ls}}], [], add_warning(anno, {:exported_var, v, from}, st)}

          :error when r_lint(st0, :recdef_top) ->
            {[], [{v, {:bound, :unused, [anno]}}],
             add_error(anno, {:variable_in_record_def, v}, st0)}

          :error ->
            {[], [{v, {:bound, :unused, [anno]}}], st0}
        end
    end
  end

  defp warn_underscore_match(v, anno, st) do
    case {is_warn_enabled(:underscore_match, st), :erlang.atom_to_list(v)} do
      {true, [?_ | _]} ->
        add_warning(anno, {:match_underscore_var, v}, st)

      {_, _} ->
        st
    end
  end

  defp warn_underscore_match_pat(v, annos, st) do
    case {is_warn_enabled(:underscore_match, st), :erlang.atom_to_list(v)} do
      {true, [?_ | _]} ->
        warn_underscore_match_pat_1(annos, v, st)

      {_, _} ->
        st
    end
  end

  defp warn_underscore_match_pat_1([anno | annos], v, st0) do
    st = add_warning(anno, {:match_underscore_var_pat, v}, st0)
    warn_underscore_match_pat_1(annos, v, st)
  end

  defp warn_underscore_match_pat_1([], _V, st) do
    st
  end

  defp pat_binsize_var(v, anno, vt, new, st) do
    case :orddict.find(v, new) do
      {:ok, {:bound, _Used, as}} ->
        {[], [{v, {:bound, :used, as}}], st}

      :error ->
        case :orddict.find(v, vt) do
          {:ok, {:bound, _Used, as}} ->
            {[{v, {:bound, :used, as}}], [], st}

          {:ok, {{:unsafe, in__}, _Used, as}} ->
            {[{v, {:bound, :used, as}}], [], add_error(anno, {:unsafe_var, v, in__}, st)}

          {:ok, {{:export, from}, _Used, as}} ->
            {[{v, {:bound, :used, as}}], [], exported_var(anno, v, from, st)}

          :error ->
            {[{v, {:bound, :used, [anno]}}], [], add_error(anno, {:unbound_var, v}, st)}
        end
    end
  end

  defp expr_var(v, anno, vt, r_lint(bvt: :none) = st) do
    do_expr_var(v, anno, vt, st)
  end

  defp expr_var(v, anno, vt0, r_lint(bvt: bvt0) = st0)
       when is_list(bvt0) do
    {vt, bvt, st} = pat_binsize_var(v, anno, vt0, bvt0, st0)
    {vt, r_lint(st, bvt: vtmerge(bvt0, bvt))}
  end

  defp do_expr_var(v, anno, vt, st) do
    case :orddict.find(v, vt) do
      {:ok, {:bound, _Usage, as}} ->
        {[{v, {:bound, :used, as}}], st}

      {:ok, {{:unsafe, in__}, _Usage, as}} ->
        {[{v, {:bound, :used, as}}], add_error(anno, {:unsafe_var, v, in__}, st)}

      {:ok, {{:export, from}, _Usage, as}} ->
        case is_warn_enabled(:export_vars, st) do
          true ->
            {[{v, {:bound, :used, as}}], add_warning(anno, {:exported_var, v, from}, st)}

          false ->
            {[{v, {{:export, from}, :used, as}}], st}
        end

      {:ok, {:stacktrace, _Usage, as}} ->
        {[{v, {:bound, :used, as}}], add_error(anno, {:stacktrace_guard, v}, st)}

      :error ->
        {[{v, {:bound, :used, [anno]}}], add_error(anno, {:unbound_var, v}, st)}
    end
  end

  defp exported_var(anno, v, from, st) do
    case is_warn_enabled(:export_vars, st) do
      true ->
        add_warning(anno, {:exported_var, v, from}, st)

      false ->
        st
    end
  end

  defp shadow_vars(vt, vt0, in__, st0) do
    case is_warn_enabled(:shadow_vars, st0) do
      true ->
        foldl(
          fn
            {v, {_, _, [a | _]}}, st ->
              add_warning(a, {:shadowed_var, v, in__}, st)

            _, st ->
              st
          end,
          st0,
          vtold(vt, vt_no_unsafe(vt0))
        )

      false ->
        st0
    end
  end

  defp check_unused_vars(vt, vt0, st0) do
    u = unused_vars(vt, vt0, st0)
    warn_unused_vars(u, vt, st0)
  end

  defp check_old_unused_vars(vt, vt0, st0) do
    u = unused_vars(vtold(vt, vt0), [], st0)
    warn_unused_vars(u, vt, st0)
  end

  defp unused_vars(vt, vt0, _St0) do
    u0 =
      :orddict.filter(
        fn
          v, {_State, :unused, _As} ->
            case :erlang.atom_to_list(v) do
              ~c"_" ++ _ ->
                false

              _ ->
                true
            end

          _V, _How ->
            false
        end,
        vt
      )

    vtnew(u0, vt0)
  end

  defp warn_unused_vars([], vt, st0) do
    {vt, st0}
  end

  defp warn_unused_vars(u, vt, st0) do
    st1 =
      case is_warn_enabled(:unused_vars, st0) do
        false ->
          st0

        true ->
          foldl(
            fn {v, {_, :unused, as}}, st ->
              foldl(
                fn a, st2 ->
                  add_warning(a, {:unused_var, v}, st2)
                end,
                st,
                as
              )
            end,
            st0,
            u
          )
      end

    uVt =
      map(
        fn {v, {state, _, as}} ->
          {v, {state, :used, as}}
        end,
        u
      )

    {vtmerge(vt, uVt), st1}
  end

  defp vtupdate(uvt, vt0) do
    :orddict.merge(
      fn _V, {s, u1, a1}, {_S, u2, a2} ->
        {s, merge_used(u1, u2), merge_annos(a1, a2)}
      end,
      uvt,
      vt0
    )
  end

  defp vtunsafe({tag, anno}, uvt, vt) do
    location = :erl_anno.location(anno)

    for {v, {_, u, as}} <- vtnew(uvt, vt) do
      {v, {{:unsafe, {tag, location}}, u, as}}
    end
  end

  defp vtmerge(vt1, vt2) do
    :orddict.merge(
      fn _V, {s1, u1, a1}, {s2, u2, a2} ->
        {merge_state(s1, s2), merge_used(u1, u2), merge_annos(a1, a2)}
      end,
      vt1,
      vt2
    )
  end

  defp vtmerge(vts) do
    foldl(
      fn vt, mvts ->
        vtmerge(vt, mvts)
      end,
      [],
      vts
    )
  end

  defp vtmerge_pat(vtA, vtB, st0) do
    vt0 =
      :orddict.merge(
        fn _V, {s1, usage1, annos1}, {s2, usage2, annos2} ->
          annos = merge_annos(annos1, annos2)

          usage =
            case {usage1, usage2} do
              {:unused, :unused} ->
                {:matched, annos}

              {:unused, _} ->
                {:matched, annos1}

              {_, :unused} ->
                {:matched, annos2}

              {_, _} ->
                :used
            end

          {merge_state(s1, s2), usage, annos}
        end,
        vtA,
        vtB
      )

    :lists.mapfoldl(
      fn
        {name, {state, {:matched, matchAs}, as}}, st1 ->
          st = warn_underscore_match_pat(name, matchAs, st1)
          {{name, {state, :used, as}}, st}

        var, st ->
          {var, st}
      end,
      st0,
      vt0
    )
  end

  defp merge_annos(as1, as2) do
    :ordsets.union(as1, as2)
  end

  defp merge_state({:unsafe, _F1} = s1, _S2) do
    s1
  end

  defp merge_state(_S1, {:unsafe, _F2} = s2) do
    s2
  end

  defp merge_state(:bound, s2) do
    s2
  end

  defp merge_state(s1, :bound) do
    s1
  end

  defp merge_state({:export, f1}, {:export, _F2}) do
    {:export, f1}
  end

  defp merge_used(:used, _Usage2) do
    :used
  end

  defp merge_used(_Usage1, :used) do
    :used
  end

  defp merge_used(:unused, :unused) do
    :unused
  end

  defp vtnew(new, old) do
    :orddict.filter(
      fn v, _How ->
        not :orddict.is_key(v, old)
      end,
      new
    )
  end

  defp vtsubtract(new, old) do
    vtnew(new, old)
  end

  defp vtold(new, old) do
    :orddict.filter(
      fn v, _How ->
        :orddict.is_key(v, old)
      end,
      new
    )
  end

  defp vt_no_unsafe(vt) do
    for {_, {s, _U, _A}} = v <- vt,
        (case s do
           {:unsafe, _} ->
             false

           _ ->
             true
         end) do
      v
    end
  end

  defp vt_no_unused(vt) do
    for {_, {_, u, _A}} = v <- vt, u !== :unused do
      v
    end
  end

  defp copy_expr(expr, anno) do
    :erl_parse.map_anno(
      fn _A ->
        anno
      end,
      expr
    )
  end

  defp check_record_info_call(_Anno, aa, [{:atom, ai, info}, {:atom, _An, name}], st) do
    case member(info, [:fields, :size]) do
      true ->
        exist_record(aa, name, st)

      false ->
        add_error(ai, :illegal_record_info, st)
    end
  end

  defp check_record_info_call(anno, _Aa, _As, st) do
    add_error(anno, :illegal_record_info, st)
  end

  defp has_wildcard_field([
         {:record_field, _Af, {:var, aa, :_}, _Val}
         | _Fs
       ]) do
    aa
  end

  defp has_wildcard_field([_ | fs]) do
    has_wildcard_field(fs)
  end

  defp has_wildcard_field([]) do
    :no
  end

  defp check_remote_function(anno, m, f, as, st0) do
    st1 = deprecated_function(anno, m, f, as, st0)
    st2 = check_qlc_hrl(anno, m, f, as, st1)
    st3 = check_load_nif(anno, m, f, as, st2)
    format_function(anno, m, f, as, st3)
  end

  defp check_load_nif(anno, :erlang, :load_nif, [_, _], st0) do
    st = r_lint(st0, load_nif: true)

    case is_warn_enabled(:nif_inline, st) do
      true ->
        check_nif_inline(anno, st)

      false ->
        st
    end
  end

  defp check_load_nif(_Anno, _ModName, _FuncName, _Args, st) do
    st
  end

  defp check_nif_inline(anno, st) do
    case any(&is_inline_opt/1, r_lint(st, :compile)) do
      true ->
        add_warning(anno, :nif_inline, st)

      false ->
        st
    end
  end

  defp is_inline_opt({:inline, [_ | _] = _FAs}) do
    true
  end

  defp is_inline_opt(:inline) do
    true
  end

  defp is_inline_opt(_) do
    false
  end

  defp check_qlc_hrl(anno, m, f, as, st) do
    arity = length(as)

    case as do
      [{:lc, _A, _E, _Qs} | _]
      when m === :qlc and
             f === :q and arity < 3 and
             not r_lint(st, :xqlc) ->
        add_warning(anno, {:missing_qlc_hrl, arity}, st)

      _ ->
        st
    end
  end

  defp deprecated_function(anno, m, f, as, st) do
    arity = length(as)
    mFA = {m, f, arity}

    case :otp_internal.obsolete(m, f, arity) do
      {:deprecated, string} when is_list(string) ->
        case not is_warn_enabled(
               :deprecated_function,
               st
             ) or
               :ordsets.is_element(
                 mFA,
                 r_lint(st, :not_deprecated)
               ) do
          true ->
            st

          false ->
            add_warning(anno, {:deprecated, mFA, string}, st)
        end

      {:deprecated, replacement, rel} ->
        case not is_warn_enabled(
               :deprecated_function,
               st
             ) or
               :ordsets.is_element(
                 mFA,
                 r_lint(st, :not_deprecated)
               ) do
          true ->
            st

          false ->
            add_warning(anno, {:deprecated, mFA, replacement, rel}, st)
        end

      {:removed, string} when is_list(string) ->
        add_removed_warning(anno, mFA, {:removed, mFA, string}, st)

      {:removed, replacement, rel} ->
        add_removed_warning(anno, mFA, {:removed, mFA, replacement, rel}, st)

      :no ->
        st
    end
  end

  defp add_removed_warning(anno, {m, _, _} = mFA, warning, r_lint(not_removed: notRemoved) = st) do
    case is_warn_enabled(:removed, st) and
           not :gb_sets.is_element(
             m,
             notRemoved
           ) and
           not :gb_sets.is_element(
             mFA,
             notRemoved
           ) do
      true ->
        add_warning(anno, warning, st)

      false ->
        st
    end
  end

  defp deprecated_type(anno, m, n, as, st) do
    nAs = length(as)

    case :otp_internal.obsolete_type(m, n, nAs) do
      {:deprecated, string} when is_list(string) ->
        case is_warn_enabled(:deprecated_type, st) do
          true ->
            add_warning(anno, {:deprecated_type, {m, n, nAs}, string}, st)

          false ->
            st
        end

      {:removed, string} ->
        add_warning(anno, {:removed_type, {m, n, nAs}, string}, st)

      :no ->
        st
    end
  end

  defp obsolete_guard({:call, anno, {:atom, ar, f}, as}, st0) do
    arity = length(as)

    case :erl_internal.old_type_test(f, arity) do
      false ->
        deprecated_function(anno, :erlang, f, as, st0)

      true ->
        st =
          case is_warn_enabled(:obsolete_guard, st0) do
            true ->
              add_warning(ar, {:obsolete_guard, {f, arity}}, st0)

            false ->
              st0
          end

        test_overriden_by_local(ar, f, arity, st)
    end
  end

  defp obsolete_guard(_G, st) do
    st
  end

  defp test_overriden_by_local(anno, oldTest, arity, st) do
    modernTest = :erlang.list_to_atom(~c"is_" ++ :erlang.atom_to_list(oldTest))

    case is_local_function(
           r_lint(st, :locals),
           {modernTest, arity}
         ) do
      true ->
        add_error(anno, {:obsolete_guard_overridden, oldTest}, st)

      false ->
        st
    end
  end

  defp feature_keywords() do
    features = :erl_features.configurable()

    g = fn ftr, map ->
      keywords = :erl_features.keywords(ftr)

      add = fn keyword, m ->
        :maps.put(keyword, ftr, m)
      end

      :lists.foldl(add, map, keywords)
    end

    :lists.foldl(g, %{}, features)
  end

  defp keyword_warning(anno, atom, st) do
    case is_warn_enabled(:keyword_warning, st) do
      true ->
        case :erl_anno.text(anno) do
          [?' | _] ->
            st

          _ ->
            keywords = r_lint(st, :feature_keywords)

            case :maps.find(atom, keywords) do
              :error ->
                st

              {:ok, ftr} ->
                add_warning(anno, {:future_feature, ftr, atom}, st)
            end
        end

      false ->
        st
    end
  end

  defp is_format_function(:io, :fwrite) do
    true
  end

  defp is_format_function(:io, :format) do
    true
  end

  defp is_format_function(:io_lib, :fwrite) do
    true
  end

  defp is_format_function(:io_lib, :format) do
    true
  end

  defp is_format_function(m, f) when is_atom(m) and is_atom(f) do
    false
  end

  defp check_format_1([fmt]) do
    check_format_1([fmt, :no_argument_list])
  end

  defp check_format_1([fmt, as]) do
    check_format_2(fmt, canonicalize_string(as))
  end

  defp check_format_1([_Dev, fmt, as]) do
    check_format_1([fmt, as])
  end

  defp check_format_1(_As) do
    {:warn, 1, ~c"format call with wrong number of arguments", []}
  end

  defp canonicalize_string({:string, anno, cs}) do
    foldr(
      fn c, t ->
        {:cons, anno, {:integer, anno, c}, t}
      end,
      {nil, anno},
      cs
    )
  end

  defp canonicalize_string(term) do
    term
  end

  defp check_format_2(fmt, as) do
    case fmt do
      {:string, a, s} ->
        check_format_2a(s, a, as)

      {:atom, a, atom} ->
        check_format_2a(:erlang.atom_to_list(atom), a, as)

      _ ->
        anno = :erl_parse.first_anno(fmt)
        {:warn, 2, anno, ~c"format string not a textual constant", []}
    end
  end

  defp check_format_2a(fmt, fmtAnno, :no_argument_list = as) do
    check_format_3(fmt, fmtAnno, as)
  end

  defp check_format_2a(fmt, fmtAnno, as) do
    case args_list(as) do
      true ->
        check_format_3(fmt, fmtAnno, as)

      false ->
        anno = :erlang.element(2, as)
        {:warn, 1, anno, ~c"format arguments not a list", []}

      :maybe ->
        anno = :erl_parse.first_anno(as)
        {:warn, 2, anno, ~c"format arguments perhaps not a list", []}
    end
  end

  defp check_format_3(fmt, fmtAnno, as) do
    case check_format_string(fmt) do
      {:ok, need} ->
        check_format_4(need, fmtAnno, as)

      {:error, s} ->
        {:warn, 1, fmtAnno, ~c"format string invalid (~ts)", [s]}
    end
  end

  defp check_format_4([], _FmtAnno, :no_argument_list) do
    :ok
  end

  defp check_format_4(need, fmtAnno, :no_argument_list) do
    msg = ~c"the format string requires an argument list with ~s, but no argument list is given"
    {:warn, 1, fmtAnno, msg, [arguments(length(need))]}
  end

  defp check_format_4(need, _FmtAnno, as) do
    anno = :erlang.element(2, as)
    prefix = ~c"the format string requires an argument list with ~s, but the argument list "

    case {args_length(as), length(need)} do
      {same, same} ->
        :ok

      {actual, 0} ->
        msg =
          ~c"the format string requires an empty argument list, but the argument list contains ~s"

        {:warn, 1, anno, msg, [arguments(actual)]}

      {0, needed} ->
        msg = prefix ++ ~c"is empty"
        {:warn, 1, anno, msg, [arguments(needed)]}

      {actual, needed} when actual < needed ->
        msg = prefix ++ ~c"contains only ~s"
        {:warn, 1, anno, msg, [arguments(needed), arguments(actual)]}

      {actual, needed} when actual > needed ->
        msg = prefix ++ ~c"contains ~s"
        {:warn, 1, anno, msg, [arguments(needed), arguments(actual)]}
    end
  end

  defp arguments(1) do
    ~c"1 argument"
  end

  defp arguments(n) do
    [:erlang.integer_to_list(n), ~c" arguments"]
  end

  defp args_list({:cons, _A, _H, t}) do
    args_list(t)
  end

  defp args_list({:string, _A, _Cs}) do
    :maybe
  end

  defp args_list({nil, _A}) do
    true
  end

  defp args_list({:atom, _, _}) do
    false
  end

  defp args_list({:integer, _, _}) do
    false
  end

  defp args_list({:float, _, _}) do
    false
  end

  defp args_list(_Other) do
    :maybe
  end

  defp args_length({:cons, _A, _H, t}) do
    1 + args_length(t)
  end

  defp args_length({nil, _A}) do
    0
  end

  def check_format_string(fmt) when is_atom(fmt) do
    check_format_string(:erlang.atom_to_list(fmt))
  end

  def check_format_string(fmt) when is_binary(fmt) do
    check_format_string(:erlang.binary_to_list(fmt))
  end

  def check_format_string(fmt) do
    extract_sequences(fmt, [])
  end

  defp extract_sequences(fmt, need0) do
    case :string.find(fmt, [?~]) do
      :nomatch ->
        {:ok, :lists.reverse(need0)}

      [?~ | fmt1] ->
        case extract_sequence(1, fmt1, need0) do
          {:ok, need1, rest} ->
            extract_sequences(rest, need1)

          error ->
            error
        end
    end
  end

  defp extract_sequence_digits(fld, [c | fmt], need)
       when is_integer(c) and
              c >= ?0 and c <= ?9 do
    extract_sequence_digits(fld, fmt, need)
  end

  defp extract_sequence_digits(fld, fmt, need) do
    extract_sequence(fld + 1, fmt, need)
  end

  defp extract_modifiers([c | fmt], modifiers0) do
    case is_modifier(c) do
      true ->
        case :ordsets.add_element(c, modifiers0) do
          ^modifiers0 ->
            {:error, ~c"repeated modifier " ++ [c]}

          modifiers ->
            extract_modifiers(fmt, modifiers)
        end

      false ->
        {[c | fmt], modifiers0}
    end
  end

  defp extract_modifiers([], modifiers) do
    {[], modifiers}
  end

  defp check_modifiers_1(m, modifiers, c, cs) do
    case :ordsets.intersection(
           :ordsets.from_list(m),
           modifiers
         ) do
      [_] = mod ->
        case :lists.member(c, cs) do
          true ->
            :ok

          false ->
            {:error, ~c"invalid modifier/control combination ~" ++ mod ++ [c]}
        end

      [] ->
        :ok

      [_, _] = ^m ->
        {:error, ~c"conflicting modifiers ~" ++ m ++ [c]}
    end
  end

  defp is_modifier(?k) do
    true
  end

  defp is_modifier(?K) do
    true
  end

  defp is_modifier(?l) do
    true
  end

  defp is_modifier(?t) do
    true
  end

  defp is_modifier(_) do
    false
  end

  defp control_type(?~, need) do
    need
  end

  defp control_type(?c, need) do
    [:int | need]
  end

  defp control_type(?f, need) do
    [:float | need]
  end

  defp control_type(?e, need) do
    [:float | need]
  end

  defp control_type(?g, need) do
    [:float | need]
  end

  defp control_type(?s, need) do
    [:string | need]
  end

  defp control_type(?w, need) do
    [:term | need]
  end

  defp control_type(?p, need) do
    [:term | need]
  end

  defp control_type(?W, need) do
    [:int, :term | need]
  end

  defp control_type(?P, need) do
    [:int, :term | need]
  end

  defp control_type(?b, need) do
    [:int | need]
  end

  defp control_type(?B, need) do
    [:int | need]
  end

  defp control_type(?x, need) do
    [:string, :int | need]
  end

  defp control_type(?X, need) do
    [:string, :int | need]
  end

  defp control_type(?+, need) do
    [:term | need]
  end

  defp control_type(?#, need) do
    [:term | need]
  end

  defp control_type(?n, need) do
    need
  end

  defp control_type(?i, need) do
    [:term | need]
  end

  defp control_type(_C, _Need) do
    :error
  end

  defp local_functions(forms) do
    :gb_sets.from_list(
      for {:function, _, func, arity, _} <- forms do
        {func, arity}
      end
    )
  end

  defp is_local_function(localSet, {func, arity}) do
    :gb_sets.is_element({func, arity}, localSet)
  end

  defp is_imported_function(importSet, {func, arity}) do
    case :orddict.find({func, arity}, importSet) do
      {:ok, _Mod} ->
        true

      :error ->
        false
    end
  end

  defp is_imported_from_erlang(importSet, {func, arity}) do
    case :orddict.find({func, arity}, importSet) do
      {:ok, :erlang} ->
        true

      _ ->
        false
    end
  end

  defp auto_import_suppressed(compileFlags) do
    case :lists.member(:no_auto_import, compileFlags) do
      true ->
        :all

      false ->
        l0 =
          for {:no_auto_import, x} <- compileFlags do
            x
          end

        l1 =
          for {y, z} <- :lists.flatten(l0), is_atom(y), is_integer(z) do
            {y, z}
          end

        :gb_sets.from_list(l1)
    end
  end

  defp is_autoimport_suppressed(:all, {_Func, _Arity}) do
    true
  end

  defp is_autoimport_suppressed(noAutoSet, {func, arity}) do
    :gb_sets.is_element({func, arity}, noAutoSet)
  end

  defp bif_clash_specifically_disabled(st, {f, a}) do
    :lists.member({f, a}, r_lint(st, :nowarn_bif_clash))
  end

  defp no_guard_bif_clash(st, {f, a}) do
    not is_local_function(r_lint(st, :locals), {f, a}) and
      (not is_imported_function(
         r_lint(st, :imports),
         {f, a}
       ) or
         is_imported_from_erlang(
           r_lint(st, :imports),
           {f, a}
         )) and
      (not is_autoimport_suppressed(
         r_lint(st, :no_auto),
         {f, a}
       ) or
         is_imported_from_erlang(
           r_lint(st, :imports),
           {f, a}
         ))
  end

  defp maps_prepend(key, value, map) do
    case :maps.find(key, map) do
      {:ok, values} ->
        :maps.put(key, [value | values], map)

      :error ->
        :maps.put(key, [value], map)
    end
  end
end
