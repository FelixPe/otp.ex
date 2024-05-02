defmodule :m_edoc_layout_chunks do
  use Bitwise
  require Record
  Record.defrecord(:r_doclet_context, :doclet_context, dir: ~c"", env: :undefined, opts: [])
  Record.defrecord(:r_doclet_gen, :doclet_gen, sources: [], app: :no_app, modules: [])

  Record.defrecord(:r_doclet_toc, :doclet_toc,
    paths: :undefined,
    indir: :undefined
  )

  Record.defrecord(:r_module, :module,
    name: [],
    parameters: :none,
    functions: [],
    exports: [],
    attributes: [],
    records: [],
    encoding: :latin1,
    file: :undefined
  )

  Record.defrecord(:r_env, :env,
    module: [],
    root: ~c"",
    file_suffix: :undefined,
    apps: :undefined,
    modules: :undefined,
    app_default: :undefined,
    macros: [],
    includes: []
  )

  Record.defrecord(:r_comment, :comment,
    line: 0,
    text: :undefined
  )

  Record.defrecord(:r_entry, :entry,
    name: :undefined,
    args: [],
    line: 0,
    export: :undefined,
    data: :undefined
  )

  Record.defrecord(:r_tag, :tag,
    name: :undefined,
    line: 0,
    origin: :comment,
    data: :undefined,
    form: :undefined
  )

  Record.defrecord(:r_docs_v1, :docs_v1,
    anno: :undefined,
    beam_language: :erlang,
    format: "application/erlang+html",
    module_doc: :undefined,
    metadata: %{otp_doc_vsn: {1, 0, 0}},
    docs: :undefined
  )

  Record.defrecord(:r_docs_v1_entry, :docs_v1_entry,
    kind_name_arity: :undefined,
    anno: :undefined,
    signature: :undefined,
    doc: :undefined,
    metadata: :undefined
  )

  Record.defrecord(:r_xmlDecl, :xmlDecl,
    vsn: :undefined,
    encoding: :undefined,
    standalone: :undefined,
    attributes: :undefined
  )

  Record.defrecord(:r_xmlAttribute, :xmlAttribute,
    name: :undefined,
    expanded_name: [],
    nsinfo: [],
    namespace: [],
    parents: [],
    pos: :undefined,
    language: [],
    value: :undefined,
    normalized: :undefined
  )

  Record.defrecord(:r_xmlNamespace, :xmlNamespace,
    default: [],
    nodes: []
  )

  Record.defrecord(:r_xmlNsNode, :xmlNsNode,
    parents: [],
    pos: :undefined,
    prefix: :undefined,
    uri: []
  )

  Record.defrecord(:r_xmlElement, :xmlElement,
    name: :undefined,
    expanded_name: [],
    nsinfo: [],
    namespace: :EFE_TODO_NESTED_RECORD,
    parents: [],
    pos: :undefined,
    attributes: [],
    content: [],
    language: ~c"",
    xmlbase: ~c"",
    elementdef: :undeclared
  )

  Record.defrecord(:r_xmlText, :xmlText,
    parents: [],
    pos: :undefined,
    language: [],
    value: :undefined,
    type: :text
  )

  Record.defrecord(:r_xmlComment, :xmlComment,
    parents: [],
    pos: :undefined,
    language: [],
    value: :undefined
  )

  Record.defrecord(:r_xmlPI, :xmlPI,
    name: :undefined,
    parents: [],
    pos: :undefined,
    value: :undefined
  )

  Record.defrecord(:r_xmlDocument, :xmlDocument, content: :undefined)

  Record.defrecord(:r_xmlContext, :xmlContext,
    axis_type: :forward,
    context_node: :undefined,
    context_position: 1,
    nodeset: [],
    bindings: [],
    functions: [],
    namespace: [],
    whole_document: :undefined
  )

  Record.defrecord(:r_xmlNode, :xmlNode, type: :element, node: :undefined, parents: [], pos: 1)

  Record.defrecord(:r_xmlObj, :xmlObj,
    type: :undefined,
    value: :undefined
  )

  Record.defrecord(:r_xmerl_fun_states, :xmerl_fun_states,
    event: :undefined,
    hook: :undefined,
    rules: :undefined,
    fetch: :undefined,
    cont: :undefined
  )

  Record.defrecord(:r_xmerl_scanner, :xmerl_scanner,
    encoding: :undefined,
    standalone: :no,
    environment: :prolog,
    declarations: [],
    doctype_name: :undefined,
    doctype_DTD: :internal,
    comments: true,
    document: false,
    default_attrs: false,
    rules: :undefined,
    keep_rules: false,
    namespace_conformant: false,
    xmlbase: :undefined,
    xmlbase_cache: :undefined,
    fetch_path: [],
    filename: :file_name_unknown,
    validation: :off,
    schemaLocation: [],
    space: :preserve,
    event_fun: :undefined,
    hook_fun: :undefined,
    acc_fun: :undefined,
    fetch_fun: :undefined,
    close_fun: :undefined,
    continuation_fun: :undefined,
    rules_read_fun: :undefined,
    rules_write_fun: :undefined,
    rules_delete_fun: :undefined,
    user_state: :undefined,
    fun_states: :EFE_TODO_NESTED_RECORD,
    entity_references: [],
    text_decl: false,
    quiet: false,
    col: 1,
    line: 1,
    common_data: [],
    allow_entities: true
  )

  Record.defrecord(:r_xmerl_event, :xmerl_event,
    event: :undefined,
    line: :undefined,
    col: :undefined,
    pos: :undefined,
    data: :undefined
  )

  def module(doc, options) do
    case :lists.keyfind(:entries, 1, options) do
      {:entries, _} ->
        :ok

      _ ->
        :erlang.error(:no_entries, [doc, options])
    end

    chunk = edoc_to_chunk(doc, options)
    :erlang.term_to_binary(chunk)
  end

  defp edoc_to_chunk(doc, opts) do
    [^doc] = :xmerl_xpath.string(~c"//module", doc)
    {:source, file} = :lists.keyfind(:source, 1, opts)
    entries = entries(opts)
    moduleEntry = :edoc_data.get_entry(:module, entries)
    line = r_entry(moduleEntry, :line)
    anno = :erl_anno.set_file(file, :erl_anno.new(line))
    moduleDoc = doc_contents(~c"./description/fullDescription", doc, opts)

    metadata =
      :maps.from_list(
        meta_deprecated(
          doc,
          opts
        ) ++ meta_since(doc, opts)
      )

    docs = doc_entries(doc, opts)
    docs_v1(anno, moduleDoc, metadata, docs)
  end

  defp doc_contents(xPath, doc, opts) do
    case doc_visibility(xPath, doc, opts) do
      :none ->
        :none

      :hidden ->
        :hidden

      :show ->
        doc_contents_(xPath, doc, opts)
    end
  end

  defp doc_visibility(_XPath, doc, opts) do
    case {xpath_to_text(~c"./@private", doc, opts), :proplists.get_bool(:show_private, opts),
          xpath_to_text(~c"./@hidden", doc, opts)} do
      {"yes", true, _} ->
        :show

      {"yes", _, _} ->
        :hidden

      {_, _, "yes"} ->
        :none

      _ ->
        :show
    end
  end

  defp doc_contents_(_XPath, doc, opts) do
    equiv = xpath_to_chunk(~c"./equiv", doc, opts)
    desc = xpath_to_chunk(~c"./description/fullDescription", doc, opts)
    see = xpath_to_chunk(~c"./see", doc, opts)
    doc_content(equiv ++ desc ++ see, opts)
  end

  defp meta_deprecated(doc, opts) do
    deprecated = xpath_to_text(~c"./deprecated/description/fullDescription", doc, opts)

    for _ <- [:EFE_DUMMY_GEN], is_truthy(deprecated) do
      {:deprecated, deprecated}
    end
  end

  defp meta_since(doc, opts) do
    since = xpath_to_text(~c"./since", doc, opts)

    for _ <- [:EFE_DUMMY_GEN], is_truthy(since) do
      {:since, since}
    end
  end

  defp is_truthy(<<>>) do
    false
  end

  defp is_truthy(b) when is_binary(b) do
    true
  end

  defp doc_entries(doc, opts) do
    types(doc, opts) ++
      callbacks(
        doc,
        opts
      ) ++ functions(doc, opts)
  end

  defp types(doc, opts) do
    for tD <- :xmerl_xpath.string(~c"//typedecls/typedecl", doc) do
      type(tD, opts)
    end
  end

  defp type(doc, opts) do
    name = xpath_to_atom(~c"./typedef/erlangName/@name", doc, opts)
    [r_xmlElement(content: content)] = :xmerl_xpath.string(~c"./typedef/argtypes", doc)
    arity = length(content)
    anno = anno(doc, opts)

    signature = [
      :erlang.list_to_binary(
        :erlang.atom_to_list(name) ++ ~c"/" ++ :erlang.integer_to_list(arity)
      )
    ]

    entryDoc = doc_contents(~c"./description/fullDescription", doc, opts)

    metadata =
      :maps.from_list(
        meta_deprecated(
          doc,
          opts
        ) ++
          meta_since(
            doc,
            opts
          ) ++
          meta_type_sig(
            name,
            arity,
            anno,
            entries(opts)
          )
      )

    docs_v1_entry(:type, name, arity, anno, signature, entryDoc, metadata)
  end

  defp meta_type_sig(name, arity, anno, entries) do
    line = :erl_anno.line(anno)
    tags = :edoc_data.get_all_tags(entries)

    case :lists.filtermap(
           fn t ->
             select_tag(t, name, arity, line)
           end,
           tags
         ) do
      [] ->
        []

      [typeAttr] ->
        [{:signature, [typeAttr]}]
    end
  end

  defp select_tag(r_tag(name: :type, line: line, origin: :code) = t, name, arity, line) do
    typeTree = r_tag(t, :form)
    typeAttr = :erl_syntax.revert(typeTree)

    case typeAttr do
      {:attribute, _, type, {^name, _, args}}
      when :type === type or
             (:opaque === type and
                length(args) == arity) ->
        {true, typeAttr}

      _ ->
        false
    end
  end

  defp select_tag(_, _, _, _) do
    false
  end

  defp callbacks(_Doc, opts) do
    entries = entries(opts)
    tags = :edoc_data.get_all_tags(entries)
    callbacks = :edoc_data.get_tags(:callback, tags)

    for cb <- callbacks do
      callback(cb, opts)
    end
  end

  defp callback(cb = r_tag(name: :callback, origin: :code), opts) do
    r_tag(line: line, data: {{name, arity}, maybeDoc}, form: form) = cb

    entryDoc =
      case maybeDoc do
        :none ->
          :none

        _ ->
          doc_content([xmerl_to_binary(maybeDoc, opts)], opts)
      end

    {:source, file} = :lists.keyfind(:source, 1, opts)
    anno = :erl_anno.set_file(file, :erl_anno.new(line))

    signature = [
      :erlang.list_to_binary(
        :erlang.atom_to_list(name) ++ ~c"/" ++ :erlang.integer_to_list(arity)
      )
    ]

    metadata = :maps.from_list([{:signature, [form]}])
    docs_v1_entry(:callback, name, arity, anno, signature, entryDoc, metadata)
  end

  defp functions(doc, opts) do
    for f <- :xmerl_xpath.string(~c"//module/functions/function", doc) do
      function(f, opts)
    end
  end

  defp function(doc, opts) do
    name = xpath_to_atom(~c"./@name", doc, opts)
    arity = xpath_to_integer(~c"./@arity", doc, opts)

    {line, signature, spec} =
      function_line_sig_spec(
        {name, arity},
        opts
      )

    {:source, file} = :lists.keyfind(:source, 1, opts)
    anno = :erl_anno.set_file(file, :erl_anno.new(line))
    entryDoc = doc_contents(~c"./", doc, opts)

    metadata =
      :maps.from_list(
        meta_deprecated(
          doc,
          opts
        ) ++
          meta_since(
            doc,
            opts
          ) ++ spec
      )

    docs_v1_entry(:function, name, arity, anno, signature, entryDoc, metadata)
  end

  defp function_line_sig_spec(nA, opts) do
    entries = entries(opts)
    r_entry(name: ^nA, line: line) = e = :lists.keyfind(nA, r_entry(:name), entries)
    {argNames, sig} = args_and_signature(e)

    case :lists.keyfind(:spec, r_tag(:name), r_entry(e, :data)) do
      false ->
        {line, sig, []}

      r_tag(name: :spec, origin: :comment) ->
        {line, sig, []}

      r_tag(name: :spec, origin: :code) = t ->
        f = :erl_syntax.revert(r_tag(t, :form))
        annotated = annotate_spec(argNames, f, source_file(opts), line)
        {line, sig, [{:signature, [annotated]}]}
    end
  end

  defp args_and_signature(e = r_entry()) do
    {name, _} = r_entry(e, :name)

    case r_entry(e, :args) do
      [args | _] = clauses when is_list(args) ->
        {clauses, format_signature(name, args)}

      args when is_list(args) ->
        {args, format_signature(name, args)}
    end
  end

  defp format_signature(name, []) do
    [<<:erlang.atom_to_binary(name, :utf8)::bytes, "()">>]
  end

  defp format_signature(name, [arg]) do
    [
      <<:erlang.atom_to_binary(name, :utf8)::bytes, "(",
        :erlang.atom_to_binary(arg, :utf8)::bytes, ")">>
    ]
  end

  defp format_signature(name, [arg | args]) do
    [
      <<:erlang.atom_to_binary(name, :utf8)::bytes, "(",
        :erlang.atom_to_binary(arg, :utf8)::bytes, ",">>
      | format_signature(args)
    ]
  end

  defp format_signature([arg]) do
    [<<:erlang.atom_to_binary(arg, :utf8)::bytes, ")">>]
  end

  defp format_signature([arg | args]) do
    [
      <<:erlang.atom_to_binary(arg, :utf8)::bytes, ",">>
      | format_signature(args)
    ]
  end

  defp annotate_spec(argClauses, spec, sourceFile, line) do
    try do
      annotate_spec_(argClauses, spec)
    catch
      :error, {:bounded_fun_arity, vars} ->
        bounded_fun_arity_error(vars, spec, sourceFile, line)
    end
  end

  defp bounded_fun_arity_error(vars, spec, sourceFile, line) do
    :edoc_report.warning(
      line,
      sourceFile,
      ~c"cannot handle spec with constraints - arity mismatch.\nThis is a bug in EDoc spec formatter - please report it at https://bugs.erlang.org/\nIdentified arguments: ~p\nOriginal spec: ~s\n",
      [
        for {:var, _, vName} <- vars do
          vName
        end,
        :erl_pp.attribute(spec)
      ]
    )

    spec
  end

  defp annotate_spec_(
         argClauses,
         {:attribute, pos, :spec, data} = spec
       ) do
    {nA, specClauses} = data

    case (try do
            :lists.zip(argClauses, specClauses)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end) do
      {_, {:function_clause, [{:lists, :zip, _, _} | _]}} ->
        :edoc_report.warning(
          ~c"cannot annotate spec: function and spec clause numbers do not match\n",
          []
        )

        spec

      argSpecClauses ->
        newData =
          {nA,
           for {aC, sC} <- argSpecClauses do
             annotate_clause(aC, sC)
           end}

        {:attribute, pos, :spec, newData}
    end
  end

  defp annotate_clause(argNames, {:type, pos, :fun, data}) do
    [{:type, _, :product, argTypes}, retType] = data

    annArgTypes =
      for {name, type} <-
            :lists.zip(
              argNames,
              argTypes
            ) do
        ann_fun_type(name, pos, type)
      end

    newData = [{:type, pos, :product, annArgTypes}, retType]
    {:type, pos, :fun, newData}
  end

  defp annotate_clause(argNames, {:type, pos, :bounded_fun, data}) do
    [{:type, _, :fun, _} = clause, constraints] = data
    {newClause, newConstraints} = annotate_bounded_fun_clause(argNames, clause, constraints)
    {:type, pos, :bounded_fun, [newClause, newConstraints]}
  end

  defp ann_fun_type(_Name, _Pos, {:ann_type, _, _} = annType) do
    annType
  end

  defp ann_fun_type(name, pos, type) do
    typeVar =
      :erl_syntax.set_pos(
        :erl_syntax.variable(name),
        pos
      )

    annType =
      :erl_syntax.set_pos(
        :erl_syntax.annotated_type(
          typeVar,
          type
        ),
        pos
      )

    :erl_syntax.revert(annType)
  end

  defp annotate_bounded_fun_clause(argNames, {:type, pos, :fun, data}, constraints) do
    [{:type, _, :product, args}, retType] = data

    newVarsAndConstraints =
      :lists.foldl(
        fn {name, arg}, acc ->
          bounded_fun_arg(%{acc | name: name, arg: arg})
        end,
        %{
          name: :undefined,
          arg: :undefined,
          pos: pos,
          new_vars: [],
          new_constraints: [],
          ret_type: retType,
          constraints: constraints
        },
        :lists.zip(argNames, args)
      )

    %{new_vars: typeVars, new_constraints: newConstraints} = newVarsAndConstraints
    length(argNames) == length(typeVars) or :erlang.error({:bounded_fun_arity, typeVars})

    newConstraints2 =
      case retType do
        {:var, _, _} ->
          [
            get_constraint(retType, constraints)
            | newConstraints
          ]

        _ ->
          newConstraints
      end

    newData = [{:type, pos, :product, :lists.reverse(typeVars)}, retType]
    {{:type, pos, :fun, newData}, :lists.reverse(newConstraints2)}
  end

  defp bounded_fun_arg(%{arg: {singleton, _, _} = arg} = acc)
       when :atom === singleton or :integer === singleton do
    %{new_vars: nVs} = acc
    %{acc | new_vars: [arg | nVs]}
  end

  defp bounded_fun_arg(%{arg: {:var, _, :_} = v} = acc) do
    %{new_vars: nVs} = acc
    %{acc | new_vars: [v | nVs]}
  end

  defp bounded_fun_arg(%{arg: {:var, _, _} = v} = acc) do
    %{new_vars: nVs, new_constraints: nCs, constraints: cs, ret_type: retType} = acc

    case get_constraint(v, cs) do
      {:type, _, :constraint, _} = c ->
        %{acc | new_vars: [v | nVs], new_constraints: [c | nCs]}

      :no_constraint ->
        case get_mention(v, cs) do
          {:type, _, :constraint, _} ->
            %{acc | new_vars: [v | nVs]}

          :no_mention ->
            {:var, _, name} = v
            retNames = :erl_syntax_lib.variables(retType)

            case :sets.is_element(name, retNames) do
              true ->
                %{acc | new_vars: [v | nVs]}

              false ->
                acc
            end
        end
    end
  end

  defp bounded_fun_arg(%{arg: {:ann_type, var, type}} = acc) do
    bounded_fun_arg_(var, type, acc)
  end

  defp bounded_fun_arg(%{arg: type} = acc)
       when :remote_type === :erlang.element(1, type) or
              :type === :erlang.element(1, type) or
              :user_type === :erlang.element(1, type) do
    %{name: name, pos: pos} = acc

    var =
      :erl_syntax.revert(
        :erl_syntax.set_pos(
          :erl_syntax.variable(name),
          pos
        )
      )

    bounded_fun_arg_(var, type, acc)
  end

  defp bounded_fun_arg_(var, type, acc) do
    %{pos: pos, new_vars: nVs, new_constraints: nCs} = acc
    c = {:type, pos, :constraint, [{:atom, pos, :is_subtype}, [var, type]]}
    %{acc | new_vars: [var | nVs], new_constraints: [c | nCs]}
  end

  defp get_constraint({:var, _, name}, constraints) do
    f = fn
      {:type, _, :constraint, [_, [{:var, _, cName}, _]]}
      when name === cName ->
        true

      _ ->
        false
    end

    case :lists.filter(f, constraints) do
      [c] ->
        c

      [] ->
        :no_constraint
    end
  end

  defp get_mention({:var, _, name}, constraints) do
    f = fn
      {:type, _, :constraint, _} = c ->
        vars = :erl_syntax_lib.variables(c)
        :sets.is_element(name, vars)

      _ ->
        false
    end

    case :lists.filter(f, constraints) do
      [c | _] ->
        c

      [] ->
        :no_mention
    end
  end

  defp entries(opts) do
    {:entries, entries} = :lists.keyfind(:entries, 1, opts)
    entries
  end

  defp source_file(opts) do
    {:source, source} = :lists.keyfind(:source, 1, opts)
    source
  end

  defp doc_content([], _Opts) do
    %{}
  end

  defp doc_content(content, opts) do
    docLanguage = :proplists.get_value(:lang, opts, "en")
    %{docLanguage => content}
  end

  defp docs_v1(anno, moduleDoc, metadata, docs) do
    r_docs_v1(anno: anno, module_doc: moduleDoc, metadata: metadata, docs: docs)
  end

  defp anno(doc, opts) do
    {:source, file} = :lists.keyfind(:source, 1, opts)
    line = xpath_to_integer(~c"./@line", doc, opts)
    :erl_anno.set_file(file, :erl_anno.new(line))
  end

  defp docs_v1_entry(kind, name, arity, anno, signature, entryDoc, metadata) do
    {{kind, name, arity}, anno, signature, entryDoc, metadata}
  end

  defp xpath_to_text(xPath, doc, opts) do
    case :xmerl_xpath.string(xPath, doc) do
      [] ->
        <<>>

      [r_xmlAttribute() = attr] ->
        {_, value} = format_attribute(attr)
        hd(:shell_docs.normalize([value]))

      [r_xmlElement()] = elements ->
        xmerl_to_binary(elements, opts)

      [_ | _] ->
        :erlang.error(:multiple_nodes, [xPath, doc, opts])
    end
  end

  defp xmerl_to_binary(xML, opts) do
    :erlang.iolist_to_binary(
      chunk_to_text(
        xmerl_to_chunk(
          xML,
          opts
        )
      )
    )
  end

  defp chunk_to_text([]) do
    []
  end

  defp chunk_to_text([node | nodes]) do
    case node do
      _ when is_binary(node) ->
        [node | chunk_to_text(nodes)]

      {_Tag, _Attrs, subNodes} ->
        [chunk_to_text(subNodes) | chunk_to_text(nodes)]
    end
  end

  defp xpath_to_atom(xPath, doc, opts) do
    :erlang.binary_to_atom(
      xpath_to_text(xPath, doc, opts),
      :utf8
    )
  end

  defp xpath_to_integer(xPath, doc, opts) do
    :erlang.binary_to_integer(xpath_to_text(xPath, doc, opts))
  end

  defp xpath_to_chunk(xPath, doc, opts) do
    xmerlDoc = :xmerl_xpath.string(xPath, doc)
    xmerl_to_chunk(xmerlDoc, opts)
  end

  defp xmerl_to_chunk(contents, opts) do
    :shell_docs.normalize(format_content(contents, opts))
  end

  defp format_content(contents, opts) do
    {seeTags, otherTags} =
      :lists.partition(
        fn
          r_xmlElement(name: :see) ->
            true

          _ ->
            false
        end,
        contents
      )

    :lists.flatten(
      for t <- otherTags do
        format_content_(t, opts)
      end ++ rewrite_see_tags(seeTags, opts)
    )
  end

  defp format_content_(r_xmlPI(), _) do
    []
  end

  defp format_content_(r_xmlComment(), _) do
    []
  end

  defp format_content_(r_xmlText() = t, _) do
    text = r_xmlText(t, :value)

    case :edoc_lib.is_space(text) do
      true ->
        []

      false ->
        [:unicode.characters_to_binary(text)]
    end
  end

  defp format_content_(r_xmlElement(name: :equiv) = e, opts) do
    format_element(rewrite_equiv_tag(e), opts)
  end

  defp format_content_(r_xmlElement(name: :a) = e, opts) do
    format_element(rewrite_a_tag(e), opts)
  end

  defp format_content_(r_xmlElement() = e, opts) do
    format_element(e, opts)
  end

  defp format_element(r_xmlElement() = e, opts) do
    r_xmlElement(name: name, content: content, attributes: attributes) = e

    case {is_edoc_tag(name), is_html_tag(name)} do
      {true, _} ->
        format_content(content, opts)

      {_, false} ->
        :edoc_report.warning(
          0,
          source_file(opts),
          ~c"'~s' is not allowed - skipping tag, extracting content",
          [name]
        )

        format_content(content, opts)

      _ ->
        [{name, format_attributes(attributes), format_content(content, opts)}]
    end
  end

  defp format_attributes(attrs) do
    for attr <- attrs do
      format_attribute(attr)
    end
  end

  defp format_attribute(r_xmlAttribute() = attr) do
    r_xmlAttribute(name: name, value: v) = attr

    case v do
      _ when is_list(v) ->
        {name, :unicode.characters_to_binary(v)}

      _ when is_atom(v) ->
        {name, :erlang.atom_to_binary(v, :utf8)}

      _ when is_integer(v) ->
        {name, :erlang.integer_to_binary(v)}
    end
  end

  defp is_edoc_tag(:fullDescription) do
    true
  end

  defp is_edoc_tag(:since) do
    true
  end

  defp is_edoc_tag(_) do
    false
  end

  defp is_html_tag(tag) do
    tags = :shell_docs.supported_tags()
    :lists.member(tag, tags)
  end

  defp rewrite_a_tag(r_xmlElement(name: :a) = e) do
    simpleE = :xmerl_lib.simplify_element(e)
    :xmerl_lib.normalize_element(rewrite_docgen_link(simpleE))
  end

  defp rewrite_see_tags([], _Opts) do
    []
  end

  defp rewrite_see_tags([r_xmlElement(name: :see) | _] = seeTags, opts) do
    grouped =
      for t <- seeTags do
        rewrite_see_tag(t)
      end

    newXML = {:p, [], [{:em, [], [~c"See also: "]}] ++ :lists.join(~c", ", grouped) ++ [~c"."]}

    [
      format_content_(
        :xmerl_lib.normalize_element(newXML),
        opts
      )
    ]
  end

  defp rewrite_see_tag(r_xmlElement(name: :see) = e) do
    seeTag = :xmerl_lib.simplify_element(e)
    {:see, attrs, xML} = rewrite_docgen_link(seeTag)
    {:a, attrs, xML}
  end

  defp rewrite_docgen_link({tag, attrL, subEls} = e)
       when tag === :a or
              tag === :see do
    attrs = :maps.from_list(attrL)

    case {:maps.get(:"docgen-rel", attrs, false), :maps.get(:"docgen-href", attrs, false)} do
      {false, false} ->
        e

      {false, _} ->
        inconsistent_docgen_attrs(attrs)

      {_, false} ->
        inconsistent_docgen_attrs(attrs)

      {shortRel, uRI} ->
        attrsNoDocgen = :maps.without([:"docgen-rel", :"docgen-href"], attrs)
        newAttrs = Map.merge(attrsNoDocgen, %{rel: expand_docgen_rel(shortRel), href: uRI})
        {tag, :maps.to_list(newAttrs), subEls}
    end
  end

  defp inconsistent_docgen_attrs(attrs) do
    :erlang.error({:inconsistent_docgen_attrs, attrs})
  end

  defp expand_docgen_rel(rel)
       when rel === ~c"seemfa" or rel === ~c"seeerl" or rel === ~c"seetype" or
              rel === ~c"seeapp" or rel === ~c"seecom" or rel === ~c"seecref" or
              rel === ~c"seefile" or
              rel === ~c"seeguide" do
    ~c"https://erlang.org/doc/link/" ++ rel
  end

  defp rewrite_equiv_tag(r_xmlElement(name: :equiv) = e) do
    newE =
      case :xmerl_lib.simplify_element(e) do
        {:equiv, [], [{:expr, [], expr}]} ->
          {:p, [], [~c"Equivalent to ", expr, ~c"."]}

        {:equiv, [], [{:expr, [], expr}, {:see, _, _} = seeTag]} ->
          {:see, attrs, _} = rewrite_docgen_link(seeTag)
          {:p, [], [~c"Equivalent to ", {:a, attrs, expr}, ~c"."]}
      end

    :xmerl_lib.normalize_element(newE)
  end
end
