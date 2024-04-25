defmodule :m_shell_docs do
  use Bitwise
  require Record

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

  Record.defrecord(:r_config, :config,
    docs: :undefined,
    encoding: :undefined,
    ansi: :undefined,
    io_opts: :io.getopts(),
    columns: :undefined
  )

  def supported_tags() do
    [
      :a,
      :p,
      :div,
      :br,
      :h1,
      :h2,
      :h3,
      :h4,
      :h5,
      :h6,
      :i,
      :b,
      :em,
      :strong,
      :pre,
      :code,
      :ul,
      :ol,
      :li,
      :dl,
      :dt,
      :dd
    ]
  end

  def validate(module) when is_atom(module) do
    {:ok, doc} = :code.get_doc(module)
    validate(doc)
  end

  def validate(r_docs_v1(module_doc: mDocs, docs: allDocs)) do
    aE =
      :lists.sort([
        :a,
        :p,
        :div,
        :br,
        :h1,
        :h2,
        :h3,
        :h4,
        :h5,
        :h6,
        :i,
        :b,
        :em,
        :strong,
        :pre,
        :code,
        :ul,
        :ol,
        :li,
        :dl,
        :dt,
        :dd
      ])

    ^aE =
      :lists.sort(
        [:i, :b, :em, :strong, :code, :a] ++
          [:p, :div, :pre, :br, :ul, :ol, :li, :dl, :dt, :dd, :h1, :h2, :h3, :h4, :h5, :h6]
      )

    true =
      :lists.all(
        fn elem ->
          elem === :a or elem === :code or elem === :i or elem === :em or elem === :b or
            elem === :strong
        end,
        [:i, :b, :em, :strong, :code, :a]
      )

    true =
      :lists.all(
        fn elem ->
          not (elem === :a or elem === :code or elem === :i or elem === :em or elem === :b or
                 elem === :strong)
        end,
        [:p, :div, :pre, :br, :ul, :ol, :li, :dl, :dt, :dd, :h1, :h2, :h3, :h4, :h5, :h6]
      )

    _ = validate_docs(mDocs)

    :lists.foreach(
      fn {_, _Anno, sig, docs, _Meta} ->
        case :lists.all(&:erlang.is_binary/1, sig) do
          false ->
            throw({:invalid_signature, sig})

          true ->
            :ok
        end

        validate_docs(docs)
      end,
      allDocs
    )

    :ok
  end

  defp validate_docs(:hidden) do
    :ok
  end

  defp validate_docs(:none) do
    :ok
  end

  defp validate_docs(%{} = mDocs) do
    :maps.foreach(
      fn _Key, mDoc ->
        validate_docs(mDoc, [])
      end,
      mDocs
    )

    :ok
  end

  defp validate_docs([h | t], path) when is_tuple(h) do
    _ = validate_docs(h, path)
    validate_docs(t, path)
  end

  defp validate_docs({:br, attr, content} = br, path) do
    cond do
      attr === [] and content === [] ->
        :ok

      true ->
        throw({:content_to_allowed_in_br, br, path})
    end
  end

  defp validate_docs({tag, attr, content}, path) do
    case tag !== :li and length(path) > 0 and (hd(path) === :ul or hd(path) === :ol) do
      true ->
        throw({:only_li_allowed_within_ul_or_ol, tag, path})

      _ ->
        :ok
    end

    case tag !== :dd and tag !== :dt and length(path) > 0 and hd(path) === :dl do
      true ->
        throw({:only_dd_or_dt_allowed_within_dl, tag, path})

      _ ->
        :ok
    end

    case tag === :p and :lists.member(:p, path) do
      true ->
        throw({:nested_p_not_allowed, tag, path})

      false ->
        :ok
    end

    case :erlang.or(
           :lists.member(:pre, path),
           :lists.any(
             fn h ->
               :lists.member(h, path)
             end,
             [:h1, :h2, :h3, :h4, :h5, :h6]
           )
         ) do
      true
      when not (tag === :a or tag === :code or tag === :i or tag === :em or tag === :b or
                    tag === :strong) ->
        throw({:cannot_put_block_tag_within_pre, tag, path})

      _ ->
        :ok
    end

    case :lists.member(
           tag,
           [:p, :div, :pre, :br, :ul, :ol, :li, :dl, :dt, :dd, :h1, :h2, :h3, :h4, :h5, :h6]
         ) do
      true ->
        case :lists.any(
               fn p ->
                 p === :a or p === :code or p === :i or p === :em or p === :b or p === :strong
               end,
               path
             ) do
          true ->
            throw({:cannot_put_inline_tag_outside_block, tag, path})

          false ->
            :ok
        end

      false ->
        :ok
    end

    case :lists.member(
           tag,
           [
             :a,
             :p,
             :div,
             :br,
             :h1,
             :h2,
             :h3,
             :h4,
             :h5,
             :h6,
             :i,
             :b,
             :em,
             :strong,
             :pre,
             :code,
             :ul,
             :ol,
             :li,
             :dl,
             :dt,
             :dd
           ]
         ) do
      false ->
        throw({:invalid_tag, tag, path})

      true ->
        :ok
    end

    case :lists.all(
           fn {key, val} ->
             is_atom(key) and is_binary(val)
           end,
           attr
         ) do
      true ->
        :ok

      false ->
        throw({:invalid_attribute, {tag, attr}})
    end

    validate_docs(content, [tag | path])
  end

  defp validate_docs([chars | t], path) when is_binary(chars) do
    validate_docs(t, path)
  end

  defp validate_docs([], _) do
    :ok
  end

  def normalize(docs) do
    trimmed = normalize_trim(docs, true)
    normalize_space(trimmed)
  end

  defp normalize_trim(bin, true) when is_binary(bin) do
    noSpace = :re.replace(bin, ~c"[^\\S\n]*\n+[^\\S\n]*", ~c"\n", [:unicode, :global])
    noTab = :re.replace(noSpace, ~c"\t", ~c" ", [:unicode, :global])
    noNewLine = :re.replace(noTab, ~c"\\v", ~c" ", [:unicode, :global])
    :re.replace(noNewLine, ~c"\\s+", ~c" ", [:unicode, :global, {:return, :binary}])
  end

  defp normalize_trim(bin, false) when is_binary(bin) do
    bin
  end

  defp normalize_trim([{:code, attr, content} | t], false) do
    trimmedContent =
      case :lists.reverse(
             normalize_trim(
               content,
               false
             )
           ) do
        [bin | rest] when is_binary(bin) ->
          :lists.reverse([:string.trim(bin, :trailing) | rest])

        else__ ->
          :lists.reverse(else__)
      end

    [
      {:code, attr, trimmedContent}
      | normalize_trim(
          t,
          false
        )
    ]
  end

  defp normalize_trim([{:pre, attr, content} | t], trim) do
    [
      {:pre, attr, normalize_trim(content, false)}
      | normalize_trim(t, trim)
    ]
  end

  defp normalize_trim([{tag, attr, content} | t], trim) do
    [
      {tag, attr, normalize_trim(content, trim)}
      | normalize_trim(t, trim)
    ]
  end

  defp normalize_trim([<<>> | t], trim) do
    normalize_trim(t, trim)
  end

  defp normalize_trim([b1, b2 | t], trim)
       when is_binary(b1) and
              is_binary(b2) do
    normalize_trim(
      [<<b1::binary, b2::binary>> | t],
      trim
    )
  end

  defp normalize_trim([h | t], trim) do
    [normalize_trim(h, trim) | normalize_trim(t, trim)]
  end

  defp normalize_trim([], _Trim) do
    []
  end

  defp normalize_space([{pre, attr, content} | t]) when pre === :pre do
    [
      {pre, attr, trim_first_and_last(content, ?\n)}
      | normalize_space(t)
    ]
  end

  defp normalize_space([{block, attr, content} | t])
       when not (block === :a or block === :code or block === :i or block === :em or block === :b or
                   block === :strong) do
    [
      {block, attr, normalize_space(content)}
      | normalize_space(t)
    ]
  end

  defp normalize_space([]) do
    []
  end

  defp normalize_space(elems) do
    {inlineElems, t} =
      :lists.splitwith(
        fn e ->
          is_binary(e) or
            (is_tuple(e) and
               (:erlang.element(
                  1,
                  e
                ) === :a or
                  :erlang.element(
                    1,
                    e
                  ) === :code or
                  :erlang.element(
                    1,
                    e
                  ) === :i or
                  :erlang.element(
                    1,
                    e
                  ) === :em or
                  :erlang.element(
                    1,
                    e
                  ) === :b or
                  :erlang.element(
                    1,
                    e
                  ) === :strong))
        end,
        elems
      )

    trim_inline(inlineElems) ++ normalize_space(t)
  end

  defp trim_inline(content) do
    {newContent, _} = trim_inline(content, false)
    trim_first_and_last(newContent, ?\s)
  end

  defp trim_inline([bin | t], false) when is_binary(bin) do
    lastElem = :binary.at(bin, byte_size(bin) - 1)

    case trim_inline(t, lastElem === ?\s) do
      {[b2 | newT], newState} when is_binary(b2) ->
        {[<<bin::binary, b2::binary>> | newT], newState}

      {newT, newState} ->
        {[bin | newT], newState}
    end
  end

  defp trim_inline([" " | t], true) do
    trim_inline(t, true)
  end

  defp trim_inline([<<" ", bin::binary>> | t], true)
       when is_binary(bin) do
    trim_inline([bin | t], true)
  end

  defp trim_inline([bin | t], true) when is_binary(bin) do
    trim_inline([bin | t], false)
  end

  defp trim_inline([{elem, attr, content} | t], trimSpace) do
    {newContent, contentTrimSpace} =
      trim_inline(
        content,
        trimSpace
      )

    {newT, tTrimSpace} = trim_inline(t, contentTrimSpace)

    isAnchor =
      elem === :a and
        :proplists.is_defined(
          :id,
          attr
        )

    cond do
      newContent == [] and not isAnchor ->
        {newT, tTrimSpace}

      true ->
        {[{elem, attr, newContent} | newT], tTrimSpace}
    end
  end

  defp trim_inline([], trimSpace) do
    {[], trimSpace}
  end

  defp trim_first_and_last(content, what) when what < 256 do
    {firstTrimmed, _} = trim_first(content, what)
    {lastTrimmed, _} = trim_last(firstTrimmed, what)
    lastTrimmed
  end

  defp trim_first([bin | t], what) when is_binary(bin) do
    case bin do
      <<^what>> ->
        {t, true}

      <<^what, newBin::binary>> ->
        {[newBin | t], true}

      ^bin ->
        {[bin | t], true}
    end
  end

  defp trim_first([{elem, attr, content} = tag | t], what) do
    case trim_first(content, what) do
      {[], true} ->
        {t, true}

      {newContent, true} ->
        {[{elem, attr, newContent} | t], true}

      {^content, false} ->
        {newT, newState} = trim_first(t, what)
        {[tag | newT], newState}
    end
  end

  defp trim_first([], _What) do
    {[], false}
  end

  defp trim_last([bin | t], what) when is_binary(bin) do
    case trim_last(t, what) do
      {newT, true} ->
        {[bin | newT], true}

      {^t, false} ->
        preSz = byte_size(bin) - 1

        case bin do
          <<^what>> ->
            {t, true}

          <<newBin::size(preSz)-binary, ^what>> ->
            {[newBin | t], true}

          ^bin ->
            {[bin | t], true}
        end
    end
  end

  defp trim_last([{elem, attr, content} = tag | t], what) do
    case trim_last(t, what) do
      {newT, true} ->
        {[tag | newT], true}

      {^t, false} ->
        case trim_last(content, what) do
          {[], true} ->
            {[], true}

          {newContent, newState} ->
            {[{elem, attr, newContent} | t], newState}
        end
    end
  end

  defp trim_last([], _What) do
    {[], false}
  end

  def get_doc(module) do
    {:ok, r_docs_v1(module_doc: moduleDoc) = d} = :code.get_doc(module)
    get_local_doc(module, moduleDoc, d)
  end

  def get_doc(module, function, arity) do
    {:ok, r_docs_v1(docs: docs) = d} = :code.get_doc(module)

    fnFunctions =
      :lists.filter(
        fn
          {{:function, f, a}, _Anno, _Sig, _Doc, _Meta} ->
            f === function and a === arity

          _ ->
            false
        end,
        docs
      )

    for {f, a, s, dc, m} <- fnFunctions do
      {f, a, s, get_local_doc(f, dc, d), m}
    end
  end

  def render(module, r_docs_v1() = d) when is_atom(module) do
    render(module, d, %{})
  end

  def render(module, r_docs_v1(module_doc: moduleDoc) = d, config)
      when is_atom(module) and is_map(config) do
    render_headers_and_docs(
      [[{:h2, [], [<<"\t", :erlang.atom_to_binary(module)::binary>>]}]],
      get_local_doc(module, moduleDoc, d),
      d,
      config
    )
  end

  def render(_Module, function, r_docs_v1() = d) do
    render(_Module, function, d, %{})
  end

  def render(module, function, r_docs_v1(docs: docs) = d, config)
      when is_atom(module) and is_atom(function) and
             is_map(config) do
    render_function(
      :lists.filter(
        fn
          {{:function, f, _}, _Anno, _Sig, _Doc, _Meta} ->
            f === function

          _ ->
            false
        end,
        docs
      ),
      d,
      config
    )
  end

  def render(_Module, function, arity, r_docs_v1() = d) do
    render(_Module, function, arity, d, %{})
  end

  def render(module, function, arity, r_docs_v1(docs: docs) = d, config)
      when is_atom(module) and is_atom(function) and
             is_integer(arity) and is_map(config) do
    render_function(
      :lists.filter(
        fn
          {{:function, f, a}, _Anno, _Sig, _Doc, _Meta} ->
            f === function and a === arity

          _ ->
            false
        end,
        docs
      ),
      d,
      config
    )
  end

  def get_type_doc(module, type, arity) do
    {:ok, r_docs_v1(docs: docs) = d} = :code.get_doc(module)

    fnFunctions =
      :lists.filter(
        fn
          {{:type, t, a}, _Anno, _Sig, _Doc, _Meta} ->
            t === type and a === arity

          _ ->
            false
        end,
        docs
      )

    for {f, a, s, dc, m} <- fnFunctions do
      {f, a, s, get_local_doc(f, dc, d), m}
    end
  end

  def render_type(module, d) do
    render_type(module, d, %{})
  end

  def render_type(module, d = r_docs_v1(), config) do
    render_signature_listing(module, :type, d, config)
  end

  def render_type(module, type, d = r_docs_v1()) do
    render_type(module, type, d, %{})
  end

  def render_type(_Module, type, r_docs_v1(docs: docs) = d, config) do
    render_typecb_docs(
      :lists.filter(
        fn
          {{:type, t, _}, _Anno, _Sig, _Doc, _Meta} ->
            t === type

          _ ->
            false
        end,
        docs
      ),
      d,
      config
    )
  end

  def render_type(_Module, type, arity, r_docs_v1() = d) do
    render_type(_Module, type, arity, d, %{})
  end

  def render_type(_Module, type, arity, r_docs_v1(docs: docs) = d, config) do
    render_typecb_docs(
      :lists.filter(
        fn
          {{:type, t, a}, _Anno, _Sig, _Doc, _Meta} ->
            t === type and a === arity

          _ ->
            false
        end,
        docs
      ),
      d,
      config
    )
  end

  def get_callback_doc(module, callback, arity) do
    {:ok, r_docs_v1(docs: docs) = d} = :code.get_doc(module)

    fnFunctions =
      :lists.filter(
        fn
          {{:callback, t, a}, _Anno, _Sig, _Doc, _Meta} ->
            t === callback and a === arity

          _ ->
            false
        end,
        docs
      )

    for {f, a, s, dc, m} <- fnFunctions do
      {f, a, s, get_local_doc(f, dc, d), m}
    end
  end

  def render_callback(module, d) do
    render_callback(module, d, %{})
  end

  def render_callback(_Module, callback, r_docs_v1() = d) do
    render_callback(_Module, callback, d, %{})
  end

  def render_callback(module, d, config) do
    render_signature_listing(module, :callback, d, config)
  end

  def render_callback(_Module, callback, arity, r_docs_v1() = d) do
    render_callback(_Module, callback, arity, d, %{})
  end

  def render_callback(_Module, callback, r_docs_v1(docs: docs) = d, config) do
    render_typecb_docs(
      :lists.filter(
        fn
          {{:callback, t, _}, _Anno, _Sig, _Doc, _Meta} ->
            t === callback

          _ ->
            false
        end,
        docs
      ),
      d,
      config
    )
  end

  def render_callback(_Module, callback, arity, r_docs_v1(docs: docs) = d, config) do
    render_typecb_docs(
      :lists.filter(
        fn
          {{:callback, t, a}, _Anno, _Sig, _Doc, _Meta} ->
            t === callback and a === arity

          _ ->
            false
        end,
        docs
      ),
      d,
      config
    )
  end

  defp get_local_doc(missingMod, docs, d) when is_atom(missingMod) do
    get_local_doc(:erlang.atom_to_binary(missingMod), docs, d)
  end

  defp get_local_doc({f, a}, docs, d) do
    get_local_doc(
      :unicode.characters_to_binary(
        :io_lib.format(
          ~c"~tp/~p",
          [f, a]
        )
      ),
      docs,
      d
    )
  end

  defp get_local_doc({_Type, f, a}, docs, d) do
    get_local_doc({f, a}, docs, d)
  end

  defp get_local_doc(_Missing, %{"en" => docs}, d) do
    normalize_format(docs, d)
  end

  defp get_local_doc(_Missing, moduleDoc, d)
       when map_size(moduleDoc) > 0 do
    normalize_format(
      :maps.get(
        hd(:maps.keys(moduleDoc)),
        moduleDoc
      ),
      d
    )
  end

  defp get_local_doc(missing, :hidden, _D) do
    [
      {:p, [],
       [
         "The documentation for ",
         missing,
         " is hidden. This probably means that it is internal and not to be used by other applications."
       ]}
    ]
  end

  defp get_local_doc(missing, none, _D)
       when none === :none or
              none === %{} do
    [{:p, [], ["There is no documentation for ", missing]}]
  end

  defp normalize_format(docs, r_docs_v1(format: "application/erlang+html")) do
    normalize(docs)
  end

  defp normalize_format(docs, r_docs_v1(format: <<"text/", _::binary>>))
       when is_binary(docs) do
    [{:pre, [], [docs]}]
  end

  defp render_function([], _D, _Config) do
    {:error, :function_missing}
  end

  defp render_function(fDocs, d, config) when is_map(config) do
    render_function(fDocs, d, init_config(d, config))
  end

  defp render_function(fDocs, r_docs_v1(docs: docs) = d, config) do
    grouping =
      :lists.foldl(
        fn
          {_Group, _Anno, _Sig, _Doc, %{equiv: group}} = func, acc ->
            case :lists.keytake(group, 1, acc) do
              false ->
                [{group, [func]} | acc]

              {:value, {^group, members}, newAcc} ->
                [{group, [func | members]} | newAcc]
            end

          {group, _Anno, _Sig, _Doc, _Meta} = func, acc ->
            [{group, [func]} | acc]
        end,
        [],
        :lists.sort(
          fn a, b ->
            :erlang.element(
              1,
              a
            ) <=
              :erlang.element(
                1,
                b
              )
          end,
          fDocs
        )
      )

    :lists.map(
      fn {group, members} ->
        signatures =
          :lists.flatmap(
            &render_signature/1,
            :lists.reverse(members)
          )

        case :lists.search(
               fn {_, _, _, doc, _} ->
                 doc !== %{}
               end,
               members
             ) do
          {:value, {_, _, _, doc, _Meta}} ->
            render_headers_and_docs(signatures, get_local_doc(group, doc, d), d, config)

          false ->
            case :lists.keyfind(group, 1, docs) do
              false ->
                render_headers_and_docs(signatures, get_local_doc(group, :none, d), d, config)

              {_, _, _, doc, _} ->
                render_headers_and_docs(signatures, get_local_doc(group, doc, d), d, config)
            end
        end
      end,
      :lists.reverse(grouping)
    )
  end

  defp render_signature({{_Type, _F, _A}, _Anno, _Sigs, _Docs, %{signature: specs} = meta}) do
    :lists.flatmap(
      fn aSTSpec ->
        pPSpec =
          :erl_pp.attribute(
            aSTSpec,
            [{:encoding, :unicode}]
          )

        spec =
          case aSTSpec do
            {_Attribute, _Line, :opaque, _} ->
              hd(:string.split(pPSpec, ~c"::"))

            _ ->
              pPSpec
          end

        binSpec =
          :unicode.characters_to_binary(
            :string.trim(
              spec,
              :trailing,
              ~c"\n"
            )
          )

        [
          {:pre, [], [{:strong, [], binSpec}]}
          | render_meta(meta)
        ]
      end,
      specs
    )
  end

  defp render_signature({{_Type, _F, _A}, _Anno, sigs, _Docs, meta}) do
    :lists.flatmap(
      fn sig ->
        [
          {:h2, [], [<<"Â Â "::utf8, sig::binary>>]}
          | render_meta(meta)
        ]
      end,
      sigs
    )
  end

  defp render_meta(m) do
    case render_meta_(m) do
      [] ->
        []

      meta ->
        [[{:dl, [], meta}]]
    end
  end

  defp render_meta_(%{since: vsn} = m) do
    [
      {:dt, [], "Since"},
      {:dd, [], [vsn]}
      | render_meta_(:maps.remove(:since, m))
    ]
  end

  defp render_meta_(%{deprecated: depr} = m) do
    [
      {:dt, [], "Deprecated"},
      {:dd, [], [depr]}
      | render_meta_(:maps.remove(:deprecated, m))
    ]
  end

  defp render_meta_(_) do
    []
  end

  defp render_headers_and_docs(headers, docContents, d, config) do
    render_headers_and_docs(headers, docContents, init_config(d, config))
  end

  defp render_headers_and_docs(headers, docContents, r_config() = config) do
    [
      ~c"\n",
      render_docs(
        :lists.flatmap(
          fn header ->
            [{:br, [], []}, header]
          end,
          headers
        ),
        config
      ),
      ~c"\n",
      render_docs(docContents, 2, config)
    ]
  end

  defp render_signature_listing(module, type, d, config) when is_map(config) do
    render_signature_listing(module, type, d, init_config(d, config))
  end

  defp render_signature_listing(module, type, r_docs_v1(docs: docs) = d, config) do
    slogan = [{:h2, [], [<<"\t", :erlang.atom_to_binary(module)::binary>>]}, {:br, [], []}]

    case :lists.filter(
           fn {{t, _, _}, _Anno, _Sig, _Doc, _Meta} ->
             type === t
           end,
           docs
         ) do
      [] ->
        render_docs(
          slogan ++
            [<<"There are no ", :erlang.atom_to_binary(type)::binary, "s in this module">>],
          d,
          config
        )

      headers ->
        hdr =
          :lists.flatmap(
            fn header ->
              [{:br, [], []}, render_signature(header)]
            end,
            headers
          )

        render_docs(
          slogan ++
            [
              {:p, [],
               [
                 <<"These ", :erlang.atom_to_binary(type)::binary,
                   "s are documented in this module:">>
               ]},
              {:br, [], []},
              hdr
            ],
          d,
          config
        )
    end
  end

  defp render_typecb_docs([], _C) do
    {:error, :type_missing}
  end

  defp render_typecb_docs(typeCBs, r_config() = c) when is_list(typeCBs) do
    for typeCB <- typeCBs do
      render_typecb_docs(typeCB, c)
    end
  end

  defp render_typecb_docs(
         {f, _, _Sig, docs, _Meta} = typeCB,
         r_config(docs: d) = c
       ) do
    render_headers_and_docs(render_signature(typeCB), get_local_doc(f, docs, d), c)
  end

  defp render_typecb_docs(docs, d, config) do
    render_typecb_docs(docs, init_config(d, config))
  end

  defp render_docs(docContents, r_config() = config) do
    render_docs(docContents, 0, config)
  end

  defp render_docs(docContents, d, config)
       when elem(d, 0) === :docs_v1 do
    render_docs(docContents, 0, init_config(d, config))
  end

  defp render_docs(docContents, ind, d = r_config())
       when is_integer(ind) do
    init_ansi(d)

    try do
      {doc, _} = trimnl(render_docs(docContents, [], 0, ind, d))
      doc
    after
      clean_ansi()
    end
  end

  defp init_config(d, config) when is_map(config) do
    defaultOpts = :io.getopts()
    defaultEncoding = :proplists.get_value(:encoding, defaultOpts, :latin1)

    columns =
      case :maps.find(:columns, config) do
        :error ->
          case :io.columns() do
            {:ok, c} ->
              c

            _ ->
              80
          end

        {:ok, c} ->
          c
      end

    r_config(
      docs: d,
      encoding: :maps.get(:encoding, config, defaultEncoding),
      ansi: :maps.get(:ansi, config, :undefined),
      columns: columns
    )
  end

  defp init_config(d, config) do
    r_config(config, docs: d)
  end

  defp render_docs(elems, state, pos, ind, d)
       when is_list(elems) do
    :lists.mapfoldl(
      fn elem, p ->
        render_docs(elem, state, p, ind, d)
      end,
      pos,
      elems
    )
  end

  defp render_docs(elem, state, pos, ind, d) do
    render_element(elem, state, pos, ind, d)
  end

  defp render_element({ignoreMe, _, content}, state, pos, ind, d)
       when ignoreMe === :a do
    render_docs(content, state, pos, ind, d)
  end

  defp render_element({:h1, _, content}, state, 0 = pos, _Ind, d) do
    trimnlnl(render_element({:code, [], [{:strong, [], content}]}, state, pos, 0, d))
  end

  defp render_element({:h2, _, content}, state, 0 = pos, _Ind, d) do
    trimnlnl(render_element({:strong, [], content}, state, pos, 0, d))
  end

  defp render_element({h, _, content}, state, pos, _Ind, d)
       when (pos <= 2 and
               h === :h3) or h === :h4 or h === :h5 or h === :h6 do
    trimnlnl(render_element({:code, [], content}, state, pos, 2, d))
  end

  defp render_element({:pre, _Attr, _Content} = e, state, pos, ind, d)
       when pos > ind do
    {docs, newPos} = render_element(e, state, 0, ind, d)
    {[~c"\n\n", docs], newPos}
  end

  defp render_element({elem, _Attr, _Content} = e, state, pos, ind, d)
       when pos > ind and
              not (elem === :a or elem === :code or elem === :i or elem === :em or elem === :b or
                     elem === :strong) do
    {docs, newPos} = render_element(e, state, 0, ind, d)
    {[~c"\n", docs], newPos}
  end

  defp render_element({:div, [{:class, what}], content}, state, pos, ind, d) do
    {docs, _} = render_docs(content, [:div | state], 0, ind + 2, d)
    trimnlnl([pad(ind - pos), :string.titlecase(what), ~c":\n", docs])
  end

  defp render_element({tag, _, content}, state, pos, ind, d)
       when tag === :p or tag === :div do
    trimnlnl(render_docs(content, [tag | state], pos, ind, d))
  end

  defp render_element(elem, state, pos, ind, d) when pos < ind do
    {docs, newPos} = render_element(elem, state, ind, ind, d)
    {[pad(ind - pos), docs], newPos}
  end

  defp render_element({:code, _, content}, [:pre | _] = state, pos, ind, d) do
    render_docs(content, [:code | state], pos, ind, d)
  end

  defp render_element({:code, _, content}, state, pos, ind, d) do
    underline = sansi(:underline)
    {docs, newPos} = render_docs(content, [:code | state], pos, ind, d)
    {[underline, docs, ransi(:underline)], newPos}
  end

  defp render_element({:em, attr, content}, state, pos, ind, d) do
    render_element({:i, attr, content}, state, pos, ind, d)
  end

  defp render_element({:i, _, content}, state, pos, ind, d) do
    render_docs(content, state, pos, ind, d)
  end

  defp render_element({:br, [], []}, _State, pos, _Ind, _D) do
    {~c"", pos}
  end

  defp render_element({:strong, attr, content}, state, pos, ind, d) do
    render_element({:b, attr, content}, state, pos, ind, d)
  end

  defp render_element({:b, _, content}, state, pos, ind, d) do
    bold = sansi(:bold)
    {docs, newPos} = render_docs(content, state, pos, ind, d)
    {[bold, docs, ransi(:bold)], newPos}
  end

  defp render_element({:pre, _, content}, state, pos, ind, d) do
    trimnlnl(render_docs(content, [:pre | state], pos, ind + 2, d))
  end

  defp render_element({:ul, [{:class, "types"}], content}, state, _Pos, ind, d) do
    {docs, _} = render_docs(content, [:types | state], 0, ind + 2, d)
    trimnlnl([~c"Types:\n", docs])
  end

  defp render_element({:li, attr, content}, [:types | _] = state, pos, ind, c) do
    doc =
      case {:proplists.get_value(:name, attr), :proplists.get_value(:class, attr)} do
        {:undefined, class}
        when class === :undefined or
               class === "type" ->
          render_docs(content, [:type | state], pos, ind, c)

        {_, "description"} ->
          render_docs(content, [:type | state], pos, ind + 2, c)

        {name, _} ->
          case render_type_signature(binary_to_atom(name), c) do
            :undefined when content === [] ->
              {[~c"-type ", name, ~c"() :: term()."], 0}

            :undefined ->
              render_docs(content, [:type | state], pos, ind, c)

            type ->
              {type, 0}
          end
      end

    trimnl(doc)
  end

  defp render_element({:ul, [], content}, state, pos, ind, d) do
    render_docs(content, [:l | state], pos, ind, d)
  end

  defp render_element({:ol, [], content}, state, pos, ind, d) do
    render_docs(content, [:l | state], pos, ind, d)
  end

  defp render_element({:li, [], content}, [:l | _] = state, pos, ind, d) do
    bullet = get_bullet(state, r_config(d, :encoding))
    bulletLen = :string.length(bullet)
    {docs, _NewPos} = render_docs(content, [:li | state], pos + bulletLen, ind + bulletLen, d)
    trimnlnl([bullet, docs])
  end

  defp render_element({:dl, _, content}, state, pos, ind, d) do
    render_docs(content, [:dl | state], pos, ind, d)
  end

  defp render_element({:dt, attr, content}, [:dl | _] = state, pos, ind, d) do
    since =
      case attr do
        [{:since, vsn}] ->
          [~c"     (since ", :unicode.characters_to_list(vsn), ?)]

        [] ->
          []
      end

    underline = sansi(:underline)
    {docs, _NewPos} = render_docs(content, [:li | state], pos, ind, d)
    {[underline, docs, ransi(:underline), ?:, since, ?\n], 0}
  end

  defp render_element({:dd, _, content}, [:dl | _] = state, pos, ind, d) do
    trimnlnl(render_docs(content, [:li | state], pos, ind + 2, d))
  end

  defp render_element(b, state, pos, ind, d) when is_binary(b) do
    case :lists.member(:pre, state) do
      true ->
        pre = :string.replace(b, ~c"\n", [nlpad(ind)], :all)
        {pre, pos + lastline(pre)}

      _ ->
        render_words(split_to_words(b), state, pos, ind, [[]], d)
    end
  end

  defp render_element({tag, attr, content}, state, pos, ind, d) do
    case :lists.member(
           tag,
           [
             :a,
             :p,
             :div,
             :br,
             :h1,
             :h2,
             :h3,
             :h4,
             :h5,
             :h6,
             :i,
             :b,
             :em,
             :strong,
             :pre,
             :code,
             :ul,
             :ol,
             :li,
             :dl,
             :dt,
             :dd
           ]
         ) do
      true ->
        throw({:unhandled_element, tag, attr, content})

      false ->
        :ok
    end

    render_docs(content, state, pos, ind, d)
  end

  defp render_words(words, [_, :types | state], pos, ind, acc, d) do
    render_words(words, state, pos, ind + 2, acc, d)
  end

  defp render_words([unicodeWord | t], state, pos, ind, acc, r_config(columns: cols) = d)
       when is_binary(unicodeWord) do
    word = translate(unicodeWord, d)
    wordLength = :string.length(word)
    newPos = wordLength + pos
    isPunct = :re.run(word, ~c"^\\W$", [:unicode]) !== :nomatch

    cond do
      newPos > cols - 10 - ind and word !== <<>> and
          not isPunct ->
        render_words(t, state, wordLength + ind + 1, ind, [[[nlpad(ind), word]] | acc], d)

      true ->
        [line | lineAcc] = acc
        newPosSpc = newPos + 1
        render_words(t, state, newPosSpc, ind, [[word | line] | lineAcc], d)
    end
  end

  defp render_words([], _State, pos, _Ind, acc, _D) do
    lines =
      :lists.map(
        fn revLine ->
          line = :lists.reverse(revLine)
          :lists.join(?\s, line)
        end,
        :lists.reverse(acc)
      )

    {:erlang.iolist_to_binary(lines), pos}
  end

  defp translate(unicodeWord, r_config(encoding: :unicode)) do
    unicodeWord
  end

  defp translate(unicodeWord, r_config(encoding: :latin1)) do
    :string.replace(unicodeWord, [160], ~c" ", :all)
  end

  defp render_type_signature(
         name,
         r_config(docs: r_docs_v1(metadata: %{types: allTypes}))
       ) do
    case (for type = {tName, _} <- :maps.keys(allTypes),
              tName === name do
            type
          end) do
      [] ->
        :undefined

      types ->
        for type <- types do
          :erl_pp.attribute(:maps.get(type, allTypes))
        end
    end
  end

  defp pad(n) do
    pad(n, ~c"")
  end

  defp nlpad(n) do
    pad(n, ~c"\n")
  end

  defp pad(n, extra) do
    pad = :lists.duplicate(n, ~c" ")

    case ansi() do
      :undefined ->
        [extra, pad]

      ansi ->
        [~c"\e[0m", extra, pad, ansi]
    end
  end

  defp get_bullet(_State, :latin1) do
    " * "
  end

  defp get_bullet(state, :unicode) do
    case length(
           for :l <- state do
             :l
           end
         ) do
      level when level > 4 ->
        get_bullet(state, :latin1)

      level ->
        :lists.nth(
          level,
          [<<" â\200¢ "::utf8>>, <<" ï¿® "::utf8>>, <<" â\227¼ "::utf8>>, <<" â\227» "::utf8>>]
        )
    end
  end

  defp lastline(str) do
    lastStr =
      case :string.find(str, ~c"\n", :trailing) do
        :nomatch ->
          str

        match ->
          tl(:string.next_codepoint(match))
      end

    :string.length(lastStr)
  end

  defp split_to_words(b) do
    :binary.split(b, [" "], [:global])
  end

  defp trimnlnl({chars, _Pos}) do
    nl(nl(:string.trim(chars, :trailing, ~c"\n")))
  end

  defp trimnlnl(chars) do
    nl(nl(:string.trim(chars, :trailing, ~c"\n")))
  end

  defp trimnl({chars, _Pos}) do
    nl(:string.trim(chars, :trailing, ~c"\n"))
  end

  defp nl({chars, _Pos}) do
    nl(chars)
  end

  defp nl(chars) do
    {[chars, ~c"\n"], 0}
  end

  defp init_ansi(r_config(ansi: :undefined, io_opts: opts)) do
    case {:application.get_env(:kernel, :shell_docs_ansi),
          :proplists.get_value(:terminal, opts, false),
          :proplists.is_defined(
            :echo,
            opts
          ) and
            :proplists.is_defined(
              :expand_fun,
              opts
            )} do
      {{:ok, false}, _, _} ->
        :erlang.put(:ansi, :noansi)

      {{:ok, true}, _, _} ->
        :erlang.put(:ansi, [])

      {_, true, _} ->
        :erlang.put(:ansi, [])

      {_, _, true} ->
        :erlang.put(:ansi, [])

      {_, _, false} ->
        :erlang.put(:ansi, :noansi)
    end
  end

  defp init_ansi(r_config(ansi: true)) do
    :erlang.put(:ansi, [])
  end

  defp init_ansi(r_config(ansi: false)) do
    :erlang.put(:ansi, :noansi)
  end

  defp clean_ansi() do
    case :erlang.get(:ansi) do
      [] ->
        :erlang.erase(:ansi)

      :noansi ->
        :erlang.erase(:ansi)
    end

    :ok
  end

  defp sansi(type) do
    sansi(type, :erlang.get(:ansi))
  end

  defp sansi(_Type, :noansi) do
    []
  end

  defp sansi(type, curr) do
    :erlang.put(:ansi, [type | curr])
    ansi(:erlang.get(:ansi))
  end

  defp ransi(type) do
    ransi(type, :erlang.get(:ansi))
  end

  defp ransi(_Type, :noansi) do
    []
  end

  defp ransi(type, curr) do
    :erlang.put(:ansi, :proplists.delete(type, curr))

    case ansi(:erlang.get(:ansi)) do
      :undefined ->
        ~c"\e[0m"

      ansi ->
        ansi
    end
  end

  defp ansi() do
    ansi(:erlang.get(:ansi))
  end

  defp ansi(:noansi) do
    :undefined
  end

  defp ansi(curr) do
    case :lists.usort(curr) do
      [] ->
        :undefined

      [:bold] ->
        ~c"\e[;1m"

      [:underline] ->
        ~c"\e[;;4m"

      [:bold, :underline] ->
        ~c"\e[;1;4m"
    end
  end
end
