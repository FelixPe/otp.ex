defmodule :m_edoc_doclet do
  use Bitwise
  import :edoc_report, only: [report: 2, warning: 2]
  require Record
  Record.defrecord(:r_doclet_context, :doclet_context, dir: ~c"", env: :undefined, opts: [])
  Record.defrecord(:r_doclet_gen, :doclet_gen, sources: [], app: :no_app, modules: [])

  Record.defrecord(:r_doclet_toc, :doclet_toc,
    paths: :undefined,
    indir: :undefined
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

  def run(r_doclet_gen() = cmd, ctxt) do
    gen(r_doclet_gen(cmd, :sources), r_doclet_gen(cmd, :app), r_doclet_gen(cmd, :modules), ctxt)
  end

  def run(r_doclet_toc() = cmd, ctxt) do
    toc(r_doclet_toc(cmd, :paths), ctxt)
  end

  defp gen(sources, app, modules, ctxt) do
    dir = r_doclet_context(ctxt, :dir)
    env = r_doclet_context(ctxt, :env)
    options = r_doclet_context(ctxt, :opts)
    title = title(app, options)
    cSS = stylesheet(options)
    {modules1, error} = sources(sources, dir, modules, env, options)
    modules_frame(dir, modules1, title, cSS, options)
    overview(dir, title, env, options)
    index_file(dir, title)
    :edoc_lib.write_info_file(app, modules1, dir)
    copy_stylesheet(dir, options)
    copy_image(dir)

    case error do
      true ->
        exit(:error)

      false ->
        :ok
    end
  end

  defp title(app, options) do
    :proplists.get_value(
      :title,
      options,
      cond do
        app == :no_app ->
          ~c"Overview"

        true ->
          :io_lib.fwrite(~c"Application: ~ts", [app])
      end
    )
  end

  defp sources(sources, dir, modules, env, options) do
    suffix = :proplists.get_value(:file_suffix, options, ~c".html")
    private = :proplists.get_bool(:private, options)
    hidden = :proplists.get_bool(:hidden, options)

    {ms, e} =
      :lists.foldl(
        fn src, {set, error} ->
          source(src, dir, suffix, env, set, private, hidden, error, options)
        end,
        {:sets.new(), false},
        sources
      )

    {for m <- modules, :sets.is_element(m, ms) do
       m
     end, e}
  end

  defp source({m, name, path}, dir, suffix, env, set, private, hidden, error, options) do
    file = :filename.join(path, name)

    case (try do
            {:ok, :edoc.get_doc(file, env, options)}
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end) do
      {:ok, {module, doc}} ->
        check_name(module, m, file)

        case (not is_private(doc) or private) and (not is_hidden(doc) or hidden) do
          true ->
            text = :edoc.layout(doc, options)
            name1 = :erlang.atom_to_list(m) ++ suffix
            encoding = [{:encoding, encoding(doc)}]
            :edoc_lib.write_file(text, dir, name1, encoding)
            {:sets.add_element(module, set), error}

          false ->
            {set, error}
        end

      r ->
        report(~c"skipping source file '~ts': ~tP.", [file, r, 15])
        {set, true}
    end
  end

  defp check_name(m, m0, file) do
    n = m
    n0 = m0

    case n do
      [?? | _] ->
        :ok

      _ ->
        cond do
          n !== n0 ->
            warning(~c"file '~ts' actually contains module '~s'.", [file, m])

          true ->
            :ok
        end
    end

    :ok
  end

  defp index_file(dir, title) do
    frame2 =
      {:frame, [{:src, ~c"modules-frame.html"}, {:name, ~c"modulesFrame"}, {:title, ~c""}], []}

    frame3 =
      {:frame, [{:src, ~c"overview-summary.html"}, {:name, ~c"overviewFrame"}, {:title, ~c""}],
       []}

    frameset =
      {:frameset, [{:cols, ~c"20%,80%"}],
       [
         ~c"\n",
         frame2,
         ~c"\n",
         ~c"\n",
         frame3,
         ~c"\n",
         {:noframes,
          [
            ~c"\n",
            {:h2, [~c"This page uses frames"]},
            ~c"\n",
            {:p,
             [
               ~c"Your browser does not accept frames.",
               ~c"\n",
               :br,
               ~c"You should go to the ",
               {:a, [{:href, ~c"overview-summary.html"}], [~c"non-frame version"]},
               ~c" instead.",
               ~c"\n"
             ]},
            ~c"\n"
          ]},
         ~c"\n"
       ]}

    xML = xhtml_1(title, [], frameset)
    text = :xmerl.export_simple([xML], :xmerl_html, [])
    :edoc_lib.write_file(text, dir, ~c"index.html")
  end

  defp modules_frame(dir, ms, title, cSS, options) do
    suffix = :proplists.get_value(:file_suffix, options, ~c".html")

    body = [
      ~c"\n",
      {:h2, [{:class, ~c"indextitle"}], [~c"Modules"]},
      ~c"\n",
      {:table, [{:width, ~c"100%"}, {:border, 0}, {:summary, ~c"list of modules"}],
       :lists.append(
         for m <- ms do
           [
             ~c"\n",
             {:tr,
              [
                {:td, [],
                 [
                   {:a,
                    [
                      {:href,
                       module_ref(
                         m,
                         suffix
                       )},
                      {:target, ~c"overviewFrame"},
                      {:class, ~c"module"}
                    ], [:erlang.atom_to_list(m)]}
                 ]}
              ]}
           ]
         end
       )},
      ~c"\n"
    ]

    xML = xhtml(title, cSS, body)
    text = :xmerl.export_simple([xML], :xmerl_html, [])
    :edoc_lib.write_file(text, dir, ~c"modules-frame.html")
  end

  defp module_ref(m, suffix) do
    :erlang.atom_to_list(m) ++ suffix
  end

  defp xhtml(title, cSS, content) do
    xhtml_1(title, cSS, {:body, [{:bgcolor, ~c"white"}], content})
  end

  defp xhtml_1(title, cSS, body) do
    {:html, [~c"\n", {:head, [~c"\n", {:title, [title]}, ~c"\n"] ++ cSS}, ~c"\n", body, ~c"\n"]}
  end

  defp overview(dir, title, env, opts) do
    file = :proplists.get_value(:overview, opts, :filename.join(dir, ~c"overview.edoc"))

    encoding =
      :edoc_lib.read_encoding(
        file,
        [{:in_comment_only, false}]
      )

    tags = read_file(file, :overview, env, opts)
    data0 = :edoc_data.overview(title, tags, env, opts)

    encodingAttribute =
      r_xmlAttribute(
        name: :encoding,
        value: :erlang.atom_to_list(encoding)
      )

    r_xmlElement(attributes: as) = data0
    data = r_xmlElement(data0, attributes: [encodingAttribute | as])

    f = fn m ->
      m.overview(data, opts)
    end

    text = :edoc_lib.run_layout(f, opts)
    encOpts = [{:encoding, encoding}]
    :edoc_lib.write_file(text, dir, ~c"overview-summary.html", encOpts)
  end

  defp copy_image(dir) do
    case :code.priv_dir(:edoc) do
      privDir when is_list(privDir) ->
        from = :filename.join(privDir, ~c"erlang.png")
        :edoc_lib.copy_file(from, :filename.join(dir, ~c"erlang.png"))

      _ ->
        report(~c"cannot find default image file.", [])
        exit(:error)
    end
  end

  defp copy_stylesheet(dir, options) do
    case :proplists.get_value(:stylesheet, options) do
      :undefined ->
        from =
          case :proplists.get_value(
                 :stylesheet_file,
                 options
               ) do
            file when is_list(file) ->
              file

            _ ->
              case :code.priv_dir(:edoc) do
                privDir when is_list(privDir) ->
                  :filename.join(privDir, ~c"stylesheet.css")

                _ ->
                  report(~c"cannot find default stylesheet file.", [])
                  exit(:error)
              end
          end

        :edoc_lib.copy_file(from, :filename.join(dir, ~c"stylesheet.css"))

      _ ->
        :ok
    end
  end

  defp stylesheet(options) do
    case :proplists.get_value(:stylesheet, options) do
      ~c"" ->
        []

      s ->
        ref =
          case s do
            :undefined ->
              ~c"stylesheet.css"

            ~c"" ->
              ~c""

            ^s when is_list(s) ->
              s

            _ ->
              report(~c"bad value for option 'stylesheet'.", [])
              exit(:error)
          end

        [
          {:link,
           [{:rel, ~c"stylesheet"}, {:type, ~c"text/css"}, {:href, ref}, {:title, ~c"EDoc"}], []},
          ~c"\n"
        ]
    end
  end

  defp is_private(e) do
    case get_attrval(:private, e) do
      ~c"yes" ->
        true

      _ ->
        false
    end
  end

  defp is_hidden(e) do
    case get_attrval(:hidden, e) do
      ~c"yes" ->
        true

      _ ->
        false
    end
  end

  defp encoding(e) do
    case get_attrval(:encoding, e) do
      ~c"latin1" ->
        :latin1

      _ ->
        :utf8
    end
  end

  defp get_attrval(name, r_xmlElement(attributes: as)) do
    case get_attr(name, as) do
      [r_xmlAttribute(value: v)] ->
        v

      [] ->
        ~c""
    end
  end

  defp get_attr(name, [r_xmlAttribute(name: name) = a | as]) do
    [a | get_attr(name, as)]
  end

  defp get_attr(name, [_ | as]) do
    get_attr(name, as)
  end

  defp get_attr(_, []) do
    []
  end

  defp read_file(file, context, env, opts) do
    case :edoc_extract.file(file, context, env, opts) do
      {:ok, tags} ->
        tags

      {:error, _} ->
        []
    end
  end

  defp toc(paths, ctxt) do
    opts = r_doclet_context(ctxt, :opts)
    dir = r_doclet_context(ctxt, :dir)
    env = r_doclet_context(ctxt, :env)
    app_index_file(paths, dir, env, opts)
  end

  defp app_index_file(paths, dir, env, options) do
    title = :proplists.get_value(:title, options, ~c"Overview")
    cSS = stylesheet(options)

    apps1 =
      for a <- paths do
        {:filename.dirname(a), :filename.basename(a)}
      end

    index_file(dir, title)
    application_frame(dir, apps1, title, cSS)
    modules_frame(dir, [], title, cSS, options)
    overview(dir, title, env, options)
    copy_stylesheet(dir, options)
  end

  defp application_frame(dir, apps, title, cSS) do
    body = [
      ~c"\n",
      {:h2, [~c"Applications"]},
      ~c"\n",
      {:table, [{:width, ~c"100%"}, {:border, 0}],
       :lists.append(
         for {path, app} <- apps do
           [
             {:tr,
              [
                {:td, [],
                 [
                   {:a,
                    [
                      {:href,
                       app_ref(
                         path,
                         app
                       )},
                      {:target, ~c"_top"}
                    ], [app]}
                 ]}
              ]}
           ]
         end
       )},
      ~c"\n"
    ]

    xML = xhtml(title, cSS, body)
    text = :xmerl.export_simple([xML], :xmerl_html, [])
    :edoc_lib.write_file(text, dir, ~c"modules-frame.html")
  end

  defp app_ref(path, m) do
    :filename.join([path, m, ~c"doc", ~c"index.html"])
  end
end
