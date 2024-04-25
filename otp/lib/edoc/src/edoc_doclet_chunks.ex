defmodule :m_edoc_doclet_chunks do
  use Bitwise
  import :edoc_report, only: [report: 2]
  require Record
  Record.defrecord(:r_doclet_context, :doclet_context, dir: '',
                                          env: :undefined, opts: [])
  Record.defrecord(:r_doclet_gen, :doclet_gen, sources: [],
                                      app: :no_app, modules: [])
  Record.defrecord(:r_doclet_toc, :doclet_toc, paths: :undefined,
                                      indir: :undefined)
  Record.defrecord(:r_xmlDecl, :xmlDecl, vsn: :undefined,
                                   encoding: :undefined, standalone: :undefined,
                                   attributes: :undefined)
  Record.defrecord(:r_xmlAttribute, :xmlAttribute, name: :undefined,
                                        expanded_name: [], nsinfo: [],
                                        namespace: [], parents: [],
                                        pos: :undefined, language: [],
                                        value: :undefined,
                                        normalized: :undefined)
  Record.defrecord(:r_xmlNamespace, :xmlNamespace, default: [],
                                        nodes: [])
  Record.defrecord(:r_xmlNsNode, :xmlNsNode, parents: [],
                                     pos: :undefined, prefix: :undefined,
                                     uri: [])
  Record.defrecord(:r_xmlElement, :xmlElement, name: :undefined,
                                      expanded_name: [], nsinfo: [],
                                      namespace: :EFE_TODO_NESTED_RECORD,
                                      parents: [], pos: :undefined,
                                      attributes: [], content: [], language: '',
                                      xmlbase: '', elementdef: :undeclared)
  Record.defrecord(:r_xmlText, :xmlText, parents: [],
                                   pos: :undefined, language: [],
                                   value: :undefined, type: :text)
  Record.defrecord(:r_xmlComment, :xmlComment, parents: [],
                                      pos: :undefined, language: [],
                                      value: :undefined)
  Record.defrecord(:r_xmlPI, :xmlPI, name: :undefined,
                                 parents: [], pos: :undefined,
                                 value: :undefined)
  Record.defrecord(:r_xmlDocument, :xmlDocument, content: :undefined)
  Record.defrecord(:r_xmlContext, :xmlContext, axis_type: :forward,
                                      context_node: :undefined,
                                      context_position: 1, nodeset: [],
                                      bindings: [], functions: [],
                                      namespace: [], whole_document: :undefined)
  Record.defrecord(:r_xmlNode, :xmlNode, type: :element,
                                   node: :undefined, parents: [], pos: 1)
  Record.defrecord(:r_xmlObj, :xmlObj, type: :undefined,
                                  value: :undefined)
  Record.defrecord(:r_xmerl_fun_states, :xmerl_fun_states, event: :undefined,
                                            hook: :undefined, rules: :undefined,
                                            fetch: :undefined, cont: :undefined)
  Record.defrecord(:r_xmerl_scanner, :xmerl_scanner, encoding: :undefined,
                                         standalone: :no, environment: :prolog,
                                         declarations: [],
                                         doctype_name: :undefined,
                                         doctype_DTD: :internal, comments: true,
                                         document: false, default_attrs: false,
                                         rules: :undefined, keep_rules: false,
                                         namespace_conformant: false,
                                         xmlbase: :undefined,
                                         xmlbase_cache: :undefined,
                                         fetch_path: [],
                                         filename: :file_name_unknown,
                                         validation: :off, schemaLocation: [],
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
                                         text_decl: false, quiet: false, col: 1,
                                         line: 1, common_data: [])
  Record.defrecord(:r_xmerl_event, :xmerl_event, event: :undefined,
                                       line: :undefined, col: :undefined,
                                       pos: :undefined, data: :undefined)
  def run(r_doclet_gen() = cmd, ctxt) do
    gen(r_doclet_gen(cmd, :sources), r_doclet_gen(cmd, :app), r_doclet_gen(cmd, :modules),
          ctxt)
  end

  def run(r_doclet_toc() = _Cmd, _Ctxt) do
    :erlang.error(:not_implemented)
  end

  defp gen(sources, _App, modules, ctxt) do
    dir = :filename.join(r_doclet_context(ctxt, :dir), 'chunks')
    env = r_doclet_context(ctxt, :env)
    options = r_doclet_context(ctxt, :opts)
    case (sources(sources, dir, modules, env, options)) do
      {_, true = _Error} ->
        exit(:error)
      {_, false} ->
        :ok
    end
  end

  defp sources(sources, dir, modules, env, options) do
    suffix = :proplists.get_value(:file_suffix, options, '.chunk')
    {ms, e} = :lists.foldl(fn src, {set, error} ->
                                source(src, dir, suffix, env, set, error,
                                         options)
                           end,
                             {:sets.new(), false}, sources)
    {for m <- modules, :sets.is_element(m, ms) do
       m
     end,
       e}
  end

  defp source({_M, name, path}, dir, suffix, env, okSet,
            errorFlag, options0) do
    file = :filename.join(path, name)
    try do
      requiredChunkOpts = [:return_entries, :private, :hidden]
      options = [{:show_private,
                    :proplists.get_bool(:private,
                                          options0)}] ++ requiredChunkOpts ++ options0
      {_Module, doc, entries} = :edoc.get_doc(file, env,
                                                options)
      chunk = :edoc.layout(doc,
                             [{:entries, entries}, {:source, name} | options])
      writeOptions = [{:encoding, :utf8}]
      :ok = write_file(chunk, dir,
                         chunk_file_name(name, suffix), writeOptions)
      {:sets.add_element(name, okSet), errorFlag}
    catch
      _, _R ->
        :ok
        {okSet, true}
    end
  end

  defp chunk_file_name(erlName, suffix) do
    :string.join([:filename.basename(erlName, '.erl'), suffix],
                   '')
  end

  defp write_file(data, dir, name, _Options) do
    file = :filename.join([dir, name])
    :ok = :filelib.ensure_dir(file)
    case (:file.write_file(file, data)) do
      :ok ->
        :ok
      {:error, r} ->
        r1 = :file.format_error(r)
        report('could not write file \'~ts\': ~ts.', [file, r1])
        exit(:error)
    end
  end

end