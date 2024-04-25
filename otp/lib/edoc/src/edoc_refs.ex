defmodule :m_edoc_refs do
  use Bitwise
  import Kernel, except: [to_string: 1]
  import :edoc_lib, only: [escape_uri: 1, join_uri: 2]
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

  def app(app) do
    {:app, app}
  end

  def app(app, ref) do
    {:app, app, ref}
  end

  def module(m) do
    {:module, m}
  end

  def module(m, ref) do
    {:module, m, ref}
  end

  def module(app, m, ref) do
    app(app, module(m, ref))
  end

  def function(f, a) do
    {:function, f, a}
  end

  def function(m, f, a) do
    module(m, function(f, a))
  end

  def function(app, m, f, a) do
    module(app, m, function(f, a))
  end

  def type(t) do
    {:type, t}
  end

  def type(m, t) do
    module(m, type(t))
  end

  def type(app, m, t) do
    module(app, m, type(t))
  end

  def to_string({:app, a}) do
    ~c"//" ++ :erlang.atom_to_list(a)
  end

  def to_string({:app, a, ref}) do
    ~c"//" ++ :erlang.atom_to_list(a) ++ ~c"/" ++ to_string(ref)
  end

  def to_string({:module, m}) do
    :erlang.atom_to_list(m)
  end

  def to_string({:module, m, ref}) do
    :erlang.atom_to_list(m) ++ ~c":" ++ to_string(ref)
  end

  def to_string({:function, f, a}) do
    :erlang.atom_to_list(f) ++ ~c"/" ++ :erlang.integer_to_list(a)
  end

  def to_string({:type, t}) do
    :erlang.atom_to_list(t) ++ ~c"()"
  end

  def to_label({:function, f, a}) do
    escape_uri(:erlang.atom_to_list(f)) ++ ~c"-" ++ :erlang.integer_to_list(a)
  end

  def to_label({:type, t}) do
    ~c"type-" ++ escape_uri(:erlang.atom_to_list(t))
  end

  def get_docgen_link({:app, _} = ref) do
    {:seeapp, docgen_uri(ref)}
  end

  def get_docgen_link({:app, _, innerRef} = ref) do
    {rel, _} = get_docgen_link(innerRef)
    {rel, docgen_uri(ref)}
  end

  def get_docgen_link({:module, _, innerRef} = ref) do
    {rel, _} = get_docgen_link(innerRef)
    {rel, docgen_uri(ref)}
  end

  def get_docgen_link({:module, _} = ref) do
    {:seeerl, docgen_uri(ref)}
  end

  def get_docgen_link({:function, _, _} = ref) do
    {:seemfa, docgen_uri(ref)}
  end

  def get_docgen_link({:type, _} = ref) do
    {:seetype, docgen_uri(ref)}
  end

  defp docgen_uri({:app, a}) do
    [:erlang.atom_to_list(a), ~c":index"]
  end

  defp docgen_uri({:app, a, ref}) do
    [:erlang.atom_to_list(a), ~c":", docgen_uri(ref)]
  end

  defp docgen_uri({:module, m}) do
    :erlang.atom_to_list(m)
  end

  defp docgen_uri({:module, m, ref}) do
    [:erlang.atom_to_list(m), docgen_uri(ref)]
  end

  defp docgen_uri({:function, f, a}) do
    [~c"#", :erlang.atom_to_list(f), ~c"/", :erlang.integer_to_list(a)]
  end

  defp docgen_uri({:type, t}) do
    [~c"#", :erlang.atom_to_list(t), ~c"/0"]
  end

  defp docgen_uri({:type, t, a}) do
    [~c"#", :erlang.atom_to_list(t), ~c"/", :erlang.integer_to_list(a)]
  end

  def get_uri({:app, app}, env) do
    join_uri(app_ref(app, env), ~c"index.html")
  end

  def get_uri({:app, app, ref}, env) do
    app_ref(app, ref, env)
  end

  def get_uri({:module, m, ref}, env) do
    module_ref(m, env) ++ ~c"#" ++ to_label(ref)
  end

  def get_uri({:module, m}, env) do
    module_ref(m, env)
  end

  def get_uri(ref, _Env) do
    ~c"#" ++ to_label(ref)
  end

  defp abs_uri({:module, m}, env) do
    module_absref(m, env)
  end

  defp abs_uri({:module, m, ref}, env) do
    module_absref(m, env) ++ ~c"#" ++ to_label(ref)
  end

  defp module_ref(m, env) do
    case r_env(env, :modules).(m) do
      ~c"" ->
        file = :erlang.atom_to_list(m) ++ r_env(env, :file_suffix)
        escape_uri(file)

      base ->
        join_uri(base, module_absref(m, env))
    end
  end

  defp module_absref(m, env) do
    escape_uri(:erlang.atom_to_list(m)) ++ escape_uri(r_env(env, :file_suffix))
  end

  defp app_ref(a, env) do
    case r_env(env, :apps).(a) do
      ~c"" ->
        join_uri(
          r_env(env, :app_default),
          join_uri(escape_uri(:erlang.atom_to_list(a)), ~c"doc")
        )

      base ->
        base
    end
  end

  defp app_ref(a, ref, env) do
    join_uri(app_ref(a, env), abs_uri(ref, env))
  end

  def is_top({:app, _App}, _Env) do
    true
  end

  def is_top(_Ref, _Env) do
    false
  end
end
