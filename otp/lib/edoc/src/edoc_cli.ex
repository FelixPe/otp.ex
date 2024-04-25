defmodule :m_edoc_cli do
  use Bitwise

  def main([]) do
    print(usage())
  end

  def main(args) do
    opts = parse_args(args)
    print(~c"Running with opts:\n~p\n", [opts])
    :ok = :code.add_pathsa(:maps.get(:code_paths, opts))

    case opts do
      %{run: :app, app: app} ->
        :edoc.application(app, edoc_opts(opts))

      %{run: :files, files: files} ->
        :edoc.files(files, edoc_opts(opts))
    end
  end

  defp parse_args(args) do
    init = %{
      mode: :default,
      run: :app,
      app: :no_app,
      files: [],
      code_paths: [],
      out_dir: :undefined,
      include_paths: [],
      continue: false
    }

    check_opts(
      :maps.without(
        [:continue],
        parse_args(args, init)
      )
    )
  end

  defp parse_args([], opts) do
    opts
  end

  defp parse_args([~c"-" ++ _ = arg | args], %{continue: cont} = opts)
       when cont != false do
    parse_args([arg | args], %{opts | continue: false})
  end

  defp parse_args([~c"-chunks" | args], opts) do
    parse_args(args, %{opts | mode: :chunks})
  end

  defp parse_args([~c"-o", outDir | args], opts) do
    parse_args(args, %{opts | out_dir: outDir})
  end

  defp parse_args([~c"-pa", path | args], opts) do
    %{code_paths: paths} = opts
    parse_args(args, %{opts | code_paths: paths ++ [path]})
  end

  defp parse_args([~c"-I", path | args], opts) do
    %{include_paths: paths} = opts

    parse_args(
      args,
      %{opts | include_paths: paths ++ [path]}
    )
  end

  defp parse_args([~c"-app", app | args], opts) do
    parse_args(
      args,
      %{opts | run: :app, app: :erlang.list_to_atom(app)}
    )
  end

  defp parse_args([~c"-files" | args], opts) do
    parse_args(
      args,
      %{opts | run: :files, continue: :files}
    )
  end

  defp parse_args([file | args], %{continue: :files} = opts) do
    %{files: files} = opts
    parse_args(args, %{opts | files: files ++ [file]})
  end

  defp parse_args([unknown | args], opts) do
    print(~c"Unknown option: ~ts\n", [unknown])
    parse_args(args, opts)
  end

  defp check_opts(opts) do
    case opts do
      %{run: :app, app: app}
      when is_atom(app) and
             app != :no_app ->
        :ok

      %{run: :app, app: :no_app} ->
        quit(:no_app, opts)

      %{run: :files, files: [_ | _]} ->
        :ok

      %{run: :files, files: []} ->
        quit(:no_files, opts)
    end

    %{mode: mode, out_dir: outDir, code_paths: codePaths, include_paths: includePaths} = opts

    :lists.member(
      mode,
      [:default, :chunks]
    ) or :erlang.error(:mode, opts)

    cond do
      is_list(outDir) ->
        :ok

      outDir === :undefined ->
        :ok

      outDir !== :undefined ->
        :erlang.error(:out_dir, opts)
    end

    is_list(codePaths) or :erlang.error(:code_paths)
    is_list(includePaths) or :erlang.error(:include_paths)
    opts
  end

  defp quit(reason, _Opts) do
    case reason do
      :no_app ->
        print(~c"No app name specified\n")

      :no_files ->
        print(~c"No files to process\n")
    end

    print(~c"\n")
    print(usage())
    :erlang.halt(1)
  end

  defp edoc_opts(opts) do
    edocOpts =
      case :maps.get(:mode, opts) do
        :default ->
          [{:preprocess, true}]

        :chunks ->
          [{:doclet, :edoc_doclet_chunks}, {:layout, :edoc_layout_chunks}, {:preprocess, true}]
      end

    outDir = :maps.get(:out_dir, opts)

    [
      {:includes, :maps.get(:include_paths, opts)}
      | edocOpts
    ] ++
      for _ <- [:EFE_DUMMY_GEN],
          outDir != :undefined do
        {:dir, outDir}
      end
  end

  defp print(text) do
    print(text, [])
  end

  defp print(fmt, args) do
    :io.format(fmt, args)
  end

  defp usage() do
    ~c"Usage: edoc [options] -app App\n       edoc [options] -files Source...\n\nRun EDoc from the command line:\n  -app App       \truns edoc:application/2; App is the application name\n  -files Sources \truns edoc:files/2; Sources are .erl files\n\nOptions:\n  -chunks        \twhen present, only doc chunks are generated\n  -o Dir         \tuse Dir for doc output\n  -I IncPath     \tadd IncPath to EDoc include file search path;\n                 \tcan be used multiple times\n  -pa CodePath   \tadd CodePath to Erlang code path; can be used multiple times\n"
  end
end
