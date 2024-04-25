defmodule :m_typer do
  use Bitwise
  def start() do
    _ = :io.setopts(:standard_error,
                      [{:encoding, :unicode}])
    _ = :io.setopts([{:encoding, :unicode}])
    :ok = :typer_core.run(process_cl_args())
    :erlang.halt(0)
  end

  defp process_cl_args() do
    argList = :init.get_plain_arguments()
    opts = analyze_args(argList, %{})
    case (opts) do
      %{mode: _} ->
        opts
      ^opts ->
        Map.put(opts, :mode, :show)
    end
  end

  defp analyze_args([], opts) do
    opts
  end

  defp analyze_args(argList, opts) do
    {result, rest} = cl(argList)
    newOpts = analyze_result(result, opts)
    analyze_args(rest, newOpts)
  end

  defp cl(['-h' | _]) do
    help_message()
  end

  defp cl(['--help' | _]) do
    help_message()
  end

  defp cl(['-v' | _]) do
    version_message()
  end

  defp cl(['--version' | _]) do
    version_message()
  end

  defp cl(['--edoc' | opts]) do
    {:edoc, opts}
  end

  defp cl(['--show' | opts]) do
    {{:mode, :show}, opts}
  end

  defp cl(['--show_exported' | opts]) do
    {{:mode, :show_exported}, opts}
  end

  defp cl(['--show-exported' | opts]) do
    {{:mode, :show_exported}, opts}
  end

  defp cl(['--show_success_typings' | opts]) do
    {:show_succ, opts}
  end

  defp cl(['--show-success-typings' | opts]) do
    {:show_succ, opts}
  end

  defp cl(['--annotate' | opts]) do
    {{:mode, :annotate}, opts}
  end

  defp cl(['--annotate-inc-files' | opts]) do
    {{:mode, :annotate_inc_files}, opts}
  end

  defp cl(['--annotate-in-place' | opts]) do
    {{:mode, :annotate_in_place}, opts}
  end

  defp cl(['--no_spec' | opts]) do
    {:no_spec, opts}
  end

  defp cl(['--plt', plt | opts]) do
    {{:plt, plt}, opts}
  end

  defp cl(['-D' | _Opts]) do
    fatal_error('no variable name specified after -D')
  end

  defp cl(['-D' ++ def__ | opts]) do
    defPair = process_def_list(:re.split(def__, '=',
                                           [{:return, :list}, :unicode]))
    {{:def, defPair}, opts}
  end

  defp cl(['-I', dir | opts]) do
    {{:inc, dir}, opts}
  end

  defp cl(['-I' | _Opts]) do
    fatal_error('no include directory specified after -I')
  end

  defp cl(['-I' ++ dir | opts]) do
    {{:inc, dir}, opts}
  end

  defp cl(['-T' | opts]) do
    {files, restOpts} = collect_args(opts)
    case (files) do
      [] ->
        fatal_error('no file or directory specified after -T')
      [_ | _] ->
        {{:trusted, files}, restOpts}
    end
  end

  defp cl(['-r' | opts]) do
    {files, restOpts} = collect_args(opts)
    {{:files_r, files}, restOpts}
  end

  defp cl(['-pa', dir | opts]) do
    {{:pa, dir}, opts}
  end

  defp cl(['-pz', dir | opts]) do
    {{:pz, dir}, opts}
  end

  defp cl(['-' ++ h | _]) do
    fatal_error('unknown option -' ++ h)
  end

  defp cl(opts) do
    {files, restOpts} = collect_args(opts)
    {{:files, files}, restOpts}
  end

  defp collect_args(list) do
    collect_args_1(list, [])
  end

  defp collect_args_1(['-' ++ _ | _] = l, acc) do
    {:lists.reverse(acc), l}
  end

  defp collect_args_1([arg | t], acc) do
    collect_args_1(t, [arg | acc])
  end

  defp collect_args_1([], acc) do
    {:lists.reverse(acc), []}
  end

  defp process_def_list(l) do
    case (l) do
      [name, value] ->
        {:ok, tokens, _} = :erl_scan.string(value ++ '.')
        {:ok, erlValue} = :erl_parse.parse_term(tokens)
        {:erlang.list_to_atom(name), erlValue}
      [name] ->
        {:erlang.list_to_atom(name), true}
    end
  end

  defp analyze_result({:files, val}, opts) do
    append_in_map(:files, val, opts)
  end

  defp analyze_result({:files_r, val}, opts) do
    append_in_map(:files_r, val, opts)
  end

  defp analyze_result({:trusted, val}, opts) do
    append_in_map(:trusted, val, opts)
  end

  defp analyze_result(:edoc, opts) do
    Map.put(opts, :edoc, true)
  end

  defp analyze_result({:mode, mode}, %{mode: oldMode}) do
    mode_error(oldMode, mode)
  end

  defp analyze_result({:mode, mode}, opts) do
    Map.put(opts, :mode, mode)
  end

  defp analyze_result({:def, val}, opts) do
    append_in_map(:macros, [val], opts)
  end

  defp analyze_result({:inc, val}, opts) do
    append_in_map(:includes, [val], opts)
  end

  defp analyze_result({:plt, plt}, opts) do
    Map.put(opts, :plt, plt)
  end

  defp analyze_result(:show_succ, opts) do
    Map.put(opts, :show_succ, true)
  end

  defp analyze_result(:no_spec, opts) do
    Map.put(opts, :no_spec, true)
  end

  defp analyze_result({:pa, dir}, opts) do
    true = :code.add_patha(dir)
    opts
  end

  defp analyze_result({:pz, dir}, opts) do
    true = :code.add_pathz(dir)
    opts
  end

  defp append_in_map(key, list, map) do
    :maps.update_with(key,
                        fn l ->
                             l ++ list
                        end,
                        list, map)
  end

  defp fatal_error(slogan) do
    msg(:io_lib.format('typer: ~ts\n', [slogan]))
    :erlang.halt(1)
  end

  defp mode_error(oldMode, newMode) do
    msg = :io_lib.format('Mode was previously set to \'~s\'; cannot set it to \'~s\' now', [oldMode, newMode])
    fatal_error(msg)
  end

  defp msg(msg) do
    :io.format(:standard_error, '~ts', [msg])
  end

  defp version_message() do
    :io.format('TypEr version ' ++ :EFE_TODO_VSN_MACRO ++ '\n')
    :erlang.halt(0)
  end

  defp help_message() do
    s = " Usage: typer [--help] [--version] [--plt PLT] [--edoc]\n              [--show | --show-exported | --annotate | --annotate-inc-files | --annotate-in-place]\n              [-Ddefine]* [-I include_dir]* [-pa dir]* [-pz dir]*\n              [-T application]* [-r] file*\n\n Options:\n   -r dir*\n       search directories recursively for .erl files below them\n   --show\n       Prints type specifications for all functions on stdout.\n       (this is the default behaviour; this option is not really needed)\n   --show-exported (or --show_exported)\n       Same as --show, but prints specifications for exported functions only\n       Specs are displayed sorted alphabetically on the function's name\n   --annotate\n       Annotates the specified files with type specifications and writes\n       the resulting files into a new typer_ann folder.\n   --annotate-inc-files\n       Same as --annotate but annotates all -include() files as well as\n       all .erl files\n   --annotate-in-place\n       Annotate directly on the source code files, instead of dumping the\n       annotated files in a different directory\n   --edoc\n       Prints type information as Edoc @spec comments, not as type specs\n   --plt PLT\n       Use the specified dialyzer PLT file rather than the default one\n       (Incremental and non-incremental PLT files are supported)\n   -T file*\n       The specified file(s) already contain type specifications and these\n       are to be trusted in order to print specs for the rest of the files\n       (Multiple files or dirs, separated by spaces, can be specified.)\n   -Dname (or -Dname=value)\n       pass the defined name(s) to TypEr\n       (The syntax of defines is the same as that used by \"erlc\".)\n   -I include_dir\n       pass the include_dir to TypEr\n       (The syntax of includes is the same as that used by \"erlc\".)\n   -pa dir\n   -pz dir\n       Set code path options to TypEr\n       (This is useful for files that use parse transforms.)\n   --version (or -v)\n       prints the Typer version and exits\n   --help (or -h)\n       prints this message and exits\n\n Note:\n   * denotes that multiple occurrences of these options are possible.\n"
    :io.put_chars(s)
    :erlang.halt(0)
  end

end