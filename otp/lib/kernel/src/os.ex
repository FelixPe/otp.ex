defmodule :m_os do
  use Bitwise
  require Record

  Record.defrecord(:r_file_info, :file_info,
    size: :undefined,
    type: :undefined,
    access: :undefined,
    atime: :undefined,
    mtime: :undefined,
    ctime: :undefined,
    mode: :undefined,
    links: :undefined,
    major_device: :undefined,
    minor_device: :undefined,
    inode: :undefined,
    uid: :undefined,
    gid: :undefined
  )

  Record.defrecord(:r_file_descriptor, :file_descriptor,
    module: :undefined,
    data: :undefined
  )

  def env() do
    :erlang.nif_error(:undef)
  end

  def getenv(_VarName) do
    :erlang.nif_error(:undef)
  end

  def getpid() do
    :erlang.nif_error(:undef)
  end

  def perf_counter() do
    :erlang.nif_error(:undef)
  end

  def perf_counter(unit) do
    try do
      :erlang.convert_time_unit(:os.perf_counter(), :perf_counter, unit)
    catch
      :error, _ ->
        badarg_with_info([unit])
    end
  end

  def putenv(_VarName, _Value) do
    :erlang.nif_error(:undef)
  end

  def system_time() do
    :erlang.nif_error(:undef)
  end

  def system_time(_Unit) do
    :erlang.nif_error(:undef)
  end

  def timestamp() do
    :erlang.nif_error(:undef)
  end

  def unsetenv(_VarName) do
    :erlang.nif_error(:undef)
  end

  def set_signal(_Signal, _Option) do
    :erlang.nif_error(:undef)
  end

  def getenv() do
    for {key, value} <- :os.env() do
      :lists.flatten([key, ?=, value])
    end
  end

  def getenv(varName, defaultValue) do
    try do
      :os.getenv(varName)
    catch
      :error, _ ->
        badarg_with_info([varName, defaultValue])
    else
      false ->
        defaultValue

      value ->
        value
    end
  end

  def type() do
    :erlang.system_info(:os_type)
  end

  def version() do
    :erlang.system_info(:os_version)
  end

  def find_executable(name) do
    find_executable(name, :os.getenv(~c"PATH", ~c""))
  end

  def find_executable(name, path) do
    extensions = extensions()

    case :filename.pathtype(name) do
      :relative ->
        find_executable1(name, split_path(path), extensions)

      _ ->
        case verify_executable(name, extensions, extensions) do
          {:ok, complete} ->
            complete

          :error ->
            false
        end
    end
  end

  defp find_executable1(name, [base | rest], extensions) do
    complete0 = :filename.join(base, name)

    case verify_executable(complete0, extensions, extensions) do
      {:ok, complete} ->
        complete

      :error ->
        find_executable1(name, rest, extensions)
    end
  end

  defp find_executable1(_Name, [], _Extensions) do
    false
  end

  defp verify_executable(name0, [ext | rest], origExtensions) do
    name1 = name0 ++ ext

    case :file.read_file_info(name1) do
      {:ok, r_file_info(type: :regular, mode: mode)}
      when mode &&& 73 !== 0 ->
        {:ok, name1}

      _ ->
        verify_executable(name0, rest, origExtensions)
    end
  end

  defp verify_executable(name, [], origExtensions)
       when origExtensions !== [~c""] do
    case can_be_full_name(
           :string.lowercase(name),
           origExtensions
         ) do
      true ->
        verify_executable(name, [~c""], [~c""])

      _ ->
        :error
    end
  end

  defp verify_executable(_, [], _) do
    :error
  end

  defp can_be_full_name(_Name, []) do
    false
  end

  defp can_be_full_name(name, [h | t]) do
    case :lists.suffix(h, name) do
      true ->
        true

      _ ->
        can_be_full_name(name, t)
    end
  end

  defp split_path(path) do
    case type() do
      {:win32, _} ->
        {:ok, curr} = :file.get_cwd()
        split_path(path, ?;, [], [curr])

      _ ->
        split_path(path, ?:, [], [])
    end
  end

  defp split_path([sep | rest], sep, current, path) do
    split_path(rest, sep, [], [reverse_element(current) | path])
  end

  defp split_path([c | rest], sep, current, path) do
    split_path(rest, sep, [c | current], path)
  end

  defp split_path([], _, current, path) do
    :lists.reverse(path, [reverse_element(current)])
  end

  defp reverse_element([]) do
    ~c"."
  end

  defp reverse_element([?" | t]) do
    case :lists.reverse(t) do
      [?" | list] ->
        list

      list ->
        list ++ [?"]
    end
  end

  defp reverse_element(list) do
    :lists.reverse(list)
  end

  defp extensions() do
    case type() do
      {:win32, _} ->
        [~c".exe", ~c".com", ~c".cmd", ~c".bat"]

      {:unix, _} ->
        [~c""]
    end
  end

  def cmd(cmd) do
    try do
      do_cmd(cmd, %{})
    catch
      {:open_port, reason} ->
        badarg_with_cause([cmd], {:open_port, reason})

      :badarg ->
        badarg_with_info([cmd])
    end
  end

  def cmd(cmd, opts) do
    try do
      do_cmd(cmd, opts)
    catch
      :badopt ->
        badarg_with_cause([cmd, opts], :badopt)

      {:open_port, reason} ->
        badarg_with_cause([cmd, opts], {:open_port, reason})

      :badarg ->
        badarg_with_info([cmd, opts])
    end
  end

  defp do_cmd(cmd, opts) do
    maxSize = get_option(:max_size, opts, :infinity)
    {spawnCmd, spawnOpts, spawnInput, eot} = mk_cmd(:os.type(), validate(cmd))

    port =
      try do
        :erlang.open_port(
          {:spawn, spawnCmd},
          [
            :binary,
            :stderr_to_stdout,
            :stream,
            :in,
            :hide
            | spawnOpts
          ]
        )
      catch
        :error, reason ->
          throw({:open_port, reason})
      end

    monRef = :erlang.monitor(:port, port)
    true = :erlang.port_command(port, spawnInput)
    bytes = get_data(port, monRef, eot, [], 0, maxSize)
    :erlang.demonitor(monRef, [:flush])
    string = :unicode.characters_to_list(bytes)

    cond do
      is_list(string) ->
        string

      true ->
        :erlang.binary_to_list(bytes)
    end
  end

  defp get_option(opt, options, default) do
    case options do
      %{^opt => value} ->
        value

      %{} ->
        default

      _ ->
        throw(:badopt)
    end
  end

  defp mk_cmd({:win32, wtype}, cmd) do
    command =
      case {:os.getenv(~c"COMSPEC"), wtype} do
        {false, :windows} ->
          :lists.concat([~c"command.com /c", cmd])

        {false, _} ->
          :lists.concat([~c"cmd /c", cmd])

        {cspec, _} ->
          :lists.concat([cspec, ~c" /c", cmd])
      end

    {command, [], [], <<>>}
  end

  defp mk_cmd(_, cmd) do
    shell =
      case :file.read_file_info(~c"/bin/sh", [:raw]) do
        {:ok, r_file_info(type: :regular)} ->
          ~c"/bin/sh"

        _ ->
          case :file.read_file_info(~c"/system/bin/sh", [:raw]) do
            {:ok, r_file_info(type: :regular)} ->
              ~c"/system/bin/sh"

            _ ->
              ~c"/bin/sh"
          end
      end

    {shell ++ ~c" -s unix:cmd", [:out],
     [~c"(", :unicode.characters_to_binary(cmd), ~c"\n) </dev/null; echo \"\004\"\n"], <<4>>}
  end

  defp validate(term) do
    try do
      validate1(term)
    catch
      :error, _ ->
        throw(:badarg)
    end
  end

  defp validate1(atom) when is_atom(atom) do
    validate1(:erlang.atom_to_list(atom))
  end

  defp validate1(list) when is_list(list) do
    case validate2(list) do
      false ->
        list

      true ->
        :string.trim(list, :trailing, [0])
    end
  end

  defp validate2([0 | rest]) do
    validate3(rest)
  end

  defp validate2([c | rest]) when is_integer(c) and c > 0 do
    validate2(rest)
  end

  defp validate2([list | rest]) when is_list(list) do
    :erlang.or(validate2(list), validate2(rest))
  end

  defp validate2([]) do
    false
  end

  defp validate3([]) do
    true
  end

  defp validate3([0 | rest]) do
    validate3(rest)
  end

  defp validate3([list | rest]) when is_list(list) do
    validate3(list)
    validate3(rest)
  end

  defp get_data(port, monRef, eot, sofar, size, max) do
    receive do
      {^port, {:data, bytes}} ->
        case eot(bytes, eot, size, max) do
          :more ->
            get_data(port, monRef, eot, [sofar, bytes], size + byte_size(bytes), max)

          last ->
            try do
              :erlang.port_close(port)
            catch
              :error, e -> {:EXIT, {e, __STACKTRACE__}}
              :exit, e -> {:EXIT, e}
              e -> e
            end

            flush_until_down(port, monRef)
            :erlang.iolist_to_binary([sofar, last])
        end

      {:DOWN, ^monRef, _, _, _} ->
        flush_exit(port)
        :erlang.iolist_to_binary(sofar)
    end
  end

  defp eot(bs, <<>>, size, max)
       when size + byte_size(bs) < max do
    :more
  end

  defp eot(bs, <<>>, size, max) do
    :binary.part(bs, {0, max - size})
  end

  defp eot(bs, eot, size, max) do
    case :binary.match(bs, eot) do
      {pos, _} when size + pos < max ->
        :binary.part(bs, {0, pos})

      _ ->
        eot(bs, <<>>, size, max)
    end
  end

  defp flush_until_down(port, monRef) do
    receive do
      {^port, {:data, _Bytes}} ->
        flush_until_down(port, monRef)

      {:DOWN, ^monRef, _, _, _} ->
        flush_exit(port)
    end
  end

  defp flush_exit(port) do
    receive do
      {:EXIT, ^port, _} ->
        :ok
    after
      0 ->
        :ok
    end
  end

  defp badarg_with_cause(args, cause) do
    :erlang.error(:badarg, args, [{:error_info, %{module: :erl_kernel_errors, cause: cause}}])
  end

  defp badarg_with_info(args) do
    :erlang.error(:badarg, args, [{:error_info, %{module: :erl_kernel_errors}}])
  end
end
