defmodule :m_filename do
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

  def absname(name) do
    {:ok, cwd} = :file.get_cwd()
    absname(name, cwd)
  end

  def absname(name, absBase)
      when is_binary(name) and
             is_list(absBase) do
    absname(name, filename_string_to_binary(absBase))
  end

  def absname(name, absBase)
      when is_list(name) and
             is_binary(absBase) do
    absname(filename_string_to_binary(name), absBase)
  end

  def absname(name, absBase) do
    case pathtype(name) do
      :relative ->
        absname_join(absBase, name)

      :absolute ->
        join([flatten(name)])

      :volumerelative ->
        absname_vr(split(name), split(absBase), absBase)
    end
  end

  defp absname_vr(["/" | rest1], [volume | _], _AbsBase) do
    join([volume | rest1])
  end

  defp absname_vr([<<x, ?:>> | rest1], [<<x, _::binary>> | _], absBase) do
    absname(join(rest1), absBase)
  end

  defp absname_vr([<<x, ?:>> | name], _, _AbsBase) do
    dcwd =
      case :file.get_cwd([x, ?:]) do
        {:ok, dir} ->
          filename_string_to_binary(dir)

        {:error, _} ->
          <<x, ?:, ?/>>
      end

    absname(join(name), dcwd)
  end

  defp absname_vr([~c"/" | rest1], [volume | _], _AbsBase) do
    join([volume | rest1])
  end

  defp absname_vr([[x, ?:] | rest1], [[x | _] | _], absBase) do
    absname(join(rest1), absBase)
  end

  defp absname_vr([[x, ?:] | name], _, _AbsBase) do
    dcwd =
      case :file.get_cwd([x, ?:]) do
        {:ok, dir} ->
          dir

        {:error, _} ->
          [x, ?:, ?/]
      end

    absname(join(name), dcwd)
  end

  def absname_join(absBase, name) do
    join(absBase, flatten(name))
  end

  def basename(name) when is_binary(name) do
    case :os.type() do
      {:win32, _} ->
        win_basenameb(name)

      _ ->
        basenameb(name, ["/"])
    end
  end

  def basename(name0) do
    name1 = flatten(name0)
    {dirSep2, drvSep} = separators()
    name = skip_prefix(name1, drvSep)
    basename1(name, name, dirSep2)
  end

  defp win_basenameb(<<letter, ?:, rest::binary>>)
       when is_integer(letter) and
              ((?A <= letter and letter <= ?Z) or (?a <= letter and letter <= ?z)) do
    basenameb(rest, ["/", "\\"])
  end

  defp win_basenameb(o) do
    basenameb(o, ["/", "\\"])
  end

  defp basenameb(bin, sep) do
    parts =
      for x <- :binary.split(bin, sep, [:global]),
          x !== <<>> do
        x
      end

    cond do
      parts === [] ->
        <<>>

      true ->
        :lists.last(parts)
    end
  end

  defp basename1([?/], tail0, _DirSep2) do
    [_ | tail] = :lists.reverse(tail0)
    :lists.reverse(tail)
  end

  defp basename1([?/ | rest], _Tail, dirSep2) do
    basename1(rest, rest, dirSep2)
  end

  defp basename1([dirSep2 | rest], tail, dirSep2)
       when is_integer(dirSep2) do
    basename1([?/ | rest], tail, dirSep2)
  end

  defp basename1([char | rest], tail, dirSep2)
       when is_integer(char) do
    basename1(rest, tail, dirSep2)
  end

  defp basename1([], tail, _DirSep2) do
    tail
  end

  defp skip_prefix(name, false) do
    name
  end

  defp skip_prefix([l, drvSep | name], drvSep)
       when is_integer(l) and ((?A <= l and l <= ?Z) or (?a <= l and l <= ?z)) do
    name
  end

  defp skip_prefix(name, _) do
    name
  end

  def basename(name, ext)
      when is_binary(name) and
             is_list(ext) do
    basename(name, filename_string_to_binary(ext))
  end

  def basename(name, ext)
      when is_list(name) and
             is_binary(ext) do
    basename(filename_string_to_binary(name), ext)
  end

  def basename(name, ext)
      when is_binary(name) and
             is_binary(ext) do
    bName = basename(name)
    lAll = byte_size(name)
    lN = byte_size(bName)
    lE = byte_size(ext)

    case lN - lE do
      neg when neg < 0 ->
        bName

      pos ->
        startLen = lAll - pos - lE

        case name do
          <<_::size(startLen)-binary, part::size(pos)-binary, ^ext::binary>> ->
            part

          _Other ->
            bName
        end
    end
  end

  def basename(name0, ext0) do
    name = flatten(name0)
    ext = flatten(ext0)
    {dirSep2, drvSep} = separators()
    noPrefix = skip_prefix(name, drvSep)
    basename(noPrefix, ext, [], dirSep2)
  end

  defp basename(ext, ext, tail, _DrvSep2) do
    :lists.reverse(tail)
  end

  defp basename([?/], ext, tail, drvSep2) do
    basename([], ext, tail, drvSep2)
  end

  defp basename([?/ | rest], ext, _Tail, drvSep2) do
    basename(rest, ext, [], drvSep2)
  end

  defp basename([dirSep2 | rest], ext, tail, dirSep2)
       when is_integer(dirSep2) do
    basename([?/ | rest], ext, tail, dirSep2)
  end

  defp basename([char | rest], ext, tail, drvSep2)
       when is_integer(char) do
    basename(rest, ext, [char | tail], drvSep2)
  end

  defp basename([], _Ext, tail, _DrvSep2) do
    :lists.reverse(tail)
  end

  def dirname(name) when is_binary(name) do
    {dsep, drivesep} = separators()

    sList =
      case dsep do
        sep when is_integer(sep) ->
          [<<sep>>]

        _ ->
          []
      end

    {xPart0, dirs} =
      case drivesep do
        x when is_integer(x) ->
          case name do
            <<dL, ^x, rest::binary>>
            when is_integer(dL) and ((?A <= dL and dL <= ?Z) or (?a <= dL and dL <= ?z)) ->
              {<<dL, x>>, rest}

            _ ->
              {<<>>, name}
          end

        _ ->
          {<<>>, name}
      end

    parts0 = :binary.split(dirs, ["/" | sList], [:global])

    parts =
      case parts0 do
        [] ->
          []

        _ ->
          :lists.reverse(fstrip(tl(:lists.reverse(parts0))))
      end

    xPart =
      case {parts, xPart0} do
        {[], <<>>} ->
          "."

        _ ->
          xPart0
      end

    dirjoin(parts, xPart, "/")
  end

  def dirname(name0) do
    name = flatten(name0)
    dirname(name, [], [], separators())
  end

  defp dirname([?/ | rest], dir, file, seps) do
    dirname(rest, file ++ dir, [?/], seps)
  end

  defp dirname([dirSep | rest], dir, file, {dirSep, _} = seps)
       when is_integer(dirSep) do
    dirname(rest, file ++ dir, [?/], seps)
  end

  defp dirname([dl, drvSep | rest], [], [], {_, drvSep} = seps)
       when is_integer(drvSep) and
              is_integer(dl) and ((?A <= dl and dl <= ?Z) or (?a <= dl and dl <= ?z)) do
    dirname(rest, [drvSep, dl], [], seps)
  end

  defp dirname([char | rest], dir, file, seps)
       when is_integer(char) do
    dirname(rest, dir, [char | file], seps)
  end

  defp dirname([], [], file, _Seps) do
    case :lists.reverse(file) do
      [?/ | _] ->
        [?/]

      _ ->
        ~c"."
    end
  end

  defp dirname([], [?/ | rest], file, seps) do
    dirname([], rest, file, seps)
  end

  defp dirname([], [drvSep, dl], file, {_, drvSep}) do
    case :lists.reverse(file) do
      [?/ | _] ->
        [dl, drvSep, ?/]

      _ ->
        [dl, drvSep]
    end
  end

  defp dirname([], dir, _, _) do
    :lists.reverse(dir)
  end

  defp fstrip([<<>>, x | y]) do
    fstrip([x | y])
  end

  defp fstrip(a) do
    a
  end

  defp dirjoin([<<>> | t], acc, sep) do
    dirjoin1(t, <<acc::binary, "/">>, sep)
  end

  defp dirjoin(a, b, c) do
    dirjoin1(a, b, c)
  end

  defp dirjoin1([], acc, _) do
    acc
  end

  defp dirjoin1([one], acc, _) do
    <<acc::binary, one::binary>>
  end

  defp dirjoin1([h | t], acc, sep) do
    dirjoin(t, <<acc::binary, h::binary, sep::binary>>, sep)
  end

  def extension(name) when is_binary(name) do
    {dsep, _} = separators()

    sList =
      case dsep do
        sep when is_integer(sep) ->
          [<<sep>>]

        _ ->
          []
      end

    case :binary.matches(name, ["."]) do
      [] ->
        <<>>

      list ->
        case :lists.last(list) do
          {0, _} ->
            <<>>

          {pos, _} ->
            <<_::size(pos - 1)-binary, part::binary>> = name

            case :binary.match(part, ["/" | sList]) do
              :nomatch ->
                <<_::size(pos)-binary, result::binary>> = name
                result

              _ ->
                <<>>
            end
        end
    end
  end

  def extension(name0) do
    name = flatten(name0)
    extension([?/ | name], [], major_os_type())
  end

  defp extension([?. | rest] = result, _Result, osType) do
    extension(rest, result, osType)
  end

  defp extension([?/, ?. | rest], _Result, osType) do
    extension(rest, [], osType)
  end

  defp extension([?\\, ?. | rest], _Result, :win32) do
    extension(rest, [], :win32)
  end

  defp extension([char | rest], [], osType)
       when is_integer(char) do
    extension(rest, [], osType)
  end

  defp extension([?/ | rest], _Result, osType) do
    extension(rest, [], osType)
  end

  defp extension([?\\ | rest], _Result, :win32) do
    extension(rest, [], :win32)
  end

  defp extension([char | rest], result, osType)
       when is_integer(char) do
    extension(rest, result, osType)
  end

  defp extension([], result, _OsType) do
    result
  end

  def join([name1, name2 | rest]) do
    join([join(name1, name2) | rest])
  end

  def join([name]) when is_list(name) do
    join1(name, [], [], major_os_type())
  end

  def join([name]) when is_binary(name) do
    join1b(name, <<>>, [], major_os_type())
  end

  def join([name]) when is_atom(name) do
    join([:erlang.atom_to_list(name)])
  end

  def join(name1, name2)
      when is_list(name1) and
             is_list(name2) do
    osType = major_os_type()

    case pathtype(name2) do
      :relative ->
        join1(name1, name2, [], osType)

      _Other ->
        join1(name2, [], [], osType)
    end
  end

  def join(name1, name2)
      when is_binary(name1) and
             is_list(name2) do
    join(name1, filename_string_to_binary(name2))
  end

  def join(name1, name2)
      when is_list(name1) and
             is_binary(name2) do
    join(filename_string_to_binary(name1), name2)
  end

  def join(name1, name2)
      when is_binary(name1) and
             is_binary(name2) do
    osType = major_os_type()

    case pathtype(name2) do
      :relative ->
        join1b(name1, name2, [], osType)

      _Other ->
        join1b(name2, <<>>, [], osType)
    end
  end

  def join(name1, name2) when is_atom(name1) do
    join(:erlang.atom_to_list(name1), name2)
  end

  def join(name1, name2) when is_atom(name2) do
    join(name1, :erlang.atom_to_list(name2))
  end

  defp join1([ucLetter, ?: | rest], relativeName, [], :win32)
       when is_integer(ucLetter) and ucLetter >= ?A and
              ucLetter <= ?Z do
    join1(rest, relativeName, [?:, ucLetter + ?a - ?A], :win32)
  end

  defp join1([?\\, ?\\ | rest], relativeName, [], :win32) do
    join1([?/, ?/ | rest], relativeName, [], :win32)
  end

  defp join1([?/, ?/ | rest], relativeName, [], :win32) do
    join1(rest, relativeName, [?/, ?/], :win32)
  end

  defp join1([?\\ | rest], relativeName, result, :win32) do
    join1([?/ | rest], relativeName, result, :win32)
  end

  defp join1([?/ | rest], relativeName, [?., ?/ | result], osType) do
    join1(rest, relativeName, [?/ | result], osType)
  end

  defp join1([?/ | rest], relativeName, [?/ | result], osType) do
    join1(rest, relativeName, [?/ | result], osType)
  end

  defp join1([], [], result, osType) do
    maybe_remove_dirsep(result, osType)
  end

  defp join1([], relativeName, [?: | rest], :win32) do
    join1(relativeName, [], [?: | rest], :win32)
  end

  defp join1([], relativeName, [?/ | result], osType) do
    join1(relativeName, [], [?/ | result], osType)
  end

  defp join1([], relativeName, [?., ?/ | result], osType) do
    join1(relativeName, [], [?/ | result], osType)
  end

  defp join1([], relativeName, result, osType) do
    join1(relativeName, [], [?/ | result], osType)
  end

  defp join1([[_ | _] = list | rest], relativeName, result, osType) do
    join1(list ++ rest, relativeName, result, osType)
  end

  defp join1([[] | rest], relativeName, result, osType) do
    join1(rest, relativeName, result, osType)
  end

  defp join1([char | rest], relativeName, result, osType)
       when is_integer(char) do
    join1(rest, relativeName, [char | result], osType)
  end

  defp join1([atom | rest], relativeName, result, osType)
       when is_atom(atom) do
    join1(:erlang.atom_to_list(atom) ++ rest, relativeName, result, osType)
  end

  defp join1b(<<ucLetter, ?:, rest::binary>>, relativeName, [], :win32)
       when is_integer(ucLetter) and ucLetter >= ?A and
              ucLetter <= ?Z do
    join1b(rest, relativeName, [?:, ucLetter + ?a - ?A], :win32)
  end

  defp join1b(<<?\\, ?\\, rest::binary>>, relativeName, [], :win32) do
    join1b(<<?/, ?/, rest::binary>>, relativeName, [], :win32)
  end

  defp join1b(<<?/, ?/, rest::binary>>, relativeName, [], :win32) do
    join1b(rest, relativeName, [?/, ?/], :win32)
  end

  defp join1b(<<?\\, rest::binary>>, relativeName, result, :win32) do
    join1b(<<?/, rest::binary>>, relativeName, result, :win32)
  end

  defp join1b(<<?/, rest::binary>>, relativeName, [?., ?/ | result], osType) do
    join1b(rest, relativeName, [?/ | result], osType)
  end

  defp join1b(<<?/, rest::binary>>, relativeName, [?/ | result], osType) do
    join1b(rest, relativeName, [?/ | result], osType)
  end

  defp join1b(<<>>, <<>>, result, osType) do
    :erlang.list_to_binary(
      maybe_remove_dirsep(
        result,
        osType
      )
    )
  end

  defp join1b(<<>>, relativeName, [?: | rest], :win32) do
    join1b(relativeName, <<>>, [?: | rest], :win32)
  end

  defp join1b(<<>>, relativeName, [?/, ?/ | result], :win32) do
    join1b(relativeName, <<>>, [?/, ?/ | result], :win32)
  end

  defp join1b(<<>>, relativeName, [?/ | result], osType) do
    join1b(relativeName, <<>>, [?/ | result], osType)
  end

  defp join1b(<<>>, relativeName, [?., ?/ | result], osType) do
    join1b(relativeName, <<>>, [?/ | result], osType)
  end

  defp join1b(<<>>, relativeName, result, osType) do
    join1b(relativeName, <<>>, [?/ | result], osType)
  end

  defp join1b(<<char, rest::binary>>, relativeName, result, osType)
       when is_integer(char) do
    join1b(rest, relativeName, [char | result], osType)
  end

  defp maybe_remove_dirsep([?/, ?:, letter], :win32) do
    [letter, ?:, ?/]
  end

  defp maybe_remove_dirsep([?/], _) do
    [?/]
  end

  defp maybe_remove_dirsep([?/, ?/], :win32) do
    [?/, ?/]
  end

  defp maybe_remove_dirsep([?/ | name], _) do
    :lists.reverse(name)
  end

  defp maybe_remove_dirsep(name, _) do
    :lists.reverse(name)
  end

  def append(dir, name)
      when is_binary(dir) and
             is_binary(name) do
    <<dir::binary, ?/::size(8), name::binary>>
  end

  def append(dir, name) when is_binary(dir) do
    append(dir, filename_string_to_binary(name))
  end

  def append(dir, name) when is_binary(name) do
    append(filename_string_to_binary(dir), name)
  end

  def append(dir, name) do
    dir ++ [?/ | name]
  end

  def pathtype(atom) when is_atom(atom) do
    pathtype(:erlang.atom_to_list(atom))
  end

  def pathtype(name) when is_list(name) or is_binary(name) do
    case :os.type() do
      {:win32, _} ->
        win32_pathtype(name)

      {_, _} ->
        unix_pathtype(name)
    end
  end

  defp unix_pathtype(<<?/, _::binary>>) do
    :absolute
  end

  defp unix_pathtype([?/ | _]) do
    :absolute
  end

  defp unix_pathtype([list | rest]) when is_list(list) do
    unix_pathtype(list ++ rest)
  end

  defp unix_pathtype([atom | rest]) when is_atom(atom) do
    unix_pathtype(:erlang.atom_to_list(atom) ++ rest)
  end

  defp unix_pathtype(_) do
    :relative
  end

  defp win32_pathtype([list | rest]) when is_list(list) do
    win32_pathtype(list ++ rest)
  end

  defp win32_pathtype([atom | rest]) when is_atom(atom) do
    win32_pathtype(:erlang.atom_to_list(atom) ++ rest)
  end

  defp win32_pathtype([char, list | rest]) when is_list(list) do
    win32_pathtype([char | list ++ rest])
  end

  defp win32_pathtype(<<?/, ?/, _::binary>>) do
    :absolute
  end

  defp win32_pathtype(<<?\\, ?/, _::binary>>) do
    :absolute
  end

  defp win32_pathtype(<<?/, ?\\, _::binary>>) do
    :absolute
  end

  defp win32_pathtype(<<?\\, ?\\, _::binary>>) do
    :absolute
  end

  defp win32_pathtype(<<?/, _::binary>>) do
    :volumerelative
  end

  defp win32_pathtype(<<?\\, _::binary>>) do
    :volumerelative
  end

  defp win32_pathtype(<<_Letter, ?:, ?/, _::binary>>) do
    :absolute
  end

  defp win32_pathtype(<<_Letter, ?:, ?\\, _::binary>>) do
    :absolute
  end

  defp win32_pathtype(<<_Letter, ?:, _::binary>>) do
    :volumerelative
  end

  defp win32_pathtype([?/, ?/ | _]) do
    :absolute
  end

  defp win32_pathtype([?\\, ?/ | _]) do
    :absolute
  end

  defp win32_pathtype([?/, ?\\ | _]) do
    :absolute
  end

  defp win32_pathtype([?\\, ?\\ | _]) do
    :absolute
  end

  defp win32_pathtype([?/ | _]) do
    :volumerelative
  end

  defp win32_pathtype([?\\ | _]) do
    :volumerelative
  end

  defp win32_pathtype([c1, c2, list | rest]) when is_list(list) do
    pathtype([c1, c2 | list ++ rest])
  end

  defp win32_pathtype([_Letter, ?:, ?/ | _]) do
    :absolute
  end

  defp win32_pathtype([_Letter, ?:, ?\\ | _]) do
    :absolute
  end

  defp win32_pathtype([_Letter, ?: | _]) do
    :volumerelative
  end

  defp win32_pathtype(_) do
    :relative
  end

  def rootname(name) when is_binary(name) do
    :erlang.list_to_binary(rootname(:erlang.binary_to_list(name)))
  end

  def rootname(name0) do
    name = flatten(name0)
    rootname(name, [], [], major_os_type())
  end

  defp rootname([?/ | rest], root, ext, osType) do
    rootname(rest, [?/] ++ ext ++ root, [], osType)
  end

  defp rootname([?\\ | rest], root, ext, :win32) do
    rootname(rest, [?/] ++ ext ++ root, [], :win32)
  end

  defp rootname([?. | rest], [?/ | _] = root, [], osType) do
    rootname(rest, [?. | root], [], osType)
  end

  defp rootname([?. | rest], root, ext, osType) do
    rootname(rest, ext ++ root, ~c".", osType)
  end

  defp rootname([char | rest], root, [], osType)
       when is_integer(char) do
    rootname(rest, [char | root], [], osType)
  end

  defp rootname([char | rest], root, ext, osType)
       when is_integer(char) do
    rootname(rest, root, [char | ext], osType)
  end

  defp rootname([], root, _Ext, _OsType) do
    :lists.reverse(root)
  end

  def rootname(name, ext)
      when is_binary(name) and
             is_binary(ext) do
    :erlang.list_to_binary(
      rootname(
        :erlang.binary_to_list(name),
        :erlang.binary_to_list(ext)
      )
    )
  end

  def rootname(name, ext) when is_binary(name) do
    rootname(name, filename_string_to_binary(ext))
  end

  def rootname(name, ext) when is_binary(ext) do
    rootname(filename_string_to_binary(name), ext)
  end

  def rootname(name0, ext0) do
    name = flatten(name0)
    ext = flatten(ext0)
    rootname2(name, ext, [], major_os_type())
  end

  defp rootname2(ext, ext, [?/ | _] = result, _OsType) do
    :lists.reverse(result, ext)
  end

  defp rootname2(ext, ext, [?\\ | _] = result, :win32) do
    :lists.reverse(result, ext)
  end

  defp rootname2(ext, ext, result, _OsType) do
    :lists.reverse(result)
  end

  defp rootname2([], _Ext, result, _OsType) do
    :lists.reverse(result)
  end

  defp rootname2([char | rest], ext, result, osType)
       when is_integer(char) do
    rootname2(rest, ext, [char | result], osType)
  end

  def split(name) when is_binary(name) do
    case :os.type() do
      {:win32, _} ->
        win32_splitb(name)

      _ ->
        unix_splitb(name)
    end
  end

  def split(name0) do
    name = flatten(name0)

    case :os.type() do
      {:win32, _} ->
        win32_split(name)

      _ ->
        unix_split(name)
    end
  end

  defp unix_splitb(name) do
    l = :binary.split(name, ["/"], [:global])

    lL =
      case l do
        [<<>> | rest] when rest !== [] ->
          ["/" | rest]

        _ ->
          l
      end

    for x <- lL, x !== <<>> do
      x
    end
  end

  defp fix_driveletter(letter0) do
    cond do
      letter0 >= ?A and letter0 <= ?Z ->
        letter0 + ?a - ?A

      true ->
        letter0
    end
  end

  defp win32_splitb(<<letter0, ?:, slash, rest::binary>>)
       when (slash === ?\\ or slash === ?/) and is_integer(letter0) and
              ((?A <= letter0 and letter0 <= ?Z) or (?a <= letter0 and letter0 <= ?z)) do
    letter = fix_driveletter(letter0)
    l = :binary.split(rest, ["/", "\\"], [:global])

    [
      <<letter, ?:, ?/>>
      | for x <- l, x !== <<>> do
          x
        end
    ]
  end

  defp win32_splitb(<<letter0, ?:, rest::binary>>)
       when is_integer(letter0) and
              ((?A <= letter0 and letter0 <= ?Z) or (?a <= letter0 and letter0 <= ?z)) do
    letter = fix_driveletter(letter0)
    l = :binary.split(rest, ["/", "\\"], [:global])

    [
      <<letter, ?:>>
      | for x <- l, x !== <<>> do
          x
        end
    ]
  end

  defp win32_splitb(<<slash, slash, rest::binary>>)
       when slash === ?\\ or slash === ?/ do
    l = :binary.split(rest, ["/", "\\"], [:global])

    [
      "//"
      | for x <- l, x !== <<>> do
          x
        end
    ]
  end

  defp win32_splitb(<<slash, rest::binary>>)
       when slash === ?\\ or slash === ?/ do
    l = :binary.split(rest, ["/", "\\"], [:global])

    [
      <<?/>>
      | for x <- l, x !== <<>> do
          x
        end
    ]
  end

  defp win32_splitb(name) do
    l = :binary.split(name, ["/", "\\"], [:global])

    for x <- l, x !== <<>> do
      x
    end
  end

  defp unix_split(name) do
    split(name, [], :unix)
  end

  defp win32_split([slash, slash | rest])
       when slash === ?\\ or slash === ?/ do
    split(rest, [[?/, ?/]], :win32)
  end

  defp win32_split([?\\ | rest]) do
    win32_split([?/ | rest])
  end

  defp win32_split([x, ?\\ | rest]) when is_integer(x) do
    win32_split([x, ?/ | rest])
  end

  defp win32_split([x, y, ?\\ | rest])
       when is_integer(x) and
              is_integer(y) do
    win32_split([x, y, ?/ | rest])
  end

  defp win32_split([ucLetter, ?: | rest])
       when is_integer(ucLetter) and ?A <= ucLetter and
              ucLetter <= ?Z do
    win32_split([ucLetter + ?a - ?A, ?: | rest])
  end

  defp win32_split([letter, ?:, ?/ | rest]) do
    split(rest, [], [[letter, ?:, ?/]], :win32)
  end

  defp win32_split([letter, ?: | rest]) do
    split(rest, [], [[letter, ?:]], :win32)
  end

  defp win32_split(name) do
    split(name, [], :win32)
  end

  defp split([?/ | rest], components, osType) do
    split(rest, [], [[?/] | components], osType)
  end

  defp split([?\\ | rest], components, :win32) do
    split(rest, [], [[?/] | components], :win32)
  end

  defp split(relativeName, components, osType) do
    split(relativeName, [], components, osType)
  end

  defp split([?\\ | rest], comp, components, :win32) do
    split([?/ | rest], comp, components, :win32)
  end

  defp split([?/ | rest], [], components, osType) do
    split(rest, [], components, osType)
  end

  defp split([?/ | rest], comp, components, osType) do
    split(rest, [], [:lists.reverse(comp) | components], osType)
  end

  defp split([char | rest], comp, components, osType)
       when is_integer(char) do
    split(rest, [char | comp], components, osType)
  end

  defp split([], [], components, _OsType) do
    :lists.reverse(components)
  end

  defp split([], comp, components, osType) do
    split([], [], [:lists.reverse(comp) | components], osType)
  end

  def nativename(name0) do
    name = join([name0])

    case :os.type() do
      {:win32, _} ->
        win32_nativename(name)

      _ ->
        name
    end
  end

  defp win32_nativename(name) when is_binary(name) do
    :binary.replace(name, "/", "\\", [:global])
  end

  defp win32_nativename([?/ | rest]) do
    [?\\ | win32_nativename(rest)]
  end

  defp win32_nativename([c | rest]) do
    [c | win32_nativename(rest)]
  end

  defp win32_nativename([]) do
    []
  end

  defp separators() do
    case :os.type() do
      {:win32, _} ->
        {?\\, ?:}

      _ ->
        {false, false}
    end
  end

  defp major_os_type() do
    {osT, _} = :os.type()
    osT
  end

  def flatten(bin) when is_binary(bin) do
    bin
  end

  def flatten(list) do
    do_flatten(list, [])
  end

  defp do_flatten([h | t], tail) when is_list(h) do
    do_flatten(h, do_flatten(t, tail))
  end

  defp do_flatten([h | t], tail) when is_atom(h) do
    :erlang.atom_to_list(h) ++ do_flatten(t, tail)
  end

  defp do_flatten([h | t], tail) do
    [h | do_flatten(t, tail)]
  end

  defp do_flatten([], tail) do
    tail
  end

  defp do_flatten(atom, tail) when is_atom(atom) do
    :erlang.atom_to_list(atom) ++ flatten(tail)
  end

  defp filename_string_to_binary(list) do
    case :unicode.characters_to_binary(
           flatten(list),
           :unicode,
           :file.native_name_encoding()
         ) do
      {:error, _, _} ->
        :erlang.error(:badarg)

      bin when is_binary(bin) ->
        bin
    end
  end

  def basedir(type, application)
      when (is_atom(type) and
              is_list(application)) or is_binary(application) do
    basedir(type, application, %{})
  end

  def basedir(type, application, opts)
      when (is_atom(type) and
              is_map(opts) and
              is_list(application)) or is_binary(application) do
    os = basedir_os_from_opts(opts)
    name = basedir_name_from_opts(os, application, opts)
    base = basedir_from_os(type, os)

    case {type, os} do
      {:user_log, :linux} ->
        :filename.join([base, name, ~c"log"])

      {:user_log, :windows} ->
        :filename.join([base, name, ~c"Logs"])

      {:user_cache, :windows} ->
        :filename.join([base, name, ~c"Cache"])

      {^type, _}
      when type === :site_config or type === :site_data ->
        for b <- base do
          :filename.join([b, name])
        end

      _ ->
        :filename.join([base, name])
    end
  end

  defp basedir_os_from_opts(%{os: :linux}) do
    :linux
  end

  defp basedir_os_from_opts(%{os: :windows}) do
    :windows
  end

  defp basedir_os_from_opts(%{os: :darwin}) do
    :darwin
  end

  defp basedir_os_from_opts(%{}) do
    basedir_os_type()
  end

  defp basedir_name_from_opts(:windows, app, %{author: author, version: vsn}) do
    :filename.join([author, app, vsn])
  end

  defp basedir_name_from_opts(:windows, app, %{author: author}) do
    :filename.join([author, app])
  end

  defp basedir_name_from_opts(_, app, %{version: vsn}) do
    :filename.join([app, vsn])
  end

  defp basedir_name_from_opts(_, app, _) do
    app
  end

  defp basedir_from_os(type, os) do
    case os do
      :linux ->
        basedir_linux(type)

      :darwin ->
        basedir_darwin(type)

      :windows ->
        basedir_windows(type)
    end
  end

  defp basedir_linux(type) do
    case type do
      :user_data ->
        getenv(~c"XDG_DATA_HOME", ~c".local/share", true)

      :user_config ->
        getenv(~c"XDG_CONFIG_HOME", ~c".config", true)

      :user_cache ->
        getenv(~c"XDG_CACHE_HOME", ~c".cache", true)

      :user_log ->
        getenv(~c"XDG_CACHE_HOME", ~c".cache", true)

      :site_data ->
        base = getenv(~c"XDG_DATA_DIRS", ~c"/usr/local/share/:/usr/share/", false)
        :string.lexemes(base, ~c":")

      :site_config ->
        base = getenv(~c"XDG_CONFIG_DIRS", ~c"/etc/xdg", false)
        :string.lexemes(base, ~c":")
    end
  end

  defp basedir_darwin(type) do
    case type do
      :user_data ->
        basedir_join_home(~c"Library/Application Support")

      :user_config ->
        basedir_join_home(~c"Library/Application Support")

      :user_cache ->
        basedir_join_home(~c"Library/Caches")

      :user_log ->
        basedir_join_home(~c"Library/Logs")

      :site_data ->
        [~c"/Library/Application Support"]

      :site_config ->
        [~c"/Library/Application Support"]
    end
  end

  defp basedir_windows(type) do
    case basedir_windows_appdata() do
      :noappdata ->
        case type do
          :user_data ->
            basedir_join_home(~c"Local")

          :user_config ->
            basedir_join_home(~c"Roaming")

          :user_cache ->
            basedir_join_home(~c"Local")

          :user_log ->
            basedir_join_home(~c"Local")

          :site_data ->
            []

          :site_config ->
            []
        end

      {:ok, appData} ->
        case type do
          :user_data ->
            getenv(~c"LOCALAPPDATA", appData)

          :user_config ->
            appData

          :user_cache ->
            getenv(~c"LOCALAPPDATA", appData)

          :user_log ->
            getenv(~c"LOCALAPPDATA", appData)

          :site_data ->
            []

          :site_config ->
            []
        end
    end
  end

  defp basedir_windows_appdata() do
    case :os.getenv(~c"APPDATA") do
      invalid when invalid === false or invalid === [] ->
        :noappdata

      val ->
        {:ok, val}
    end
  end

  defp getenv(k, def__, false) do
    getenv(k, def__)
  end

  defp getenv(k, def__, true) do
    getenv(k, basedir_join_home(def__))
  end

  defp getenv(k, def__) do
    case :os.getenv(k) do
      [] ->
        def__

      false ->
        def__

      val ->
        val
    end
  end

  defp basedir_join_home(dir) do
    case :os.getenv(~c"HOME") do
      false ->
        {:ok, [[home]]} = :init.get_argument(:home)
        :filename.join(home, dir)

      home ->
        :filename.join(home, dir)
    end
  end

  defp basedir_os_type() do
    case :os.type() do
      {:unix, :darwin} ->
        :darwin

      {:win32, _} ->
        :windows

      _ ->
        :linux
    end
  end

  def validate(fileName) when is_binary(fileName) do
    validate_bin(fileName)
  end

  def validate(fileName)
      when is_list(fileName) or
             is_atom(fileName) do
    validate_list(fileName, :file.native_name_encoding(), :os.type())
  end

  defp validate_list(fileName, enc, os) do
    try do
      true = validate_list(fileName, enc, os, 0) > 0
    catch
      _, _ ->
        false
    end
  end

  defp validate_list([], _Enc, _Os, chars) do
    chars
  end

  defp validate_list(c, enc, os, chars) when is_integer(c) do
    validate_char(c, enc, os)
    chars + 1
  end

  defp validate_list(a, enc, os, chars) when is_atom(a) do
    validate_list(:erlang.atom_to_list(a), enc, os, chars)
  end

  defp validate_list([h | t], enc, os, chars) do
    newChars = validate_list(h, enc, os, chars)
    validate_list(t, enc, os, newChars)
  end

  defp validate_char(c, _, _) when c < 1 do
    throw(:invalid)
  end

  defp validate_char(c, :latin1, _) when c > 255 do
    throw(:invalid)
  end

  defp validate_char(c, :utf8, _) when c >= 1_114_112 do
    throw(:invalid)
  end

  defp validate_char(c, :utf8, {:win32, _}) when c > 65535 do
    throw(:invalid)
  end

  defp validate_char(_C, :utf8, {:win32, _}) do
    :ok
  end

  defp validate_char(c, :utf8, _) when 55296 <= c and c <= 57343 do
    throw(:invalid)
  end

  defp validate_char(_, _, _) do
    :ok
  end

  defp validate_bin(bin) do
    try do
      true = validate_bin(bin, 0) > 0
    catch
      _, _ ->
        false
    end
  end

  defp validate_bin(<<>>, bs) do
    bs
  end

  defp validate_bin(<<0, _Rest::binary>>, _Bs) do
    throw(:invalid)
  end

  defp validate_bin(<<_B, rest::binary>>, bs) do
    validate_bin(rest, bs + 1)
  end
end
