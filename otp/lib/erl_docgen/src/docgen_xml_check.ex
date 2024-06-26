defmodule :m_docgen_xml_check do
  use Bitwise

  def validate(file0) do
    file =
      case :filename.extension(file0) do
        ~c".xml" ->
          file0

        _ ->
          file0 ++ ~c".xml"
      end

    case :filelib.is_regular(file) do
      true ->
        dtdDir = :filename.join(:code.priv_dir(:erl_docgen), ~c"dtd")

        case (try do
                :xmerl_scan.file(
                  file,
                  [{:validation, true}, {:fetch_path, [dtdDir]}]
                )
              catch
                :error, e -> {:EXIT, {e, __STACKTRACE__}}
                :exit, e -> {:EXIT, e}
                e -> e
              end) do
          {:EXIT, error} ->
            :io.format(~c"~p~n", [error])
            :error

          {_Doc, _Misc} ->
            :ok
        end

      false ->
        {:error, :badfile}
    end
  end
end
