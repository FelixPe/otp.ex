defmodule :m_cdv_bin_cb do
  use Bitwise

  def get_details({type, {t, key}}, _) do
    [{^key, term}] = :ets.lookup(t, key)
    {:ok, {~c"Expanded Binary", {type, term}, []}}
  end

  def get_details({:cdv, id}, _) do
    {:ok, bin} = :crashdump_viewer.expand_binary(id)
    {:ok, {~c"Expanded Binary", {:cvd, bin}, []}}
  end

  def detail_pages() do
    [{~c"Binary", &init_bin_page/2}]
  end

  defp init_bin_page(parent, {type, bin}) do
    cs = :observer_lib.colors(parent)

    :cdv_multi_wx.start_link(
      parent,
      [
        {~c"Format ~p", :cdv_html_wx, {type, format_bin_fun(~c"~p", bin, cs)}},
        {~c"Format ~tp", :cdv_html_wx, {type, format_bin_fun(~c"~tp", bin, cs)}},
        {~c"Format ~w", :cdv_html_wx, {type, format_bin_fun(~c"~w", bin, cs)}},
        {~c"Format ~tw", :cdv_html_wx, {type, format_bin_fun(~c"~tw", bin, cs)}},
        {~c"Format ~s", :cdv_html_wx, {type, format_bin_fun(~c"~s", bin, cs)}},
        {~c"Format ~ts", :cdv_html_wx, {type, format_bin_fun(~c"~ts", bin, cs)}},
        {~c"Hex", :cdv_html_wx,
         {type,
          hex_binary_fun(
            bin,
            cs
          )}},
        {~c"Term", :cdv_html_wx,
         {type,
          binary_to_term_fun(
            bin,
            cs
          )}}
      ]
    )
  end

  defp format_bin_fun(format, bin, cs) do
    fn ->
      try do
        :io_lib.format(format, [bin])
      catch
        :error, :badarg ->
          warning = ~c"This binary cannot be formatted with " ++ format
          :observer_html_lib.warning(warning, cs)
      else
        str ->
          plain_html(:lists.flatten(str), cs)
      end
    end
  end

  defp binary_to_term_fun(bin, cs) do
    fn ->
      try do
        :erlang.binary_to_term(bin)
      catch
        :error, :badarg ->
          warning = ~c"This binary cannot be converted to an Erlang term"
          :observer_html_lib.warning(warning, cs)
      else
        term ->
          plain_html(:io_lib.format(~c"~tp", [term]), cs)
      end
    end
  end

  defp hex_binary_fun(bin, cs) do
    fn ->
      s = ~c"<<" ++ format_hex(bin, 25) ++ ~c">>"
      plain_html(:io_lib.format(~c"~s", [s]), cs)
    end
  end

  defp format_hex(<<>>, _) do
    []
  end

  defp format_hex(<<b1::size(4), b2::size(4)>>, _) do
    [:erlang.integer_to_list(b1, 16), :erlang.integer_to_list(b2, 16)]
  end

  defp format_hex(
         <<b1::size(4), b2::size(4), bin::binary>>,
         0
       ) do
    [
      :erlang.integer_to_list(b1, 16),
      :erlang.integer_to_list(b2, 16),
      ?,,
      ?\n,
      ?\s,
      ?\s
      | format_hex(bin, 25)
    ]
  end

  defp format_hex(
         <<b1::size(4), b2::size(4), bin::binary>>,
         n
       ) do
    [
      :erlang.integer_to_list(b1, 16),
      :erlang.integer_to_list(b2, 16),
      ?,
      | format_hex(
          bin,
          n - 1
        )
    ]
  end

  defp plain_html(text, cs) do
    :observer_html_lib.plain_page(text, cs)
  end
end
