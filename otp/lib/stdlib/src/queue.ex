defmodule :m_queue do
  use Bitwise
  def new() do
    {[], []}
  end

  def is_queue({r, f}) when (is_list(r) and is_list(f)) do
    true
  end

  def is_queue(_) do
    false
  end

  def is_empty({[], []}) do
    true
  end

  def is_empty({in__, out}) when (is_list(in__) and
                              is_list(out)) do
    false
  end

  def is_empty(q) do
    :erlang.error(:badarg, [q])
  end

  def len({r, f}) when (is_list(r) and is_list(f)) do
    length(r) + length(f)
  end

  def len(q) do
    :erlang.error(:badarg, [q])
  end

  def to_list({in__, out}) when (is_list(in__) and
                              is_list(out)) do
    out ++ :lists.reverse(in__, [])
  end

  def to_list(q) do
    :erlang.error(:badarg, [q])
  end

  def from_list(l) when is_list(l) do
    f2r(l)
  end

  def from_list(l) do
    :erlang.error(:badarg, [l])
  end

  def member(x, {r, f}) when (is_list(r) and is_list(f)) do
    :lists.member(x, r) or :lists.member(x, f)
  end

  def member(x, q) do
    :erlang.error(:badarg, [x, q])
  end

  def unquote(:in)(x, {[_] = in__, []}) do
    {[x], in__}
  end

  def unquote(:in)(x, {in__, out}) when (is_list(in__) and
                                   is_list(out)) do
    {[x | in__], out}
  end

  def unquote(:in)(x, q) do
    :erlang.error(:badarg, [x, q])
  end

  def in_r(x, {[], [_] = f}) do
    {f, [x]}
  end

  def in_r(x, {r, f}) when (is_list(r) and is_list(f)) do
    {r, [x | f]}
  end

  def in_r(x, q) do
    :erlang.error(:badarg, [x, q])
  end

  def out({[], []} = q) do
    {:empty, q}
  end

  def out({[v], []}) do
    {{:value, v}, {[], []}}
  end

  def out({[y | in__], []}) do
    [v | out] = :lists.reverse(in__, [])
    {{:value, v}, {[y], out}}
  end

  def out({in__, [v]}) when is_list(in__) do
    {{:value, v}, r2f(in__)}
  end

  def out({in__, [v | out]}) when is_list(in__) do
    {{:value, v}, {in__, out}}
  end

  def out(q) do
    :erlang.error(:badarg, [q])
  end

  def out_r({[], []} = q) do
    {:empty, q}
  end

  def out_r({[], [v]}) do
    {{:value, v}, {[], []}}
  end

  def out_r({[], [y | out]}) do
    [v | in__] = :lists.reverse(out, [])
    {{:value, v}, {in__, [y]}}
  end

  def out_r({[v], out}) when is_list(out) do
    {{:value, v}, f2r(out)}
  end

  def out_r({[v | in__], out}) when is_list(out) do
    {{:value, v}, {in__, out}}
  end

  def out_r(q) do
    :erlang.error(:badarg, [q])
  end

  def get({[], []} = q) do
    :erlang.error(:empty, [q])
  end

  def get({r, f}) when (is_list(r) and is_list(f)) do
    get(r, f)
  end

  def get(q) do
    :erlang.error(:badarg, [q])
  end

  defp get(r, [h | _]) when is_list(r) do
    h
  end

  defp get([h], []) do
    h
  end

  defp get([_ | r], []) do
    :lists.last(r)
  end

  def get_r({[], []} = q) do
    :erlang.error(:empty, [q])
  end

  def get_r({[h | _], f}) when is_list(f) do
    h
  end

  def get_r({[], [h]}) do
    h
  end

  def get_r({[], [_ | f]}) do
    :lists.last(f)
  end

  def get_r(q) do
    :erlang.error(:badarg, [q])
  end

  def peek({[], []}) do
    :empty
  end

  def peek({r, [h | _]}) when is_list(r) do
    {:value, h}
  end

  def peek({[h], []}) do
    {:value, h}
  end

  def peek({[_ | r], []}) do
    {:value, :lists.last(r)}
  end

  def peek(q) do
    :erlang.error(:badarg, [q])
  end

  def peek_r({[], []}) do
    :empty
  end

  def peek_r({[h | _], f}) when is_list(f) do
    {:value, h}
  end

  def peek_r({[], [h]}) do
    {:value, h}
  end

  def peek_r({[], [_ | r]}) do
    {:value, :lists.last(r)}
  end

  def peek_r(q) do
    :erlang.error(:badarg, [q])
  end

  def drop({[], []} = q) do
    :erlang.error(:empty, [q])
  end

  def drop({[_], []}) do
    {[], []}
  end

  def drop({[y | r], []}) do
    [_ | f] = :lists.reverse(r, [])
    {[y], f}
  end

  def drop({r, [_]}) when is_list(r) do
    r2f(r)
  end

  def drop({r, [_ | f]}) when is_list(r) do
    {r, f}
  end

  def drop(q) do
    :erlang.error(:badarg, [q])
  end

  def drop_r({[], []} = q) do
    :erlang.error(:empty, [q])
  end

  def drop_r({[], [_]}) do
    {[], []}
  end

  def drop_r({[], [y | f]}) do
    [_ | r] = :lists.reverse(f, [])
    {r, [y]}
  end

  def drop_r({[_], f}) when is_list(f) do
    f2r(f)
  end

  def drop_r({[_ | r], f}) when is_list(f) do
    {r, f}
  end

  def drop_r(q) do
    :erlang.error(:badarg, [q])
  end

  def reverse({r, f}) when (is_list(r) and is_list(f)) do
    {f, r}
  end

  def reverse(q) do
    :erlang.error(:badarg, [q])
  end

  def join({r, f} = q, {[], []}) when (is_list(r) and
                                       is_list(f)) do
    q
  end

  def join({[], []}, {r, f} = q) when (is_list(r) and
                                       is_list(f)) do
    q
  end

  def join({r1, f1}, {r2, f2}) when (is_list(r1) and
                                     is_list(f1) and is_list(r2) and
                                     is_list(f2)) do
    {r2, f1 ++ :lists.reverse(r1, f2)}
  end

  def join(q1, q2) do
    :erlang.error(:badarg, [q1, q2])
  end

  def split(0, {r, f} = q) when (is_list(r) and
                                is_list(f)) do
    {{[], []}, q}
  end

  def split(n, {r, f} = q) when (is_integer(n) and n >= 1 and
                                is_list(r) and is_list(f)) do
    lf = :erlang.length(f)
    cond do
      n < lf ->
        [x | f1] = f
        split_f1_to_r2(n - 1, r, f1, [], [x])
      n > lf ->
        lr = length(r)
        m = lr - (n - lf)
        cond do
          m < 0 ->
            :erlang.error(:badarg, [n, q])
          m > 0 ->
            [x | r1] = r
            split_r1_to_f2(m - 1, r1, f, [x], [])
          true ->
            {q, {[], []}}
        end
      true ->
        {f2r(f), r2f(r)}
    end
  end

  def split(n, q) do
    :erlang.error(:badarg, [n, q])
  end

  defp split_f1_to_r2(0, r1, f1, r2, f2) do
    {{r2, f2}, {r1, f1}}
  end

  defp split_f1_to_r2(n, r1, [x | f1], r2, f2) do
    split_f1_to_r2(n - 1, r1, f1, [x | r2], f2)
  end

  defp split_r1_to_f2(0, r1, f1, r2, f2) do
    {{r1, f1}, {r2, f2}}
  end

  defp split_r1_to_f2(n, [x | r1], f1, r2, f2) do
    split_r1_to_f2(n - 1, r1, f1, r2, [x | f2])
  end

  def filter(fun, {r0, f0}) when (is_function(fun, 1) and
                                is_list(r0) and is_list(f0)) do
    f = filter_f(fun, f0)
    r = filter_r(fun, r0)
    cond do
      r === [] ->
        f2r(f)
      f === [] ->
        r2f(r)
      true ->
        {r, f}
    end
  end

  def filter(fun, q) do
    :erlang.error(:badarg, [fun, q])
  end

  defp filter_f(_, []) do
    []
  end

  defp filter_f(fun, [x | f]) do
    case (fun.(x)) do
      true ->
        [x | filter_f(fun, f)]
      [y] ->
        [y | filter_f(fun, f)]
      false ->
        filter_f(fun, f)
      [] ->
        filter_f(fun, f)
      l when is_list(l) ->
        l ++ filter_f(fun, f)
    end
  end

  defp filter_r(_, []) do
    []
  end

  defp filter_r(fun, [x | r0]) do
    r = filter_r(fun, r0)
    case (fun.(x)) do
      true ->
        [x | r]
      [y] ->
        [y | r]
      false ->
        r
      [] ->
        r
      l when is_list(l) ->
        :lists.reverse(l, r)
    end
  end

  def filtermap(fun, {r0, f0}) when (is_function(fun, 1) and
                                is_list(r0) and is_list(f0)) do
    f = :lists.filtermap(fun, f0)
    r = filtermap_r(fun, r0)
    cond do
      r === [] ->
        f2r(f)
      f === [] ->
        r2f(r)
      true ->
        {r, f}
    end
  end

  def filtermap(fun, q) do
    :erlang.error(:badarg, [fun, q])
  end

  defp filtermap_r(_, []) do
    []
  end

  defp filtermap_r(fun, [x | r0]) do
    r = filtermap_r(fun, r0)
    case (fun.(x)) do
      true ->
        [x | r]
      {true, y} ->
        [y | r]
      false ->
        r
    end
  end

  def fold(fun, acc0, {r, f}) when (is_function(fun, 2) and
                                    is_list(r) and is_list(f)) do
    acc1 = :lists.foldl(fun, acc0, f)
    :lists.foldr(fun, acc1, r)
  end

  def fold(fun, acc0, q) do
    :erlang.error(:badarg, [fun, acc0, q])
  end

  def any(pred, {r, f}) when (is_function(pred, 1) and
                               is_list(r) and is_list(f)) do
    :lists.any(pred, f) or :lists.any(pred, r)
  end

  def any(pred, q) do
    :erlang.error(:badarg, [pred, q])
  end

  def all(pred, {r, f}) when (is_function(pred, 1) and
                               is_list(r) and is_list(f)) do
    :lists.all(pred, f) and :lists.all(pred, r)
  end

  def all(pred, q) do
    :erlang.error(:badarg, [pred, q])
  end

  def delete(item, {r0, f0} = q) when (is_list(r0) and
                                     is_list(f0)) do
    case (delete_front(item, f0)) do
      false ->
        case (delete_rear(item, r0)) do
          false ->
            q
          [] ->
            f2r(f0)
          r1 ->
            {r1, f0}
        end
      [] ->
        r2f(r0)
      f1 ->
        {r0, f1}
    end
  end

  def delete(item, q) do
    :erlang.error(:badarg, [item, q])
  end

  def delete_r(item, {r0, f0}) when (is_list(r0) and
                                 is_list(f0)) do
    {f1, r1} = delete(item, {f0, r0})
    {r1, f1}
  end

  def delete_r(item, q) do
    :erlang.error(:badarg, [item, q])
  end

  defp delete_front(item, [item | rest]) do
    rest
  end

  defp delete_front(item, [x | rest]) do
    case (delete_front(item, rest)) do
      false ->
        false
      f ->
        [x | f]
    end
  end

  defp delete_front(_, []) do
    false
  end

  defp delete_rear(item, [x | rest]) do
    case (delete_rear(item, rest)) do
      false when x === item ->
        rest
      false ->
        false
      r ->
        [x | r]
    end
  end

  defp delete_rear(_, []) do
    false
  end

  def delete_with(pred, {r0, f0} = q) when (is_function(pred,
                                                 1) and
                                     is_list(r0) and is_list(f0)) do
    case (delete_with_front(pred, f0)) do
      false ->
        case (delete_with_rear(pred, r0)) do
          false ->
            q
          [] ->
            f2r(f0)
          r1 ->
            {r1, f0}
        end
      [] ->
        r2f(r0)
      f1 ->
        {r0, f1}
    end
  end

  def delete_with(pred, q) do
    :erlang.error(:badarg, [pred, q])
  end

  def delete_with_r(pred, {r0, f0}) when (is_function(pred, 1) and
                                 is_list(r0) and is_list(f0)) do
    {f1, r1} = delete_with(pred, {f0, r0})
    {r1, f1}
  end

  def delete_with_r(pred, q) do
    :erlang.error(:badarg, [pred, q])
  end

  defp delete_with_front(pred, [x | rest]) do
    case (pred.(x)) do
      true ->
        rest
      false ->
        case (delete_with_front(pred, rest)) do
          false ->
            false
          f ->
            [x | f]
        end
    end
  end

  defp delete_with_front(_, []) do
    false
  end

  defp delete_with_rear(pred, [x | rest]) do
    case (delete_with_rear(pred, rest)) do
      false ->
        case (pred.(x)) do
          true ->
            rest
          false ->
            false
        end
      r ->
        [x | r]
    end
  end

  defp delete_with_rear(_, []) do
    false
  end

  def cons(x, q) do
    in_r(x, q)
  end

  def head({[], []} = q) do
    :erlang.error(:empty, [q])
  end

  def head({r, f}) when (is_list(r) and is_list(f)) do
    get(r, f)
  end

  def head(q) do
    :erlang.error(:badarg, [q])
  end

  def tail(q) do
    drop(q)
  end

  def snoc(q, x) do
    __MODULE__.in(x, q)
  end

  def daeh(q) do
    get_r(q)
  end

  def last(q) do
    get_r(q)
  end

  def liat(q) do
    drop_r(q)
  end

  def lait(q) do
    drop_r(q)
  end

  def init(q) do
    drop_r(q)
  end

  defp r2f([]) do
    {[], []}
  end

  defp r2f([_] = r) do
    {[], r}
  end

  defp r2f([y, x]) do
    {[y], [x]}
  end

  defp r2f(list) do
    {rR, fF} = :lists.split(div(length(list), 2), list)
    {rR, :lists.reverse(fF, [])}
  end

  defp f2r([]) do
    {[], []}
  end

  defp f2r([_] = f) do
    {f, []}
  end

  defp f2r([x, y]) do
    {[y], [x]}
  end

  defp f2r(list) do
    {fF, rR} = :lists.split(div(length(list), 2), list)
    {:lists.reverse(rR, []), fF}
  end

end