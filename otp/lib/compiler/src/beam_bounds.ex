defmodule :m_beam_bounds do
  use Bitwise
  def bounds(:bnot, r0) do
    case (r0) do
      {a, b} ->
        r = {inf_add(inf_neg(b), - 1), inf_add(inf_neg(a), - 1)}
        normalize(r)
      _ ->
        :any
    end
  end

  def bounds(:abs, r) do
    case (r) do
      {a, b} when (is_integer(a) and is_integer(b)) ->
        min = 0
        max = max(abs(a), abs(b))
        {min, max}
      _ ->
        {0, :"+inf"}
    end
  end

  def bounds(:"+", r1, r2) do
    case ({r1, r2}) do
      {{a, b}, {c, d}} when (abs(a) >>> 128 === 0 and
                               abs(b) >>> 128 === 0 and abs(c) >>> 128 === 0 and
                               abs(d) >>> 128 === 0)
                            ->
        normalize({a + c, b + d})
      {{:-inf, b}, {_C, d}} when (abs(b) >>> 128 === 0 and
                                    abs(d) >>> 128 === 0)
                                 ->
        normalize({:-inf, b + d})
      {{_A, b}, {:-inf, d}} when (abs(b) >>> 128 === 0 and
                                    abs(d) >>> 128 === 0)
                                 ->
        normalize({:-inf, b + d})
      {{a, :"+inf"}, {c, _D}} when (abs(a) >>> 128 === 0 and
                                 abs(c) >>> 128 === 0)
                              ->
        normalize({a + c, :"+inf"})
      {{a, _B}, {c, :"+inf"}} when (abs(a) >>> 128 === 0 and
                                 abs(c) >>> 128 === 0)
                              ->
        normalize({a + c, :"+inf"})
      {_, _} ->
        :any
    end
  end

  def bounds(:-, r1, r2) do
    case ({r1, r2}) do
      {{a, b}, {c, d}} when (abs(a) >>> 128 === 0 and
                               abs(b) >>> 128 === 0 and abs(c) >>> 128 === 0 and
                               abs(d) >>> 128 === 0)
                            ->
        normalize({a - d, b - c})
      {{a, :"+inf"}, {_C, d}} when (abs(a) >>> 128 === 0 and
                                 abs(d) >>> 128 === 0)
                              ->
        normalize({a - d, :"+inf"})
      {{_A, b}, {c, :"+inf"}} when (abs(b) >>> 128 === 0 and
                                 abs(c) >>> 128 === 0)
                              ->
        normalize({:-inf, b - c})
      {{:-inf, b}, {c, _D}} when (abs(b) >>> 128 === 0 and
                                    abs(c) >>> 128 === 0)
                                 ->
        normalize({:-inf, b - c})
      {{a, _B}, {:-inf, d}} when (abs(a) >>> 128 === 0 and
                                    abs(d) >>> 128 === 0)
                                 ->
        normalize({a - d, :"+inf"})
      {_, _} ->
        :any
    end
  end

  def bounds(:"*", r1, r2) do
    case ({r1, r2}) do
      {{a, b}, {c, d}} when (abs(a) >>> 128 === 0 and
                               abs(b) >>> 128 === 0 and abs(c) >>> 128 === 0 and
                               abs(d) >>> 128 === 0)
                            ->
        all = (for x <- [a, b], y <- [c, d] do
                 x * y
               end)
        min = :lists.min(all)
        max = :lists.max(all)
        normalize({min, max})
      {{a, :"+inf"}, {c, d}} when (abs(a) >>> 128 === 0 and
                                abs(c) >>> 128 === 0 and
                                abs(d) >>> 128 === 0 and c >= 0)
                             ->
        {min(a * c, a * d), :"+inf"}
      {{:-inf, b}, {c, d}} when (abs(b) >>> 128 === 0 and
                                   abs(c) >>> 128 === 0 and
                                   abs(d) >>> 128 === 0 and c >= 0)
                                ->
        {:-inf, max(b * c, b * d)}
      {{a, b}, {:-inf, _}} when (is_integer(a) and
                                   is_integer(b))
                                ->
        bounds(:"*", r2, r1)
      {{a, b}, {_, :"+inf"}} when (is_integer(a) and is_integer(b))
                             ->
        bounds(:"*", r2, r1)
      {_, _} ->
        :any
    end
  end

  def bounds(:div, r1, r2) do
    div_bounds(r1, r2)
  end

  def bounds(:rem, r1, r2) do
    rem_bounds(r1, r2)
  end

  def bounds(:band, r1, r2) do
    case ({r1, r2}) do
      {{a, b}, {c, d}} when (a >>> 128 === 0 and a >= 0 and
                               c >>> 128 === 0 and c >= 0 and is_integer(b) and
                               is_integer(d))
                            ->
        min = min_band(a, b, c, d)
        max = max_band(a, b, c, d)
        {min, max}
      {_, {c, d}} when (is_integer(c) and c >= 0) ->
        {0, d}
      {{a, b}, _} when (is_integer(a) and a >= 0) ->
        {0, b}
      {_, _} ->
        :any
    end
  end

  def bounds(:bor, r1, r2) do
    case ({r1, r2}) do
      {{a, b}, {c, d}} when (a >>> 128 === 0 and a >= 0 and
                               c >>> 128 === 0 and c >= 0 and is_integer(b) and
                               is_integer(d))
                            ->
        min = min_bor(a, b, c, d)
        max = max_bor(a, b, c, d)
        {min, max}
      {_, _} ->
        :any
    end
  end

  def bounds(:bxor, r1, r2) do
    case ({r1, r2}) do
      {{a, b}, {c, d}} when (a >>> 128 === 0 and a >= 0 and
                               c >>> 128 === 0 and c >= 0 and is_integer(b) and
                               is_integer(d))
                            ->
        max = max_bxor(a, b, c, d)
        {0, max}
      {_, _} ->
        :any
    end
  end

  def bounds(:bsr, r1, r2) do
    case ({r1, r2}) do
      {{a, b}, {c, d}} when (is_integer(c) and c >= 0) ->
        min = inf_min(inf_bsr(a, c), inf_bsr(a, d))
        max = inf_max(inf_bsr(b, c), inf_bsr(b, d))
        normalize({min, max})
      {_, _} ->
        :any
    end
  end

  def bounds(:bsl, r1, r2) do
    case ({r1, r2}) do
      {{a, b}, {c, d}} when (abs(a) >>> 128 === 0 and
                               abs(b) >>> 128 === 0)
                            ->
        min = inf_min(inf_bsl(a, c), inf_bsl(a, d))
        max = inf_max(inf_bsl(b, c), inf_bsl(b, d))
        normalize({min, max})
      {_, _} ->
        :any
    end
  end

  def bounds(:max, r1, r2) do
    case ({r1, r2}) do
      {{a, b}, {c, d}} ->
        normalize({inf_max(a, c), inf_max(b, d)})
      {_, _} ->
        :any
    end
  end

  def bounds(:min, r1, r2) do
    case ({r1, r2}) do
      {{a, b}, {c, d}} ->
        normalize({inf_min(a, c), inf_min(b, d)})
      {_, _} ->
        :any
    end
  end

  def relop(:"<", {a, b}, {c, d}) do
    case ({inf_lt(b, c), inf_lt(a, d)}) do
      {bool, bool} ->
        bool
      {_, _} ->
        :maybe
    end
  end

  def relop(:"=<", {a, b}, {c, d}) do
    case ({inf_le(b, c), inf_le(a, d)}) do
      {bool, bool} ->
        bool
      {_, _} ->
        :maybe
    end
  end

  def relop(:">=", {a, b}, {c, d}) do
    case ({inf_ge(b, c), inf_ge(a, d)}) do
      {bool, bool} ->
        bool
      {_, _} ->
        :maybe
    end
  end

  def relop(:">", {a, b}, {c, d}) do
    case ({inf_gt(b, c), inf_gt(a, d)}) do
      {bool, bool} ->
        bool
      {_, _} ->
        :maybe
    end
  end

  def relop(_, _, _) do
    :maybe
  end

  def infer_relop_types(op, {_, _} = range1, {_, _} = range2) do
    case (relop(op, range1, range2)) do
      :maybe ->
        infer_relop_types_1(op, range1, range2)
      true ->
        :any
      false ->
        :none
    end
  end

  def infer_relop_types(:"<", {a, _} = r1, :any) do
    {r1, normalize({inf_add(a, 1), :"+inf"})}
  end

  def infer_relop_types(:"<", :any, {_, d} = r2) do
    {normalize({:-inf, inf_add(d, - 1)}), r2}
  end

  def infer_relop_types(:"=<", {a, _} = r1, :any) do
    {r1, normalize({a, :"+inf"})}
  end

  def infer_relop_types(:"=<", :any, {_, d} = r2) do
    {normalize({:-inf, d}), r2}
  end

  def infer_relop_types(:">=", {_, b} = r1, :any) do
    {r1, normalize({:-inf, b})}
  end

  def infer_relop_types(:">=", :any, {c, _} = r2) do
    {normalize({c, :"+inf"}), r2}
  end

  def infer_relop_types(:">", {_, b} = r1, :any) do
    {r1, normalize({:-inf, inf_add(b, - 1)})}
  end

  def infer_relop_types(:">", :any, {c, _} = r2) do
    {normalize({inf_add(c, 1), :"+inf"}), r2}
  end

  def infer_relop_types(_Op, _R1, _R2) do
    :any
  end

  def is_masking_redundant(_, -1) do
    true
  end

  def is_masking_redundant({a, b}, m) when (m &&& (m + 1) === 0 and
                            m > 0 and is_integer(a) and a >= 0 and
                            b &&& m === b) do
    true
  end

  def is_masking_redundant(_, _) do
    false
  end

  defp div_bounds({_, _}, {0, 0}) do
    :any
  end

  defp div_bounds({a, b}, {c, d}) when (is_integer(a) and
                                  is_integer(b) and is_integer(c) and
                                  is_integer(d)) do
    denominators = [min(c, d), max(c, d) | cond do
                                             (c < 0 and 0 < d) ->
                                               [- 1, 1]
                                             c === 0 ->
                                               [1]
                                             d === 0 ->
                                               [- 1]
                                             true ->
                                               []
                                           end]
    all = (for x <- [a, b], y <- denominators, y !== 0 do
             div(x, y)
           end)
    min = :lists.min(all)
    max = :lists.max(all)
    normalize({min, max})
  end

  defp div_bounds({a, :"+inf"}, {c, d}) when (is_integer(c) and
                                   c > 0 and is_integer(d)) do
    min = min(div(a, c), div(a, d))
    max = :"+inf"
    normalize({min, max})
  end

  defp div_bounds({:-inf, b}, {c, d}) when (is_integer(c) and
                                      c > 0 and is_integer(d)) do
    min = :-inf
    max = max(div(b, c), div(b, d))
    normalize({min, max})
  end

  defp div_bounds(_, _) do
    :any
  end

  defp rem_bounds({a, _}, {c, d}) when (is_integer(c) and
                                  is_integer(d) and c > 0) do
    max = inf_add(d, - 1)
    min = (cond do
             a === :-inf ->
               - max
             a >= 0 ->
               0
             true ->
               - max
           end)
    normalize({min, max})
  end

  defp rem_bounds(_, {c, d}) when (is_integer(c) and
                             is_integer(d) and c !== 0 or d !== 0) do
    max = max(abs(c), abs(d)) - 1
    min = - max
    normalize({min, max})
  end

  defp rem_bounds(_, _) do
    :any
  end

  defp min_band(a, b, c, d) do
    m = 1 <<< (upper_bit(a ||| c) + 1)
    min_band(a, b, c, d, m)
  end

  defp min_band(a, _B, c, _D, 0) do
    a &&& c
  end

  defp min_band(a, b, c, d, m) do
    cond do
      ~~~ a &&& ~~~ c &&& m !== 0 ->
        case ((a ||| m) &&& - m) do
          newA when newA <= b ->
            min_band(newA, b, c, d, 0)
          _ ->
            case ((c ||| m) &&& - m) do
              newC when newC <= d ->
                min_band(a, b, newC, d, 0)
              _ ->
                min_band(a, b, c, d, m >>> 1)
            end
        end
      true ->
        min_band(a, b, c, d, m >>> 1)
    end
  end

  defp max_band(a, b, c, d) do
    m = 1 <<< upper_bit((b ^^^ d))
    max_band(a, b, c, d, m)
  end

  defp max_band(_A, b, _C, d, 0) do
    b &&& d
  end

  defp max_band(a, b, c, d, m) do
    cond do
      b &&& ~~~ d &&& m !== 0 ->
        case (b &&& ~~~ m ||| (m - 1)) do
          newB when newB >= a ->
            max_band(a, newB, c, d, 0)
          _ ->
            max_band(a, b, c, d, m >>> 1)
        end
      ~~~ b &&& d &&& m !== 0 ->
        case (d &&& ~~~ m ||| (m - 1)) do
          newD when newD >= c ->
            max_band(a, b, c, newD, 0)
          _ ->
            max_band(a, b, c, d, m >>> 1)
        end
      true ->
        max_band(a, b, c, d, m >>> 1)
    end
  end

  defp min_bor(a, b, c, d) do
    m = 1 <<< upper_bit((a ^^^ c))
    min_bor(a, b, c, d, m)
  end

  defp min_bor(a, _B, c, _D, 0) do
    a ||| c
  end

  defp min_bor(a, b, c, d, m) do
    cond do
      ~~~ a &&& c &&& m !== 0 ->
        case ((a ||| m) &&& - m) do
          newA when newA <= b ->
            min_bor(newA, b, c, d, 0)
          _ ->
            min_bor(a, b, c, d, m >>> 1)
        end
      a &&& ~~~ c &&& m !== 0 ->
        case ((c ||| m) &&& - m) do
          newC when newC <= d ->
            min_bor(a, b, newC, d, 0)
          _ ->
            min_bor(a, b, c, d, m >>> 1)
        end
      true ->
        min_bor(a, b, c, d, m >>> 1)
    end
  end

  defp max_bor(a, b, c, d) do
    intersection = b &&& d
    m = 1 <<< upper_bit(intersection)
    max_bor(intersection, a, b, c, d, m)
  end

  defp max_bor(_Intersection, _A, b, _C, d, 0) do
    b ||| d
  end

  defp max_bor(intersection, a, b, c, d, m) do
    cond do
      intersection &&& m !== 0 ->
        case (b - m ||| (m - 1)) do
          newB when newB >= a ->
            max_bor(intersection, a, newB, c, d, 0)
          _ ->
            case (d - m ||| (m - 1)) do
              newD when newD >= c ->
                max_bor(intersection, a, b, c, newD, 0)
              _ ->
                max_bor(intersection, a, b, c, d, m >>> 1)
            end
        end
      true ->
        max_bor(intersection, a, b, c, d, m >>> 1)
    end
  end

  defp max_bxor(a, b, c, d) do
    m = 1 <<< upper_bit(b &&& d)
    max_bxor(a, b, c, d, m)
  end

  defp max_bxor(_A, b, _C, d, 0) do
    b ^^^ d
  end

  defp max_bxor(a, b, c, d, m) do
    cond do
      b &&& d &&& m !== 0 ->
        case (b - m ||| (m - 1)) do
          newB when newB >= a ->
            max_bxor(a, newB, c, d, m >>> 1)
          _ ->
            case (d - m ||| (m - 1)) do
              newD when newD >= c ->
                max_bxor(a, b, c, newD, m >>> 1)
              _ ->
                max_bxor(a, b, c, d, m >>> 1)
            end
        end
      true ->
        max_bxor(a, b, c, d, m >>> 1)
    end
  end

  defp upper_bit(val) do
    upper_bit_1(val, 0)
  end

  defp upper_bit_1(val0, n) do
    case (val0 >>> 1) do
      0 ->
        n
      val ->
        upper_bit_1(val, n + 1)
    end
  end

  defp infer_relop_types_1(:"<", {a, b}, {c, d}) do
    left = normalize({a, clamp(inf_add(d, - 1), a, b)})
    right = normalize({clamp(inf_add(a, 1), c, d), d})
    {left, right}
  end

  defp infer_relop_types_1(:"=<", {a, b}, {c, d}) do
    left = normalize({a, clamp(d, a, b)})
    right = normalize({clamp(a, c, d), d})
    {left, right}
  end

  defp infer_relop_types_1(:">=", {a, b}, {c, d}) do
    left = normalize({clamp(c, a, b), b})
    right = normalize({c, clamp(b, c, d)})
    {left, right}
  end

  defp infer_relop_types_1(:">", {a, b}, {c, d}) do
    left = normalize({clamp(inf_add(c, 1), a, b), b})
    right = normalize({c, clamp(inf_add(b, - 1), c, d)})
    {left, right}
  end

  defp normalize({:-inf, :-inf}) do
    {:-inf, - 1}
  end

  defp normalize({:-inf, :"+inf"}) do
    :any
  end

  defp normalize({:"+inf", :"+inf"}) do
    {0, :"+inf"}
  end

  defp normalize({min, max} = t) do
    true = inf_ge(max, min)
    t
  end

  defp clamp(v, a, b) do
    inf_min(inf_max(v, a), b)
  end

  defp inf_min(a, b) when a === :-inf or b === :-inf do
    :-inf
  end

  defp inf_min(a, b) when a <= b do
    a
  end

  defp inf_min(a, b) when a > b do
    b
  end

  defp inf_max(:-inf, b) do
    b
  end

  defp inf_max(a, :-inf) do
    a
  end

  defp inf_max(a, b) when a >= b do
    a
  end

  defp inf_max(a, b) when a < b do
    b
  end

  defp inf_neg(:-inf) do
    :"+inf"
  end

  defp inf_neg(:"+inf") do
    :-inf
  end

  defp inf_neg(n) do
    - n
  end

  defp inf_add(int, n) when is_integer(int) do
    int + n
  end

  defp inf_add(inf, _N) do
    inf
  end

  defp inf_bsr(:-inf, _S) do
    :-inf
  end

  defp inf_bsr(:"+inf", _S) do
    :"+inf"
  end

  defp inf_bsr(n, s0) when s0 === :-inf or s0 < 0 do
    s = inf_neg(s0)
    cond do
      (s >= 128 and n < 0) ->
        :-inf
      (s >= 128 and n >= 0) ->
        :"+inf"
      true ->
        n <<< s
    end
  end

  defp inf_bsr(n, :"+inf") do
    cond do
      n < 0 ->
        - 1
      n >= 0 ->
        0
    end
  end

  defp inf_bsr(n, s) when s >= 0 do
    n >>> s
  end

  defp inf_bsl(n, s) do
    inf_bsr(n, inf_neg(s))
  end

  defp inf_lt(_, :-inf) do
    false
  end

  defp inf_lt(:-inf, _) do
    true
  end

  defp inf_lt(a, b) do
    a < b
  end

  defp inf_ge(_, :-inf) do
    true
  end

  defp inf_ge(:-inf, _) do
    false
  end

  defp inf_ge(a, b) do
    a >= b
  end

  defp inf_le(a, b) do
    inf_ge(b, a)
  end

  defp inf_gt(a, b) do
    inf_lt(b, a)
  end

end